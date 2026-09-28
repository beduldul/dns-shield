"""DNS-over-HTTPS resolution.

Ported and generalised from the proven ``copytrade.resolve`` implementation.
The design notes that mattered there are preserved here:

* Addresses are re-resolved on TTL expiry and after any transport failure,
  because CDN answer sets rotate underneath you. A CloudFront /24 was observed
  rotating across ``.5/.24/.35/.52`` within minutes -- never hardcode an IP.
* The answer is kept **in the order the resolver returned it**, and consumed
  round-robin via :meth:`ResolvedHost.next_ip`. CloudFront hands back its
  least-loaded edge first, so answer order is a real signal worth honouring.
* Every query is bounded by a timeout so nothing can hang.

The one thing this module deliberately does *not* do is expose a way to mutate
the system resolver. See :mod:`dns_shield.patch` for the targeted-override
story.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Final, Iterable, Mapping, Sequence

from . import config

__all__ = [
    "DohProvider",
    "DohResolutionError",
    "DohResolver",
    "PROVIDERS",
    "ResolvedHost",
    "RecordSet",
    "looks_like_ipv4",
    "looks_like_ipv6",
]

#: DNS type codes we understand in an answer section.
_TYPE_A: Final[int] = 1
_TYPE_CNAME: Final[int] = 5
_TYPE_AAAA: Final[int] = 28


class DohResolutionError(RuntimeError):
    """Raised when a hostname could not be resolved over DoH."""


@dataclass(frozen=True)
class DohProvider:
    """A DNS-over-HTTPS JSON endpoint.

    ``json_endpoint`` must speak the ``application/dns-json`` dialect
    (RFC 8484 wire format is a different protocol and is not supported).
    """

    name: str
    json_endpoint: str

    def query_url(self, host: str, record_type: str) -> str:
        """Build the GET URL for one lookup."""
        return (
            f"{self.json_endpoint}?name={urllib.parse.quote(host)}"
            f"&type={urllib.parse.quote(record_type)}"
        )


#: Built-in providers. Adding your own is a one-liner -- see README.
PROVIDERS: Final[Mapping[str, DohProvider]] = {
    "cloudflare": DohProvider(
        name="cloudflare",
        json_endpoint="https://cloudflare-dns.com/dns-query",
    ),
    "google": DohProvider(
        name="google",
        json_endpoint="https://dns.google/resolve",
    ),
    "quad9": DohProvider(
        name="quad9",
        json_endpoint="https://dns.quad9.net:5053/dns-query",
    ),
}


def looks_like_ipv4(value: str) -> bool:
    """Return True if ``value`` is a dotted-quad IPv4 literal."""
    try:
        socket.inet_aton(value)
    except OSError:
        return False
    return value.count(".") == 3


def looks_like_ipv6(value: str) -> bool:
    """Return True if ``value`` is an IPv6 literal."""
    if ":" not in value:
        return False
    try:
        socket.inet_pton(socket.AF_INET6, value)
    except OSError:
        return False
    return True


@dataclass(frozen=True)
class RecordSet:
    """The full answer for one (host, type) query, including the CNAME chain."""

    host: str
    addresses: tuple[str, ...]
    cnames: tuple[str, ...]
    ttl_s: float
    provider: str

    @property
    def is_empty(self) -> bool:
        """True when the resolver returned no addresses of the requested type."""
        return not self.addresses


@dataclass
class ResolvedHost:
    """A hostname resolved to one or more concrete addresses.

    Addresses are returned in the resolver's answer order. ``next_ip`` walks
    that order round-robin so consecutive attempts hit different edge nodes --
    this is what makes "first IP failed, second succeeded" work.
    """

    host: str
    ips: list[str]
    expires_at: float
    cnames: tuple[str, ...] = ()
    _cursor: int = field(init=False, repr=False, default=0)

    def __post_init__(self) -> None:
        if not self.ips:
            raise ValueError("ResolvedHost requires at least one IP")

    @property
    def expired(self) -> bool:
        """True once this entry has outlived its TTL."""
        return time.monotonic() >= self.expires_at

    def next_ip(self) -> str:
        """Round-robin to the next address, spreading load across the CDN."""
        ip = self.ips[self._cursor % len(self.ips)]
        self._cursor += 1
        return ip

    def rotate(self) -> None:
        """Advance the round-robin cursor without consuming the returned value."""
        self._cursor += 1


class DohResolver:
    """Thread-safe DNS-over-HTTPS resolver with a short-lived cache.

    ``endpoint`` accepts either a provider name (``"cloudflare"``), a full URL
    string, or a :class:`DohProvider`. Pass a sequence to try several in order
    with automatic failover.
    """

    def __init__(
        self,
        endpoint: str | DohProvider | Sequence[str | DohProvider] | None = None,
        *,
        ttl_s: float = config.DNS_CACHE_TTL_S,
        timeout_s: float = config.DOH_TIMEOUT_S,
    ) -> None:
        self._providers: tuple[DohProvider, ...] = _coerce_providers(endpoint)
        self._ttl_s = ttl_s
        self._timeout_s = timeout_s
        self._cache: dict[str, ResolvedHost] = {}
        self._lock = threading.Lock()

    @property
    def providers(self) -> tuple[DohProvider, ...]:
        """The provider chain, in failover order."""
        return self._providers

    def query(self, host: str) -> list[str]:
        """Return IPv4 addresses for ``host`` in the resolver's answer order.

        Raises :class:`DohResolutionError` if every provider in the chain fails
        or returns an answer set with no A records -- an empty result is a
        failure, not a success with zero addresses, so that callers cannot
        silently proceed with nothing to dial.
        """
        records = self.query_records(host, "A")
        if records.is_empty:
            raise DohResolutionError(f"DoH returned no A records for {host}")
        return list(records.addresses)

    def query_records(self, host: str, record_type: str = "A") -> RecordSet:
        """Query one record type across the provider chain.

        Failover is per-provider, not per-address: the first provider that
        answers wins, and a provider that returns an empty answer set is
        treated as a failure so the next one gets a turn.
        """
        errors: list[str] = []
        for provider in self._providers:
            try:
                records = self._query_one(provider, host, record_type)
            except DohResolutionError as exc:
                errors.append(f"{provider.name}: {exc}")
                continue
            # An empty answer set is a miss, not a success. Falling through to
            # the next provider is what makes a chain of resolvers useful when
            # one of them has a stale or filtered view.
            if records.is_empty:
                errors.append(f"{provider.name}: no {record_type} records")
                continue
            return records
        raise DohResolutionError(
            f"all DoH providers failed for {host}/{record_type}: " + "; ".join(errors)
        )

    def _query_one(self, provider: DohProvider, host: str, record_type: str) -> RecordSet:
        """Query exactly one provider. Raises :class:`DohResolutionError` on any miss."""
        url = provider.query_url(host, record_type)
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/dns-json",
                "user-agent": config.USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise DohResolutionError(f"query failed: {type(exc).__name__}: {exc}") from exc

        if not isinstance(payload, dict):
            raise DohResolutionError("malformed DoH payload (not an object)")

        status = payload.get("Status")
        if status != 0:
            # NXDOMAIN is 3, SERVFAIL 2. Both are real answers, not transport
            # failures, but neither gives us an address.
            raise DohResolutionError(f"DNS status {status} (NXDOMAIN=3, SERVFAIL=2)")

        return _build_record_set(payload, host, record_type, provider.name)

    def resolve(self, host: str, *, force: bool = False) -> str:
        """Return a routable address for ``host``, one at a time.

        Uses the cache when fresh; re-queries when stale, when ``force`` is set,
        or when the caller invalidated a suspected-bad answer.
        """
        with self._lock:
            cached = self._cache.get(host)
            if cached is not None and not cached.expired and not force:
                return cached.next_ip()

        entry = self.resolve_host(host, force=force)
        return entry.next_ip()

    def resolve_host(self, host: str, *, force: bool = False) -> ResolvedHost:
        """Return the cached :class:`ResolvedHost`, re-querying when needed."""
        with self._lock:
            cached = self._cache.get(host)
            if cached is not None and not cached.expired and not force:
                return cached

        records = self.query_records(host, "A")
        if records.is_empty:
            raise DohResolutionError(f"DoH returned no A records for {host}")

        ttl = min(self._ttl_s, records.ttl_s) if records.ttl_s > 0 else self._ttl_s
        entry = ResolvedHost(
            host=host,
            ips=list(records.addresses),
            expires_at=time.monotonic() + ttl,
            cnames=records.cnames,
        )
        with self._lock:
            self._cache[host] = entry
        return entry

    def invalidate(self, host: str) -> None:
        """Drop a cached entry after a suspected address rotation."""
        with self._lock:
            self._cache.pop(host, None)

    def cache_ttl_remaining(self, host: str) -> float:
        """Seconds until the cached entry for ``host`` expires (0.0 if absent)."""
        with self._lock:
            entry = self._cache.get(host)
        if entry is None:
            return 0.0
        return max(0.0, entry.expires_at - time.monotonic())


def _coerce_providers(
    endpoint: str | DohProvider | Sequence[str | DohProvider] | None,
) -> tuple[DohProvider, ...]:
    """Normalise the ``endpoint`` argument into a non-empty provider chain."""
    if endpoint is None:
        raw: Iterable[str | DohProvider] = (config.DOH_ENDPOINT,)
    elif isinstance(endpoint, (str, DohProvider)):
        raw = (endpoint,)
    else:
        raw = endpoint

    providers: list[DohProvider] = []
    for item in raw:
        if isinstance(item, DohProvider):
            providers.append(item)
        elif item in PROVIDERS:
            providers.append(PROVIDERS[item])
        elif item.startswith(("http://", "https://")):
            providers.append(DohProvider(name=item, json_endpoint=item))
        else:
            known = ", ".join(sorted(PROVIDERS))
            raise ValueError(f"unknown DoH provider {item!r} (known: {known})")

    if not providers:
        raise ValueError("at least one DoH provider is required")
    return tuple(providers)


def _build_record_set(
    payload: Mapping[str, object],
    host: str,
    record_type: str,
    provider_name: str,
) -> RecordSet:
    """Turn a raw DoH JSON payload into a :class:`RecordSet`."""
    want = _TYPE_A if record_type.upper() == "A" else _TYPE_AAAA
    answers = payload.get("Answer")
    if not isinstance(answers, list):
        return RecordSet(host, (), (), 0.0, provider_name)

    addresses: list[str] = []
    cnames: list[str] = []
    ttls: list[float] = []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        data = answer.get("data")
        if not isinstance(data, str):
            continue
        ttl = answer.get("TTL")
        if isinstance(ttl, (int, float)) and ttl > 0:
            ttls.append(float(ttl))

        atype = answer.get("type")
        if atype == _TYPE_CNAME:
            cnames.append(data.rstrip("."))
        elif atype == want and _matches_family(data, want):
            addresses.append(data)

    return RecordSet(
        host=host,
        addresses=tuple(addresses),
        cnames=tuple(cnames),
        ttl_s=min(ttls) if ttls else 0.0,
        provider=provider_name,
    )


def _matches_family(value: str, want: int) -> bool:
    """Guard against a malformed answer claiming type A but carrying garbage."""
    return looks_like_ipv4(value) if want == _TYPE_A else looks_like_ipv6(value)
