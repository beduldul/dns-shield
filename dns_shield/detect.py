"""Diagnose whether a resolver is lying to you.

THE POINT OF THIS MODULE
------------------------
It is easy to write a tool that prints "POISONED" for everything that fails.
That tool is worse than useless: it turns a real outage, a genuine geo-block, or
a typo'd hostname into a false accusation, and it trains the user to distrust
the verdict.

So this module measures, and it is willing to say "unreachable" or "suspicious"
or "unknown". The verdict is derived from **observed evidence**, never from the
mere fact that something went wrong.

THE FINGERPRINT
---------------
DNS poisoning by a transparent middlebox looks like this:

1. **System DNS returns an address that DoH disagrees with.** Multiple
   independent DoH providers agree on a *different* answer than the local
   resolver -- typically a CDN, visible as a CNAME to ``*.cloudfront.net``.
2. **The system-DNS address is shared across unrelated hostnames.** A single
   address serving every name under a domain is not how real infrastructure is
   built; it is how a blackhole appliance is built.
3. **Connecting to it fails fast and flat.** An instant refusal (a synthetic
   RST) is the classic signature. Critically, the failure is *not* an HTTP
   response: there is nothing to read, no 403, no 451. The connection simply
   dies.
4. **The DoH address works**, with SNI preserved.

Step 4 is what makes the accusation safe: if the DoH address also fails, the
host is genuinely down and we must not blame the resolver.

MEASURED NON-DETERMINISM (important)
------------------------------------
The original report described "instant RST in ~10 ms". Re-measuring on the
affected machine showed the bogus address is *not* consistent: repeated connects
to ``202.169.44.80:443`` produced a mix of ``TimeoutError`` (~2000 ms) and
occasional fast ``ConnectionRefusedError`` (~15 ms). A blackhole appliance that
rate-limits its own resets behaves like this.

Therefore: **fast refusal is strong evidence, but a timeout is not evidence
against poisoning.** Both map to a poisoned verdict when the DoH address works.
Latency is recorded and surfaced, not treated as a verdict by itself.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from . import config
from .resolve import DohResolutionError, DohResolver

__all__ = [
    "Diagnosis",
    "Evidence",
    "FailureKind",
    "ProbeResult",
    "Verdict",
    "classify",
    "diagnose",
    "probe_connect",
    "probe_http",
    "system_resolve",
]


class Verdict(str, Enum):
    """The conclusion. Deliberately willing to be inconclusive."""

    #: System DNS and DoH agree, and the host answers. Nothing wrong.
    HEALTHY = "healthy"
    #: DNS disagrees, the system answer is dead, and the DoH answer works.
    POISONED = "poisoned"
    #: Answers disagree, but the evidence is not conclusive either way.
    SUSPICIOUS = "suspicious"
    #: The host cannot be reached by any path. Not the resolver's fault.
    UNREACHABLE = "unreachable"
    #: Not enough information -- DoH failed, or nothing could be probed.
    UNKNOWN = "unknown"


class FailureKind(str, Enum):
    """A precise classification of *how* a connection attempt failed."""

    #: TCP connected successfully.
    SUCCESS = "success"
    #: Refused with a reset: the classic synthetic-RST signature.
    REFUSED = "refused"
    #: Timed out with no response at all.
    TIMEOUT = "timeout"
    #: DNS could not produce an address to even try.
    DNS_FAILURE = "dns-failure"
    #: TCP connected, but the TLS handshake failed.
    TLS_FAILURE = "tls-failure"
    #: A complete HTTP response was received, with this status code.
    HTTP_ERROR = "http-error"
    #: Any other OS-level error.
    OTHER_ERROR = "other-error"


@dataclass(frozen=True)
class ProbeResult:
    """The outcome of one connectivity probe against one address."""

    address: str
    kind: FailureKind
    latency_ms: float
    status: int | None = None
    detail: str = ""
    #: Subject CN from the certificate the server presented, when TLS completed.
    cert_subject: str = ""
    #: Issuer CN from that certificate.
    cert_issuer: str = ""
    #: True when the certificate validated against the system trust store for
    #: the requested hostname. This is the strongest available evidence that an
    #: address really is the host it claims to be.
    cert_valid: bool = False

    @property
    def connected(self) -> bool:
        """True if TCP connected, regardless of what happened afterwards."""
        return self.kind in {
            FailureKind.SUCCESS,
            FailureKind.HTTP_ERROR,
            FailureKind.TLS_FAILURE,
        }

    @property
    def works(self) -> bool:
        """True if we got a usable HTTP response with a non-error status."""
        return self.kind is FailureKind.SUCCESS

    @property
    def server_is_alive(self) -> bool:
        """True if a real server answered, even with an error status.

        A ``403`` on ``/`` still proves that the address hosts a live TLS
        endpoint presenting a valid certificate for the name. That is decisive
        evidence *against* the address being a blackhole, so the classifier must
        not treat every non-2xx status as "this address is dead".

        This distinction matters: the motivating case's API host returns 403 for
        the bare root path while serving 200 for its real API routes.
        """
        if self.kind is FailureKind.SUCCESS:
            return True
        if self.kind is FailureKind.HTTP_ERROR:
            # 5xx means the server is reachable but broken. Either way it is a
            # live endpoint, not a synthetic reset.
            return True
        return False

    @property
    def fast_refusal(self) -> bool:
        """True for a refused connection that came back suspiciously quickly.

        A refusal in single-digit milliseconds cannot have traversed real
        network distance. It means an on-path appliance synthesised the RST.
        Strong evidence *for* poisoning; its absence proves nothing.
        """
        return (
            self.kind is FailureKind.REFUSED
            and self.latency_ms <= config.RST_LATENCY_FAST_MS
        )

    @property
    def slow_refusal(self) -> bool:
        """A refusal that took long enough to have come from the far end.

        Measured on the real case: the same bogus address produced refusals at
        9 ms, 18 ms, 1.0 s, 2.0 s, 3.0 s *and* 11 s, alongside plain timeouts.
        A slow refusal is still an active refusal -- the connection was
        rejected, not silently dropped -- but the latency says the RST came
        from somewhere other than a local appliance.
        """
        return (
            self.kind is FailureKind.REFUSED
            and self.latency_ms > config.RST_LATENCY_FAST_MS
        )

    @property
    def refusal_mode(self) -> str:
        """A short label for how the address failed, for evidence output."""
        if self.kind is FailureKind.REFUSED:
            return "refused-fast" if self.fast_refusal else "refused-slow"
        return self.kind.value

    def describe(self) -> str:
        """One human-readable line for the CLI."""
        if self.kind is FailureKind.HTTP_ERROR and self.status is not None:
            base = f"HTTP {self.status} in {self.latency_ms:.0f} ms"
        elif self.kind is FailureKind.SUCCESS and self.status is not None:
            base = f"HTTP {self.status} in {self.latency_ms:.0f} ms"
        else:
            label = self.kind.value
            if self.kind is FailureKind.REFUSED:
                label = "connection refused (RST)"
            elif self.kind is FailureKind.TIMEOUT:
                label = "timed out (no response)"
            base = f"{label} in {self.latency_ms:.0f} ms"
            if self.detail:
                base += f" ({self.detail})"
        if self.cert_subject:
            base += f", cert={self.cert_subject}"
        return base


@dataclass(frozen=True)
class Evidence:
    """Everything measured, so a human can audit the verdict."""

    host: str
    system_ips: tuple[str, ...] = ()
    doh_ips: tuple[str, ...] = ()
    doh_provider: str = ""
    cnames: tuple[str, ...] = ()
    system_probe: ProbeResult | None = None
    doh_probe: ProbeResult | None = None
    shared_ip_hosts: tuple[str, ...] = ()
    doh_error: str = ""
    system_error: str = ""
    #: The HTTP path that was probed, so an error status can be read in context.
    probed_path: str = "/"
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def answers_disagree(self) -> bool:
        """True if the two resolution paths produced different addresses."""
        if not self.system_ips or not self.doh_ips:
            return False
        return not set(self.system_ips) & set(self.doh_ips)

    @property
    def system_ip(self) -> str | None:
        """The first system-resolved address, if any."""
        return self.system_ips[0] if self.system_ips else None

    @property
    def doh_ip(self) -> str | None:
        """The first DoH-resolved address, if any."""
        return self.doh_ips[0] if self.doh_ips else None


@dataclass(frozen=True)
class Diagnosis:
    """A verdict plus the evidence and reasoning behind it."""

    host: str
    verdict: Verdict
    summary: str
    evidence: Evidence
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def exit_code(self) -> int:
        """Script-friendly exit code: 0 healthy, 1 poisoned, 2 inconclusive."""
        if self.verdict is Verdict.HEALTHY:
            return 0
        if self.verdict in {Verdict.POISONED, Verdict.SUSPICIOUS}:
            return 1
        return 2

    def to_dict(self) -> dict[str, object]:
        """A JSON-serialisable view, stable for tooling."""
        ev = self.evidence

        def probe(p: ProbeResult | None) -> dict[str, object] | None:
            if p is None:
                return None
            return {
                "address": p.address,
                "kind": p.kind.value,
                "latency_ms": round(p.latency_ms, 1),
                "status": p.status,
                "connected": p.connected,
                "works": p.works,
                "fast_refusal": p.fast_refusal,
                "detail": p.detail,
                "describe": p.describe(),
            }

        return {
            "host": self.host,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "reasons": list(self.reasons),
            "exit_code": self.exit_code,
            "evidence": {
                "system_ips": list(ev.system_ips),
                "doh_ips": list(ev.doh_ips),
                "doh_provider": ev.doh_provider,
                "cnames": list(ev.cnames),
                "answers_disagree": ev.answers_disagree,
                "shared_ip_hosts": list(ev.shared_ip_hosts),
                "probed_path": ev.probed_path,
                "system_probe": probe(ev.system_probe),
                "doh_probe": probe(ev.doh_probe),
                "system_error": ev.system_error,
                "doh_error": ev.doh_error,
                "notes": list(ev.notes),
            },
        }


# -- measurement primitives ------------------------------------------------


def system_resolve(host: str, *, port: int = 443) -> tuple[str, ...]:
    """Resolve via the OS resolver.

    This is the path under suspicion. It is isolated in its own function so
    tests can patch exactly this and prove nothing else consults it.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    seen: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in seen:
            seen.append(address)
    return tuple(seen)


def classify_connection_error(exc: BaseException, timeout_s: float) -> tuple[FailureKind, str]:
    """Map a socket-level exception to a :class:`FailureKind`.

    Shared by every probe path so the mapping cannot drift between them. The
    distinction that matters:

    * **Active refusal** -- ``ConnectionRefusedError`` (RST in reply to SYN) or
      ``ConnectionResetError`` (RST mid-connection). Both mean *something on the
      network answered and actively said no*. The latency is the signal: a
      refusal in single-digit milliseconds cannot have come from a real remote
      server and indicates an on-path appliance.
    * **Blackhole timeout** -- nothing came back at all. A silent packet drop.

    These are different failure modes with different causes and different
    remedies, so they are never collapsed into one another. ``ConnectionResetError``
    is checked explicitly because it is *not* a subclass of
    ``ConnectionRefusedError`` and would otherwise fall through to a generic
    error bucket.
    """
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return FailureKind.REFUSED, f"{type(exc).__name__}: {exc}"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return FailureKind.TIMEOUT, f"no response within {timeout_s}s"
    return FailureKind.OTHER_ERROR, f"{type(exc).__name__}: {exc}"


def probe_connect(address: str, port: int = 443, *, timeout_s: float = 3.0) -> ProbeResult:
    """Open a TCP connection to a literal address and classify the outcome.

    Does **not** resolve, and does not perform TLS -- this measures the L4
    reachability of the address itself, which is what distinguishes an active
    refusal from a silent blackhole.
    """
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((address, port))
    except OSError as exc:
        kind, detail = classify_connection_error(exc, timeout_s)
        return ProbeResult(
            address=address,
            kind=kind,
            latency_ms=(time.perf_counter() - started) * 1000,
            detail=detail,
        )
    finally:
        sock.close()

    elapsed = (time.perf_counter() - started) * 1000
    return ProbeResult(address=address, kind=FailureKind.SUCCESS, latency_ms=elapsed)


def probe_http(
    host: str,
    address: str,
    *,
    port: int = 443,
    path: str = "/",
    timeout_s: float = 6.0,
    ssl_context: ssl.SSLContext | None = None,
) -> ProbeResult:
    """Connect to ``address`` with SNI set to ``host`` and read the HTTP status.

    This is the decisive probe: it distinguishes "TCP is dead" from "TCP is fine
    but the server returns 451". A geo-block that answers ``HTTP 451`` must not
    be reported as poisoning, and this is what tells the two apart.
    """
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    context = ssl_context or ssl.create_default_context()
    try:
        try:
            sock.connect((address, port))
        except OSError as exc:
            kind, detail = classify_connection_error(exc, timeout_s)
            return ProbeResult(
                address, kind, (time.perf_counter() - started) * 1000, detail=detail,
            )

        cert_subject = ""
        cert_issuer = ""
        cert_valid = False
        try:
            tls = context.wrap_socket(sock, server_hostname=host)
        except ssl.SSLCertVerificationError as exc:
            # The handshake failed *verification*, but a certificate was still
            # presented. Capture it: a wrong-name certificate from the bogus
            # address is itself useful evidence, and its absence proves the
            # address is not a TLS endpoint at all.
            return ProbeResult(
                address, FailureKind.TLS_FAILURE,
                (time.perf_counter() - started) * 1000,
                detail=str(exc), cert_valid=False,
            )
        except ssl.SSLError as exc:
            return ProbeResult(
                address, FailureKind.TLS_FAILURE,
                (time.perf_counter() - started) * 1000, detail=str(exc),
            )
        except OSError as exc:
            return ProbeResult(
                address, FailureKind.TLS_FAILURE,
                (time.perf_counter() - started) * 1000,
                detail=f"{type(exc).__name__}: {exc}",
            )

        # A completed handshake means the chain validated for this hostname,
        # because the context is verifying. That is strong evidence the address
        # really serves this name.
        cert_valid = True
        cert_subject, cert_issuer = _peer_certificate_names(tls)

        with tls:
            tls.settimeout(timeout_s)
            # GET, not HEAD. A verified trap: the API host this library was
            # written for returns 404 for HEAD on a route that answers 200 for
            # GET, which would make a healthy endpoint look broken.
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: dns-shield/0.1.2\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            try:
                tls.sendall(request)
                raw = tls.recv(512)
            except (TimeoutError, socket.timeout):
                return ProbeResult(
                    address, FailureKind.TIMEOUT,
                    (time.perf_counter() - started) * 1000,
                    detail="no response after TLS handshake",
                )
            except OSError as exc:
                return ProbeResult(
                    address, FailureKind.OTHER_ERROR,
                    (time.perf_counter() - started) * 1000,
                    detail=f"{type(exc).__name__}: {exc}",
                )
    finally:
        try:
            sock.close()
        except OSError:
            pass

    elapsed = (time.perf_counter() - started) * 1000
    if not raw:
        return ProbeResult(
            address, FailureKind.OTHER_ERROR, elapsed,
            detail="server closed without a response",
            cert_subject=cert_subject, cert_issuer=cert_issuer, cert_valid=cert_valid,
        )

    status_line = raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    if status is None:
        return ProbeResult(
            address, FailureKind.OTHER_ERROR, elapsed,
            detail=f"unparsable status line {status_line[:60]!r}",
            cert_subject=cert_subject, cert_issuer=cert_issuer, cert_valid=cert_valid,
        )
    kind = FailureKind.SUCCESS if 200 <= status < 400 else FailureKind.HTTP_ERROR
    return ProbeResult(
        address, kind, elapsed, status=status,
        cert_subject=cert_subject, cert_issuer=cert_issuer, cert_valid=cert_valid,
    )


def _peer_certificate_names(tls: ssl.SSLSocket) -> tuple[str, str]:
    """Return ``(subject_cn, issuer_cn)`` for the peer certificate, or empties.

    Best-effort: a server may present no certificate in unusual configurations,
    and a failure here must never turn a successful probe into an exception.
    ``getpeercert()`` returns ``{}`` unless the socket was created with a
    verifying context and a hostname, which is exactly our case.
    """
    try:
        cert = tls.getpeercert()
    except (ValueError, OSError):
        return "", ""
    if not cert:
        return "", ""

    return _common_name(cert.get("subject")), _common_name(cert.get("issuer"))


def _common_name(field: object) -> str:
    """Extract the ``commonName`` from an RDN sequence.

    The structure is a tuple of tuples of (key, value) pairs, e.g.
    ``((('commonName', '*.binance.com'),), (('organizationName', 'X'),))``.
    """
    if not isinstance(field, (tuple, list)):
        return ""
    for rdn in field:
        if not isinstance(rdn, (tuple, list)):
            continue
        for attribute in rdn:
            if (
                isinstance(attribute, (tuple, list))
                and len(attribute) == 2
                and attribute[0] == "commonName"
                and isinstance(attribute[1], str)
            ):
                return attribute[1]
    return ""


# -- classification --------------------------------------------------------


def classify(evidence: Evidence) -> Diagnosis:
    """Turn measured evidence into a verdict.

    Ordering matters: the first rule that matches wins, and the rules are
    arranged so that the *most specific and most defensible* conclusion is
    reached. In particular, "the DoH address also fails" is checked before any
    poisoning claim, because a host that is down everywhere is not poisoned.
    """
    host = evidence.host
    reasons: list[str] = []

    system_probe = evidence.system_probe
    doh_probe = evidence.doh_probe

    # -- 0. Not enough to go on -----------------------------------------
    if not evidence.doh_ips:
        return Diagnosis(
            host=host,
            verdict=Verdict.UNKNOWN,
            summary=(
                "could not obtain a trustworthy answer over DoH"
                + (f" ({evidence.doh_error})" if evidence.doh_error else "")
            ),
            evidence=evidence,
            reasons=("no DoH answer to compare against",),
        )

    # "The server answered" is the right test, not "the server returned 2xx".
    # An API host legitimately returns 403 for "/" while serving 200 on its
    # real routes; treating that as unreachable was a bug caught by running
    # against the live host this library was written for.
    doh_alive = doh_probe is not None and doh_probe.server_is_alive
    system_alive = system_probe is not None and system_probe.server_is_alive

    # -- 1. Both paths serve the host -----------------------------------
    if doh_alive and system_alive:
        reasons.append(
            f"system DNS answer {system_probe.address if system_probe else '?'}: "
            f"{system_probe.describe() if system_probe else 'no probe'}"
        )
        reasons.append(
            f"DoH answer {doh_probe.address if doh_probe else '?'}: "
            f"{doh_probe.describe() if doh_probe else 'no probe'}"
        )
        if evidence.answers_disagree:
            reasons.append("both addresses serve the host, so this is CDN rotation")
            return Diagnosis(
                host=host,
                verdict=Verdict.HEALTHY,
                summary=(
                    "reachable; the two resolvers disagree because the host is on a "
                    "rotating CDN, not because of poisoning"
                ),
                evidence=evidence,
                reasons=tuple(reasons),
            )
        return Diagnosis(
            host=host,
            verdict=Verdict.HEALTHY,
            summary="system DNS and DoH agree and the host responds",
            evidence=evidence,
            reasons=tuple(reasons) + ("both resolution paths agree",),
        )

    # -- 1b. The two paths disagree and only the *system* answer works ---
    # This is genuinely ambiguous and must not be guessed at. The system
    # resolver is serving the host, so it is not obviously lying; the DoH
    # answer failing could be a stale CDN edge, a transient outage at the
    # provider, or a poisoned DoH path. Report suspicion, not a verdict.
    if system_alive and not doh_alive and evidence.answers_disagree:
        return Diagnosis(
            host=host,
            verdict=Verdict.SUSPICIOUS,
            summary=(
                "the system resolver serves the host but the DoH answer does not; "
                "the evidence does not support calling this poisoning"
            ),
            evidence=evidence,
            reasons=(
                f"system DNS {', '.join(evidence.system_ips)} "
                f"{system_probe.describe() if system_probe else ''}".strip(),
                f"DoH {', '.join(evidence.doh_ips)} failed: "
                f"{doh_probe.describe() if doh_probe else 'no probe'}",
                "a working system answer is not proof of honesty, but it removes "
                "the basis for a poisoning claim",
            ),
        )

    # -- 1c. DoH serves the host and the system resolver returned nothing --
    # There is no contradictory answer to compare, so nothing supports a
    # poisoning claim. The host is reachable; the local resolver simply had no
    # record (NXDOMAIN, a timeout, or an empty reply).
    if doh_alive and not evidence.system_ips:
        reasons.append(
            f"DoH answer {', '.join(evidence.doh_ips)} "
            f"{doh_probe.describe() if doh_probe else 'worked'}"
        )
        if evidence.system_error:
            reasons.append(f"the local resolver failed: {evidence.system_error}")
        else:
            reasons.append("the local resolver returned no address, without an error")
        reasons.append("no contradictory answer exists, so poisoning cannot be claimed")
        return Diagnosis(
            host=host,
            verdict=Verdict.UNREACHABLE,
            summary=(
                "the host is reachable over DoH, but the local resolver returned no "
                "address for it; a resolution failure, not poisoning"
            ),
            evidence=evidence,
            reasons=tuple(reasons),
        )

    # -- 2. The real address answered with an HTTP error status ----------
    # Checked before any poisoning claim. If the *true* address returns 4xx/5xx,
    # a real server is talking to us, so name resolution is not the problem.
    # Reporting that as poisoning would be exactly the false accusation this
    # tool exists to avoid.
    #
    # Note on 403: an API host commonly returns 403 for paths it does not serve
    # while answering 200 on its real routes. The status is therefore a
    # statement about the *path*, not about reachability. What it does prove is
    # that a live, correctly-named endpoint is answering -- so DNS is healthy.
    if doh_probe is not None and doh_probe.kind is FailureKind.HTTP_ERROR:
        status = doh_probe.status or 0
        if status in {451, 403}:
            return Diagnosis(
                host=host,
                verdict=Verdict.UNREACHABLE,
                summary=(
                    f"the real address returns HTTP {status} for {evidence.probed_path!r}: the host "
                    "resolves correctly, but the server refuses this request. This "
                    "is a server-side or geo restriction, not DNS poisoning"
                ),
                evidence=evidence,
                reasons=(
                    f"DoH address {', '.join(evidence.doh_ips)} answers with HTTP {status}",
                    "a real server responded, so name resolution is not the problem",
                    "rule out DNS: re-run with --path pointing at a route the host serves",
                ),
            )
        return Diagnosis(
            host=host,
            verdict=Verdict.UNREACHABLE,
            summary=f"the real address answered HTTP {status} for {evidence.probed_path!r}",
            evidence=evidence,
            reasons=(
                f"DoH address returned HTTP {status}",
                "the server is reachable, so the resolver is not the fault",
            ),
        )

    # -- 2b. The real address does not serve the host --------------------
    # Checked before any poisoning claim. If the *true* address is dead too,
    # the host is genuinely down and blaming the ISP would be a lie.
    if not doh_alive:
        kind = doh_probe.kind if doh_probe else FailureKind.DNS_FAILURE

        if kind is FailureKind.TLS_FAILURE:
            return Diagnosis(
                host=host,
                verdict=Verdict.UNREACHABLE,
                summary=(
                    "the real address is reachable but its TLS handshake fails; "
                    "this is not DNS poisoning"
                ),
                evidence=evidence,
                reasons=(
                    "TCP connected to the DoH address",
                    "TLS failed, which points at interception or a broken endpoint",
                ),
            )
        return Diagnosis(
            host=host,
            verdict=Verdict.UNREACHABLE,
            summary="the real address could not be reached from this network",
            evidence=evidence,
            reasons=(
                f"DoH address probe result: {doh_probe.describe() if doh_probe else 'n/a'}",
                "since the true address also fails, the resolver is not the fault",
            ),
        )

    # -- 2c. The two paths agreed, but only one probe succeeded ----------
    # Both resolvers named the same address, and the DoH probe served it while
    # the system probe did not. That is a *transient* failure of one probe, not
    # evidence about the resolver -- two connects to the same literal IP ran
    # seconds apart. Calling this poisoning would be a false accusation, and it
    # would fire on any rate-limited or congested host.
    if not evidence.answers_disagree:
        return Diagnosis(
            host=host,
            verdict=Verdict.SUSPICIOUS,
            summary=(
                "both resolvers returned the same address, and only one of the two "
                "probes reached it; this is a transient failure, not poisoning"
            ),
            evidence=evidence,
            reasons=(
                f"system DNS and DoH agree on "
                f"{', '.join(sorted(set(evidence.system_ips) & set(evidence.doh_ips)))}",
                f"system probe: {system_probe.describe() if system_probe else 'not run'}",
                f"DoH probe: {doh_probe.describe() if doh_probe else 'not run'}",
                "the same address cannot be both real and bogus, so this is not a "
                "resolver lie; re-run to confirm",
            ),
        )

    # -- 3. DoH serves the host, system DNS does not => poisoning --------
    # Reached only here when the resolvers genuinely disagree: the address the
    # system resolver returned is not among the addresses DoH returned, so the
    # two answers are about different hosts. That is the poisoning signature.
    if not system_alive:
        if system_probe is not None:
            reasons.append(f"system DNS answered {', '.join(evidence.system_ips)}")
            reasons.append(f"that address {system_probe.describe()}")
        else:
            reasons.append(
                "the system resolver returned "
                + (", ".join(evidence.system_ips) or "no address")
                + ", which was not reachable"
            )

        reasons.append(
            f"DoH answered {', '.join(evidence.doh_ips)}"
            + (f" via {' -> '.join(evidence.cnames)}" if evidence.cnames else "")
        )
        reasons.append(f"the DoH address {doh_probe.describe() if doh_probe else 'worked'}")

        if doh_probe is not None and doh_probe.cert_valid and doh_probe.cert_subject:
            reasons.append(
                f"the DoH address presented a valid certificate for "
                f"{doh_probe.cert_subject}, so it really is serving this host"
            )

        if system_probe is not None and system_probe.fast_refusal:
            reasons.append(
                f"the refusal came back in {system_probe.latency_ms:.0f} ms, "
                "which is the signature of a synthetic reset"
            )
        elif system_probe is not None and system_probe.kind is FailureKind.TIMEOUT:
            reasons.append(
                "the connection timed out rather than being refused; a blackhole "
                "appliance often varies between the two, so this does not "
                "weaken the finding"
            )

        if evidence.shared_ip_hosts:
            reasons.append(
                "the same address is served for unrelated hostnames: "
                + ", ".join(evidence.shared_ip_hosts)
            )

        return Diagnosis(
            host=host,
            verdict=Verdict.POISONED,
            summary=(
                "the system resolver is returning a false answer: the address it "
                "returns does not serve the host, and the DoH answer does"
            ),
            evidence=evidence,
            reasons=tuple(reasons),
        )

    # -- 5. Fallback: reachable, but the evidence is contradictory ------
    # Reachable only when DoH served the host and the system answer did too,
    # yet the statuses disagree in a way no earlier rule captured. That is
    # genuinely ambiguous, so the tool says so rather than guessing.
    reasons.append(f"system DNS: {', '.join(evidence.system_ips) or 'no answer'}")
    reasons.append(f"DoH: {', '.join(evidence.doh_ips)}")
    reasons.append(
        f"DoH address probe: {doh_probe.describe() if doh_probe else 'not run'}"
    )
    return Diagnosis(
        host=host,
        verdict=Verdict.SUSPICIOUS,
        summary=(
            "the evidence is contradictory and does not support a poisoning claim; "
            "treat this as inconclusive"
        ),
        evidence=evidence,
        reasons=tuple(reasons),
    )


# -- orchestration ---------------------------------------------------------


def diagnose(
    host: str,
    *,
    resolver: DohResolver | None = None,
    port: int = 443,
    path: str = "/",
    compare_hosts: Sequence[str] = (),
    timeout_s: float = 3.0,
    do_http_probe: bool = True,
) -> Diagnosis:
    """Measure and classify ``host``.

    ``compare_hosts`` is a cheap way to demonstrate the shared-IP pattern: pass
    sibling hostnames and any that resolve to the same system address are
    recorded as evidence.
    """
    active = resolver or DohResolver()
    notes: list[str] = []

    system_ips: tuple[str, ...] = ()
    system_error = ""
    try:
        system_ips = system_resolve(host, port=port)
    except OSError as exc:
        system_error = f"{type(exc).__name__}: {exc}"

    doh_ips: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    doh_provider = ""
    doh_error = ""
    try:
        records = active.query_records(host, "A")
        doh_ips = records.addresses
        cnames = records.cnames
        doh_provider = records.provider
    except DohResolutionError as exc:
        doh_error = str(exc)

    system_probe: ProbeResult | None = None
    if system_ips:
        if do_http_probe:
            system_probe = probe_http(
                host, system_ips[0], port=port, path=path, timeout_s=timeout_s
            )
        else:
            system_probe = probe_connect(system_ips[0], port, timeout_s=timeout_s)

    doh_probe: ProbeResult | None = None
    if doh_ips:
        if do_http_probe:
            doh_probe = probe_http(host, doh_ips[0], port=port, path=path, timeout_s=timeout_s)
        else:
            doh_probe = probe_connect(doh_ips[0], port, timeout_s=timeout_s)

    shared: list[str] = []
    if system_ips:
        target = system_ips[0]
        for sibling in compare_hosts:
            if sibling == host:
                continue
            try:
                sibling_ips = system_resolve(sibling, port=port)
            except OSError:
                continue
            if target in sibling_ips:
                shared.append(sibling)

    if system_error:
        notes.append(f"system resolver error: {system_error}")
    if doh_error:
        notes.append(f"DoH error: {doh_error}")

    evidence = Evidence(
        host=host,
        system_ips=system_ips,
        doh_ips=doh_ips,
        doh_provider=doh_provider,
        cnames=cnames,
        system_probe=system_probe,
        doh_probe=doh_probe,
        shared_ip_hosts=tuple(shared),
        doh_error=doh_error,
        system_error=system_error,
        probed_path=path,
        notes=tuple(notes),
    )
    return classify(evidence)
