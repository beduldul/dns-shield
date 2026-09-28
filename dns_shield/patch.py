"""Route *specific* requests through the shield.

SCOPE, STATED PLAINLY
---------------------
This is a **targeted override**, not a global DNS hijack. It does not touch
``/etc/hosts``, it does not reconfigure the system resolver, and it does not
intercept anything you did not explicitly hand it. Only the URLs you pass
through a :class:`ShieldAdapter` or :func:`resolve_and_call` are affected;
everything else on the machine keeps using the ISP's resolver, for better or
worse.

Why an adapter at all? Because the naive approach -- resolve over DoH, then call
``requests.get(url)`` -- silently re-resolves through the poisoned resolver and
fails. See :mod:`dns_shield.transport`. So an adapter here does not merely
"set a DNS server"; it mounts the shield's own socket-level transport.

TLS VERIFICATION IS NOT DISABLED
--------------------------------
The whole technique works *because* SNI and ``Host`` are preserved, so the
server presents a certificate for the real hostname and normal CA verification
succeeds. There is therefore never a reason to pass ``verify=False``. This
module does not expose such an option, and neither should your call sites.
"""

from __future__ import annotations

from typing import Any, Mapping

from .resolve import DohResolver
from .transport import ShieldResponse, SniHTTPClient, SuccessContract

__all__ = [
    "RequestsShieldAdapter",
    "ShieldSession",
    "requests_available",
    "resolve_and_call",
    "shielded_client",
]


def _import_requests() -> Any:
    """Import ``requests`` only when the ``requests`` adapter is actually used.

    Importing it eagerly would make ``import dns_shield`` pull in urllib3 and
    certifi for every user, including those who never touch the adapter. It
    would also mean the library could not be imported at all on a machine
    without ``requests``, which is a needless constraint.
    """
    try:
        import requests  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "RequestsShieldAdapter requires 'requests'; "
            "install it with: pip install 'dns-shield[requests]'"
        ) from exc
    return requests


def requests_available() -> bool:
    """True if the optional ``requests`` dependency can be imported."""
    try:
        _import_requests()
    except RuntimeError:
        return False
    return True


class ShieldSession:
    """A ``requests.Session``-shaped object that routes every call through the shield.

    Only methods on this object are affected. This is deliberate: monkeypatching
    ``requests`` globally would be surprising and would break unrelated code in
    the same process.

    Example::

        session = ShieldSession()
        response = session.get("https://fapi.binance.com/fapi/v1/ping")
    """

    def __init__(
        self,
        resolver: DohResolver | None = None,
        *,
        client: SniHTTPClient | None = None,
        success_contract: SuccessContract | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._client = client or SniHTTPClient(
            resolver=resolver, success_contract=success_contract
        )
        self._headers: dict[str, str] = dict(headers or {})

    @property
    def client(self) -> SniHTTPClient:
        """The underlying shield transport."""
        return self._client

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: Any | None = None,
        data: bytes | None = None,
        timeout: float | None = None,
    ) -> ShieldResponse:
        """Issue a shielded request. Returns a :class:`ShieldResponse`."""
        merged: dict[str, str] = dict(self._headers)
        if headers:
            merged.update(headers)
        if timeout is not None:
            self._client.read_timeout_s = timeout
        return self._client.send(
            method, url, headers=merged, json_body=json_body, data=data
        )

    def get(self, url: str, **kwargs: Any) -> ShieldResponse:
        """Shielded GET."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> ShieldResponse:
        """Shielded POST."""
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        """Present for API symmetry; the shield holds no pooled connections."""

    def __enter__(self) -> ShieldSession:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def resolve_and_call(
    url: str,
    *,
    method: str = "GET",
    resolver: DohResolver | None = None,
    headers: Mapping[str, str] | None = None,
    timeout_s: float | None = None,
) -> ShieldResponse:
    """One-line helper: fetch ``url`` through the shield.

    Example::

        response = resolve_and_call("https://fapi.binance.com/fapi/v1/ping")
        print(response.status, response.address, response.text[:120])
    """
    client = SniHTTPClient(resolver=resolver)
    if timeout_s is not None:
        client.read_timeout_s = timeout_s
    return client.send(method, url, headers=headers)


def shielded_client(resolver: DohResolver | None = None) -> SniHTTPClient:
    """Return a bare :class:`SniHTTPClient` for callers who want the full API."""
    return SniHTTPClient(resolver=resolver)


class RequestsShieldAdapter:
    """Mounts the shield as a ``requests`` transport adapter, per-prefix.

    Unlike :class:`ShieldSession` this *does* integrate with ``requests``, but
    still only for URL prefixes you explicitly mount -- ``requests`` dispatches
    by longest-prefix match, so nothing else is touched.

    .. warning::
       Because the shield speaks HTTP/1.1 directly, an adapted request loses
       ``requests`` features that depend on urllib3 (connection pooling,
       streaming, automatic redirect following). Use :class:`ShieldSession` for
       new code; this exists so existing ``requests`` call sites can be migrated
       one prefix at a time.

    Requires ``requests``; raises :class:`RuntimeError` at construction if it is
    not installed.
    """

    def __init__(
        self,
        prefix: str,
        resolver: DohResolver | None = None,
        *,
        session: Any = None,
    ) -> None:
        requests = _import_requests()
        self.prefix = prefix
        self.session = session or requests.Session()
        self._client = SniHTTPClient(resolver=resolver)

    def mount_into(self, target_session: Any) -> Any:
        """Attach this adapter to ``target_session`` for the configured prefix."""
        target_session.mount(self.prefix, _ShieldTransportAdapter(self._client))
        return target_session


class _ShieldTransportAdapter:
    """``requests`` HTTPAdapter subclass that routes through the shield client.

    Defined lazily so importing :mod:`dns_shield.patch` does not require
    ``requests``.
    """

    def __new__(cls, client: SniHTTPClient) -> Any:  # noqa: D102
        from requests.adapters import HTTPAdapter  # noqa: PLC0415

        class _Adapter(HTTPAdapter):  # type: ignore[misc]
            def __init__(self, shield_client: SniHTTPClient) -> None:
                super().__init__()
                self._shield = shield_client

            def send(self, request: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                requests = _import_requests()

                response = self._shield.send(
                    request.method,
                    request.url,
                    headers=dict(request.headers),
                    data=request.body if isinstance(request.body, bytes) else None,
                    raise_for_status=False,
                )
                built = requests.Response()
                built.status_code = response.status
                built._content = response.text.encode("utf-8")
                built.url = response.url
                built.encoding = "utf-8"
                built.headers["X-DNS-Shield-Address"] = response.address
                return built

        return _Adapter(client)
