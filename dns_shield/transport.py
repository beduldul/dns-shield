"""SNI-preserving HTTP/1.1 transport.

THE CRITICAL INSIGHT
--------------------
You cannot resolve a host over DoH and then hand the URL to ``requests``,
``urllib`` or ``http.client``. All of them call ``socket.create_connection``
internally, which re-resolves the hostname through the **poisoned system
resolver** and throws away the address you carefully looked up. The request then
fails exactly as if you had done nothing at all.

This is verified, not theoretical. On the machine this library was written for::

    requests.get("https://fapi.binance.com/fapi/v1/ping")  ->  ConnectTimeout
    socket -> DoH IP + server_hostname="fapi.binance.com"  ->  HTTP/1.1 200 OK

So this module speaks HTTP/1.1 itself, over a socket it opened to a specific
address. It never calls :func:`socket.getaddrinfo` on the request path.

What it does NOT support
------------------------
* **HTTP/3 / QUIC.** HTTP/1.1 only. ``Connection: close`` per request, so there
  is no connection pooling or keep-alive reuse.
* **Redirects to a different host.** A 3xx is returned to you verbatim; this
  client will not silently follow a redirect, because following one would mean
  resolving a second host and the whole point is to control resolution.
  Follow it yourself with an explicit second call if you trust the target.
* **Proxies.** No ``HTTP_PROXY`` / ``CONNECT`` tunnel support.
* **IPv6 dialling.** IPv6 records can be *resolved* (:mod:`dns_shield.resolve`)
  but the transport dials IPv4. See README "Limitations".
* **Streaming / large downloads.** The body is read into memory in full.
* **Certificate pinning.** Standard CA verification for the requested hostname.

Body-level error codes
----------------------
Some APIs return **HTTP 200** with an error *inside* the JSON body. Checking the
status code alone is therefore wrong. The original motivating case was Binance's
BAPI, which wraps its status in a ``code`` field: a request for a closed
portfolio returned ``200 {"code":"11012030", ...}``. That capability is kept
here as a configurable contract (``success_field`` / ``success_value``) so the
caller can enforce it, with the Binance values available as a preset.
"""

from __future__ import annotations

import json
import random
import socket
import ssl
import time
import urllib.parse
from typing import Any, Callable, Final, Mapping

from . import config
from .resolve import DohResolutionError, DohResolver

__all__ = [
    "BINANCE_SUCCESS_CONTRACT",
    "SuccessContract",
    "TransportError",
    "ShieldResponse",
    "SniHTTPClient",
    "dechunk",
    "read_body",
    "read_head",
]

#: The retryable status set, re-exported for callers writing their own policy.
RETRYABLE_STATUS: Final[frozenset[int]] = config.RETRYABLE_STATUS


class TransportError(RuntimeError):
    """Raised for transport failures, non-2xx responses, or a failed contract."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        url: str | None = None,
        body: str | None = None,
        code: str | None = None,
        address: str | None = None,
        kind: str | None = None,
    ) -> None:
        super().__init__(message)
        #: HTTP status, when a response was received at all.
        self.status: int | None = status
        self.url: str | None = url
        self.body: str | None = body
        #: The body-level error code, when one was found.
        self.code: str | None = code
        #: The address that was dialled when the failure occurred.
        self.address: str | None = address
        #: Coarse failure class: ``connect``/``timeout``/``tls``/``http``/``contract``/
        #: ``resolution``. ``resolution`` means DoH could not produce an address,
        #: which is a different problem from the address refusing to connect.
        self.kind: str | None = kind

    @property
    def is_rate_limit(self) -> bool:
        """True if this looks like a rate-limit or capacity signal."""
        return self.status == 429 or self.code in {"11012030", "-1003"}


class SuccessContract:
    """An optional assertion that a 2xx body is *semantically* a success.

    Use when an API signals failure inside the body. Example, for Binance BAPI::

        SuccessContract(field="code", value="000000")

    A response whose body lacks ``field`` is accepted (the contract only fires
    when the field is present), so this is safe to leave enabled against an API
    that sometimes returns plain payloads.
    """

    __slots__ = ("field", "value")

    def __init__(self, field: str, value: str) -> None:
        self.field = field
        self.value = value

    def check(self, payload: Any, *, url: str, body: str) -> None:
        """Raise :class:`TransportError` if ``payload`` violates the contract."""
        if not isinstance(payload, dict):
            return
        found = payload.get(self.field)
        if found is None or str(found) == self.value:
            return
        raise TransportError(
            f"body-level {self.field}={found!r} != {self.value!r}",
            url=url,
            body=body[:200],
            code=str(found),
            kind="contract",
        )


#: Preset for Binance BAPI. Verified trap: a closed portfolio is
#: ``HTTP 200`` with ``{"code": "11012030"}``. Status alone says "fine".
BINANCE_SUCCESS_CONTRACT: Final[SuccessContract] = SuccessContract("code", "000000")


class ShieldResponse:
    """A minimal HTTP response -- status, headers, body, and dialled address.

    Deliberately not a ``requests.Response``; it is a value object so tests can
    construct one without a socket.
    """

    __slots__ = ("status", "headers", "text", "url", "address")

    def __init__(
        self,
        status: int,
        headers: Mapping[str, str],
        text: str,
        url: str,
        address: str,
    ) -> None:
        self.status = status
        self.headers: dict[str, str] = dict(headers)
        self.text = text
        self.url = url
        self.address = address

    def json(self) -> Any:
        """Decode the body as JSON."""
        return json.loads(self.text)

    @property
    def ok(self) -> bool:
        """True for a 2xx status."""
        return 200 <= self.status < 300

    def __repr__(self) -> str:
        return f"<ShieldResponse {self.status} {self.url} via {self.address}>"


def parse_status_line(raw: bytes) -> int:
    """Parse an HTTP status line tolerantly, returning the status code.

    Uses whitespace splitting rather than ``split(" ", 2)`` because RFC 7230
    permits a missing reason phrase (``HTTP/1.1 204``) and servers in the wild
    emit doubled spaces. The stricter form rejected both, reporting a protocol
    error for a response that is perfectly legal.
    """
    parts = raw.decode("latin-1", errors="replace").split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise TransportError(f"malformed status line: {raw[:80]!r}", kind="http")
    try:
        return int(parts[1])
    except ValueError as exc:
        raise TransportError(f"malformed status line: {raw[:80]!r}", kind="http") from exc


def read_head(sock: socket.socket, url: str) -> tuple[int, dict[str, str], bytes]:
    """Read the status line and headers; return ``(status, headers, leftover)``.

    ``leftover`` holds body bytes that arrived in the same TCP segment as the
    headers, which is the common case for small JSON responses. Dropping it
    truncates the body -- a subtle bug worth keeping the comment for.
    """
    buffer = b""
    complete = False
    while True:
        if b"\r\n\r\n" in buffer:
            complete = True
            break
        if len(buffer) > 64 * 1024:
            raise TransportError("response headers exceeded 64 KiB", url=url, kind="http")
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk

    if not complete:
        # The peer closed without terminating its header block. Accepting the
        # partial head would yield a status with no headers and no body, which
        # is indistinguishable from a legitimate empty 200 -- the failure would
        # then surface far away as a JSON decode error. Fail loudly here instead.
        raise TransportError(
            f"connection closed before headers were complete ({len(buffer)} bytes read)",
            url=url,
            kind="http",
        )

    head_bytes, _, leftover = buffer.partition(b"\r\n\r\n")
    lines = head_bytes.split(b"\r\n")
    if not lines or not lines[0]:
        raise TransportError("empty response from server", url=url, kind="http")

    status = parse_status_line(lines[0])

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return status, headers, leftover


def read_body(sock: socket.socket, headers: Mapping[str, str], buffer: bytes) -> bytes:
    """Read the full response body given the already-parsed headers."""
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return dechunk(sock, buffer)

    raw_length = headers.get("content-length")
    if raw_length is not None:
        try:
            length = int(raw_length)
        except ValueError:
            length = -1
        if length >= 0:
            while len(buffer) < length:
                chunk = sock.recv(min(65536, length - len(buffer)))
                if not chunk:
                    break
                buffer += chunk
            return buffer[:length]

    # No framing information: the server signals end-of-body by closing.
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer += chunk
    return buffer


def dechunk(sock: socket.socket, buffer: bytes) -> bytes:
    """Decode an HTTP/1.1 chunked transfer body.

    Each chunk must be followed by CRLF. A missing terminator means the stream
    is malformed or truncated, and returning the bytes read so far would present
    a short body as a complete one -- so it raises instead.
    """
    body = b""
    while True:
        while b"\r\n" not in buffer:
            chunk = sock.recv(65536)
            if not chunk:
                raise TransportError(
                    "chunked body ended before a chunk-size line", kind="http"
                )
            buffer += chunk
        size_line, _, buffer = buffer.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError as exc:
            raise TransportError(f"bad chunk size {size_line[:32]!r}", kind="http") from exc
        if size == 0:
            return body
        while len(buffer) < size + 2:
            chunk = sock.recv(65536)
            if not chunk:
                raise TransportError(
                    f"chunked body truncated with {len(buffer)} of {size + 2} bytes",
                    kind="http",
                )
            buffer += chunk
        if buffer[size : size + 2] != b"\r\n":
            raise TransportError(
                f"chunk not terminated by CRLF: {buffer[size : size + 2]!r}", kind="http"
            )
        body += buffer[:size]
        buffer = buffer[size + 2 :]


def backoff_delay(
    attempt: int,
    *,
    base_s: float = config.BACKOFF_BASE_S,
    max_s: float = config.BACKOFF_MAX_S,
    rng: random.Random | None = None,
) -> float:
    """Exponential backoff with full jitter, capped at ``max_s``.

    The window is ``[base_s, ceiling]`` rather than ``[0, ceiling]``. Pure full
    jitter admits a zero-length sleep, which against a fast-refusing endpoint
    would spin through the whole attempt budget instantly and hammer the peer.
    A floor keeps the retry loop honest.
    """
    ceiling = min(base_s * (2**attempt), max_s)
    floor = min(base_s, ceiling)
    generator = rng or random
    return generator.uniform(floor, ceiling) if ceiling > floor else ceiling


def retry_after_seconds(
    text: str,
    attempt: int,
    *,
    max_s: float = config.BACKOFF_MAX_S,
) -> float:
    """Honour a server ``retryAfter`` hint (ms) when present, else back off."""
    try:
        payload = json.loads(text)
        retry_ms = payload.get("retryAfter")
        if not isinstance(retry_ms, (int, float)):
            data = payload.get("data")
            retry_ms = data.get("retryAfter") if isinstance(data, dict) else None
        if isinstance(retry_ms, (int, float)) and retry_ms > 0:
            honoured = min(float(retry_ms) / 1000.0, max_s)
            # Never sleep literally zero: a peer asking for "0 ms" plus a
            # fast-failing connection would spin through the attempt budget.
            return max(honoured, config.BACKOFF_BASE_S)

    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    return backoff_delay(attempt, max_s=max_s)


class SniHTTPClient:
    """HTTP client that connects to a DoH-resolved address while preserving SNI/Host.

    ``sleeper`` is injected rather than imported so tests can exercise retry and
    backoff logic without ever blocking on the wall clock.
    """

    def __init__(
        self,
        resolver: DohResolver | None = None,
        *,
        user_agent: str = config.USER_AGENT,
        connect_timeout_s: float = config.CONNECT_TIMEOUT_S,
        read_timeout_s: float = config.READ_TIMEOUT_S,
        max_attempts: int = config.MAX_RETRIES,
        success_contract: SuccessContract | None = None,
        ssl_context: ssl.SSLContext | None = None,
        connect: Callable[..., socket.socket] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.resolver = resolver or DohResolver()
        self.user_agent = user_agent
        self.connect_timeout_s = connect_timeout_s
        self.read_timeout_s = read_timeout_s
        self.max_attempts = max_attempts
        self.success_contract = success_contract
        self._ssl_context = ssl_context or ssl.create_default_context()
        # ``socket.create_connection`` with a literal address does NOT consult
        # the system resolver. It is overridable so tests can assert the dial
        # never reaches getaddrinfo.
        self._connect = connect or socket.create_connection
        self._sleep = sleeper

    # -- internals ------------------------------------------------------

    def _dial(self, address: str, port: int) -> socket.socket:
        """Open a TCP connection to a literal address, never re-resolving."""
        return self._connect((address, port), timeout=self.connect_timeout_s)

    def _open(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None,
        headers: Mapping[str, str],
        address: str,
    ) -> tuple[int, str]:
        """Open one SNI-preserving connection; return ``(status, text)``.

        We cannot use ``urllib``/``http.client`` here: both call
        ``socket.create_connection`` internally with a *hostname*, which would
        re-resolve through the poisoned system resolver and discard the socket
        we carefully pointed at a CDN address. Instead we speak HTTP/1.1
        ourselves over the socket we opened.
        """
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if host is None:
            raise TransportError(f"URL has no host: {url}", url=url, kind="connect")

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            raw_sock = self._dial(address, port)
        except (TimeoutError, socket.timeout) as exc:
            raise TransportError(
                f"connect timed out to {address}:{port}",
                url=url,
                address=address,
                kind="timeout",
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"connect failed to {address}:{port}: {type(exc).__name__}: {exc}",
                url=url,
                address=address,
                kind="connect",
            ) from exc

        try:
            if parsed.scheme == "https":
                tls_sock = self._ssl_context.wrap_socket(raw_sock, server_hostname=host)
            else:
                tls_sock = raw_sock
        except ssl.SSLError as exc:
            raw_sock.close()
            raise TransportError(
                f"TLS handshake failed for {host} via {address}: {exc}",
                url=url,
                address=address,
                kind="tls",
            ) from exc
        except OSError as exc:
            raw_sock.close()
            raise TransportError(
                f"TLS socket error for {host} via {address}: {exc}",
                url=url,
                address=address,
                kind="tls",
            ) from exc

        with tls_sock:
            tls_sock.settimeout(self.read_timeout_s)

            head: dict[str, str] = {
                "Host": host,
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "User-Agent": self.user_agent,
            }
            for key, value in headers.items():
                head[key] = value
            if body is not None:
                head["Content-Length"] = str(len(body))

            request_lines = [f"{method} {path} HTTP/1.1"]
            request_lines.extend(f"{k}: {v}" for k, v in head.items())
            raw_request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8")
            if body is not None:
                raw_request += body

            try:
                tls_sock.sendall(raw_request)
            except OSError as exc:
                raise TransportError(
                    f"send failed via {address}: {exc}",
                    url=url,
                    address=address,
                    kind="connect",
                ) from exc

            status, response_headers, buffer = read_head(tls_sock, url)
            payload = read_body(tls_sock, response_headers, buffer)

        return status, payload.decode("utf-8", errors="replace")

    # -- public API -----------------------------------------------------

    def send(
        self,
        method: str,
        url: str,
        *,
        json_body: Any | None = None,
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        content_type: str | None = None,
        raise_for_status: bool = True,
    ) -> ShieldResponse:
        """Perform a request with retries, address rotation, and backoff.

        Each attempt dials the next address from the resolved set, so a single
        dead edge node does not fail the request.
        """
        merged: dict[str, str] = {
            "user-agent": self.user_agent,
            "accept": "application/json, text/plain, */*",
        }
        if headers:
            merged.update(headers)

        body = data
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            merged.setdefault("content-type", "application/json")
        elif content_type is not None:
            merged["content-type"] = content_type

        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if host is None:
            raise TransportError(f"URL has no host: {url}", url=url, kind="connect")

        last_error: TransportError | None = None
        # Track which addresses we have already burned in this call. We rotate
        # through the cached set first and only re-resolve once every address
        # in it has failed -- re-resolving after the *first* failure would hand
        # us a fresh cursor at index 0 and retry the same dead edge forever.
        tried: set[str] = set()
        for attempt in range(self.max_attempts):
            try:
                resolved = self.resolver.resolve_host(host)
                if tried and tried >= set(resolved.ips):
                    # Every known address failed: the answer set itself is
                    # stale, so force a re-query before trying again.
                    self.resolver.invalidate(host)
                    resolved = self.resolver.resolve_host(host, force=True)
                    tried.clear()
                address = resolved.next_ip()
            except DohResolutionError as exc:
                last_error = TransportError(
                    f"resolution failed: {exc}", url=url, kind="resolution"
                )
                self._sleep(backoff_delay(attempt))
                continue

            try:
                status, text = self._open(
                    method, url, body=body, headers=merged, address=address
                )
            except TransportError as exc:
                last_error = exc
                # Only a failed dial is evidence that this *particular* address
                # is bad. Record it and rotate to the next one.
                if exc.kind in {"connect", "timeout"}:
                    tried.add(address)
                self._sleep(backoff_delay(attempt))
                continue

            response = ShieldResponse(status, {}, text, url, address)

            if status in RETRYABLE_STATUS:
                last_error = TransportError(
                    f"HTTP {status}", status=status, url=url, body=text[:400],
                    address=address, kind="http",
                )
                self._sleep(retry_after_seconds(text, attempt))
                continue

            if raise_for_status and status >= 400:
                raise TransportError(
                    f"HTTP {status}", status=status, url=url, body=text[:400],
                    address=address, kind="http",
                )

            return response

        raise last_error or TransportError(
            "request failed with no error recorded", url=url, kind="connect"
        )

    def get(self, url: str, **kwargs: Any) -> ShieldResponse:
        """GET ``url`` through the shield."""
        return self.send("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> ShieldResponse:
        """POST to ``url`` through the shield."""
        return self.send("POST", url, **kwargs)

    def get_json(self, url: str, *, contract: SuccessContract | None = None) -> Any:
        """GET ``url`` and decode the JSON body, enforcing the success contract.

        The contract argument overrides any contract set on the client, so a
        Binance-style body-level error is caught even though the status is 200.
        """
        response = self.get(url)
        payload = response.json()
        active = contract if contract is not None else self.success_contract
        if active is not None:
            active.check(payload, url=url, body=response.text)
        return payload

    def post_json(
        self,
        url: str,
        payload: Any,
        *,
        contract: SuccessContract | None = None,
    ) -> Any:
        """POST ``payload`` as JSON and decode the response body."""
        response = self.post(url, json_body=payload)
        decoded = response.json()
        active = contract if contract is not None else self.success_contract
        if active is not None:
            active.check(decoded, url=url, body=response.text)
        return decoded
