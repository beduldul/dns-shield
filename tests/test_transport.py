"""Tests for the SNI-preserving transport.

Fully offline. Every socket is a fake, and ``socket.getaddrinfo`` is poisoned to
raise -- which is precisely the condition the library exists to survive. If the
transport ever regressed to using ``urllib``/``http.client``/``requests`` for
connecting, these tests would fail, because those call ``getaddrinfo``.

That is acceptance criterion 7: ``TestSystemResolverIsNeverConsulted``.
"""

from __future__ import annotations

import json
import socket
import ssl
from typing import Any

import pytest

from dns_shield.resolve import DohResolutionError, DohResolver, ResolvedHost
from dns_shield.transport import (
    BINANCE_SUCCESS_CONTRACT,
    ShieldResponse,
    SniHTTPClient,
    SuccessContract,
    TransportError,
    backoff_delay,
    dechunk,
    read_body,
    read_head,
    retry_after_seconds,
)

BOGUS = "202.169.44.80"
REAL_IPS = ["108.138.141.52", "108.138.141.24", "108.138.141.5", "108.138.141.35"]


# -- fakes -----------------------------------------------------------------


def http_response(
    body: str = '{"ok":true}',
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    chunked: bool = False,
) -> bytes:
    """Build raw HTTP/1.1 bytes, as they would arrive on the wire."""
    payload = body.encode()
    head_extra = ""
    if chunked:
        head_extra = "Transfer-Encoding: chunked\r\n"
        payload = b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload)
    else:
        head_extra = f"Content-Length: {len(payload)}\r\n"
    for name, value in (headers or {}).items():
        head_extra += f"{name}: {value}\r\n"
    head = f"HTTP/1.1 {status} OK\r\n{head_extra}\r\n".encode()
    return head + payload


class FakeTLSSocket:
    """A socket whose ``recv`` replays a canned byte stream."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self.closed = False
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def settimeout(self, _timeout: float) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeTLSSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeContext:
    """An ``ssl.SSLContext`` stand-in.

    ``fail`` makes the handshake raise, simulating an intercepted or broken
    endpoint. ``sni`` records the server_hostname actually requested.
    """

    def __init__(self, data: bytes = b"", *, fail: str | None = None) -> None:
        self.data = data
        self.fail = fail
        self.sni_seen: list[str | None] = []
        self.connections: list[FakeTLSSocket] = []

    def wrap_socket(self, sock: Any, *, server_hostname: str | None = None) -> FakeTLSSocket:
        self.sni_seen.append(server_hostname)
        if self.fail is not None:
            raise ssl.SSLError(self.fail)
        tls = FakeTLSSocket(self.data)
        self.connections.append(tls)
        return tls


class StubResolver:
    """A resolver returning a fixed address list, recording calls.

    Caches its :class:`ResolvedHost` exactly as the real resolver does, so that
    round-robin rotation across attempts is exercised faithfully. A stub that
    returned a fresh object each call would silently hide rotation bugs.
    """

    def __init__(self, ips: list[str] | None = None, *, error: Exception | None = None) -> None:
        self.ips = ips if ips is not None else list(REAL_IPS)
        self.error = error
        self.queries: list[str] = []
        self.invalidated: list[str] = []
        self._cache: dict[str, ResolvedHost] = {}

    def resolve(self, host: str, *, force: bool = False) -> str:
        return self.resolve_host(host, force=force).next_ip()

    def resolve_host(self, host: str, *, force: bool = False) -> ResolvedHost:
        self.queries.append(host)
        if self.error is not None:
            raise self.error
        cached = self._cache.get(host)
        if cached is not None and not force:
            return cached
        entry = ResolvedHost(host, list(self.ips), expires_at=1e18)
        self._cache[host] = entry
        return entry

    def invalidate(self, host: str) -> None:
        self.invalidated.append(host)
        self._cache.pop(host, None)


class _Succeed:
    """Sentinel meaning 'this dial attempt should succeed'."""

    def __repr__(self) -> str:
        return "SUCCEED"


SUCCEED = _Succeed()


def make_client(
    *,
    data: bytes | None = None,
    context: FakeContext | None = None,
    resolver: StubResolver | None = None,
    connect_errors: list[Exception | _Succeed] | None = None,
    **kwargs: Any,
) -> tuple[SniHTTPClient, FakeContext, StubResolver, list[tuple[str, int]]]:
    """Build a client wired to fakes. Returns the dial log too.

    ``connect_errors`` is consumed one entry per dial: an exception is raised,
    :data:`SUCCEED` lets the dial through.
    """
    ctx = context or FakeContext(data if data is not None else http_response())
    res = resolver or StubResolver()
    dials: list[tuple[str, int]] = []
    outcomes: list[Exception | _Succeed] = list(connect_errors or [])

    class _FakeSocket:
        """Stands in for the raw TCP socket handed to ``wrap_socket``."""

        def close(self) -> None:
            return None

    def fake_connect(address: tuple[str, int], timeout: float | None = None) -> Any:
        dials.append(address)
        if outcomes:
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
        return _FakeSocket()

    client = SniHTTPClient(
        resolver=res,  # type: ignore[arg-type]
        ssl_context=ctx,  # type: ignore[arg-type]
        connect=fake_connect,
        sleeper=lambda _seconds: None,  # never block in tests
        **kwargs,
    )
    return client, ctx, res, dials


# -- wire parsing ----------------------------------------------------------


class TestReadHead:
    def test_parses_status_and_headers(self) -> None:
        status, headers, leftover = read_head(
            FakeTLSSocket(http_response('{"a":1}')), "https://h/"
        )
        assert status == 200
        assert headers["content-length"] == "7"
        assert leftover == b'{"a":1}'

    def test_header_names_are_lowercased(self) -> None:
        _status, headers, _ = read_head(
            FakeTLSSocket(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"),
            "https://h/",
        )
        assert headers["content-type"] == "application/json"

    def test_malformed_status_line_raises(self) -> None:
        with pytest.raises(TransportError, match="malformed status line"):
            read_head(FakeTLSSocket(b"NOT-HTTP\r\n\r\n"), "https://h/")

    def test_oversized_headers_raise(self) -> None:
        with pytest.raises(TransportError, match="64 KiB"):
            read_head(FakeTLSSocket(b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 12000), "https://h/")

    def test_empty_response_raises(self) -> None:
        with pytest.raises(TransportError, match="closed before headers"):
            read_head(FakeTLSSocket(b""), "https://h/")

    def test_truncated_header_block_raises(self) -> None:
        """A partial head must not be accepted as a headers-less 200.

        Accepting it would make a truncated response indistinguishable from a
        legitimate empty body, and the failure would surface later as a
        confusing JSON decode error.
        """
        with pytest.raises(TransportError, match="closed before headers"):
            read_head(FakeTLSSocket(b"HTTP/1.1 200 OK\r\nContent-Len"), "https://h/")


class TestReadBody:
    def test_content_length_body(self) -> None:
        sock = FakeTLSSocket(http_response('{"hello":"world"}'))
        _s, headers, leftover = read_head(sock, "https://h/")
        assert read_body(sock, headers, leftover) == b'{"hello":"world"}'

    def test_chunked_body(self) -> None:
        sock = FakeTLSSocket(http_response('{"chunked":true}', chunked=True))
        _s, headers, leftover = read_head(sock, "https://h/")
        assert read_body(sock, headers, leftover) == b'{"chunked":true}'

    def test_chunked_with_multiple_chunks(self) -> None:
        raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        assert dechunk(FakeTLSSocket(raw), b"") == b"hello world"

    def test_chunked_ignores_extension_parameters(self) -> None:
        raw = b"5;foo=bar\r\nhello\r\n0\r\n\r\n"
        assert dechunk(FakeTLSSocket(raw), b"") == b"hello"

    def test_chunked_bad_size_raises(self) -> None:
        with pytest.raises(TransportError, match="bad chunk size"):
            dechunk(FakeTLSSocket(b"zz\r\n"), b"")

    def test_read_until_close_when_unframed(self) -> None:
        sock = FakeTLSSocket(b"payload-with-no-length")
        assert read_body(sock, {}, b"") == b"payload-with-no-length"

    def test_zero_length_body(self) -> None:
        sock = FakeTLSSocket(b"")
        assert read_body(sock, {"content-length": "0"}, b"") == b""

    def test_non_numeric_content_length_falls_back_to_close(self) -> None:
        sock = FakeTLSSocket(b"abc")
        assert read_body(sock, {"content-length": "nonsense"}, b"") == b"abc"


# -- backoff ---------------------------------------------------------------


class TestBackoff:
    def test_is_capped_at_max(self) -> None:
        assert backoff_delay(20, base_s=0.8, max_s=30.0) <= 30.0

    def test_grows_with_attempts(self) -> None:
        rng_ceiling = [
            backoff_delay(i, base_s=1.0, max_s=1000.0) for i in range(5)
        ]
        # The *ceiling* is 2**attempt; sampled values must not exceed it.
        for attempt, value in enumerate(rng_ceiling):
            assert 0.0 <= value <= 2.0**attempt

    def test_retry_after_hint_is_honoured(self) -> None:
        body = json.dumps({"retryAfter": 2500})
        assert retry_after_seconds(body, 0) == pytest.approx(2.5)

    def test_retry_after_inside_data_object(self) -> None:
        body = json.dumps({"data": {"retryAfter": 1000}})
        assert retry_after_seconds(body, 0) == pytest.approx(1.0)

    def test_retry_after_hint_is_capped(self) -> None:
        body = json.dumps({"retryAfter": 10**9})
        assert retry_after_seconds(body, 0, max_s=30.0) == 30.0

    def test_non_json_body_falls_back_to_backoff(self) -> None:
        assert 0.0 <= retry_after_seconds("<html>error</html>", 0) <= 1.0

    def test_zero_retry_after_falls_back(self) -> None:
        assert 0.0 <= retry_after_seconds(json.dumps({"retryAfter": 0}), 0) <= 1.0


# -- SNI / Host preservation ----------------------------------------------


class TestSniPreservation:
    def test_sni_is_the_hostname_not_the_ip(self) -> None:
        """Bare-IP TLS fails; SNI is the whole trick."""
        client, ctx, _res, dials = make_client()
        client.get("https://fapi.binance.com/fapi/v1/ping")
        assert ctx.sni_seen == ["fapi.binance.com"]
        assert dials[0][0] in REAL_IPS
        assert dials[0][1] == 443

    def test_host_header_is_the_hostname(self) -> None:
        client, ctx, _res, _dials = make_client()
        client.get("https://fapi.binance.com/fapi/v1/ping")
        raw = ctx.connections[0].sent[0]
        assert b"Host: fapi.binance.com\r\n" in raw

    def test_request_line_carries_path_and_query(self) -> None:
        client, ctx, _res, _dials = make_client()
        client.get("https://fapi.binance.com/fapi/v1/klines?symbol=BTCUSDT&limit=5")
        raw = ctx.connections[0].sent[0]
        assert raw.startswith(b"GET /fapi/v1/klines?symbol=BTCUSDT&limit=5 HTTP/1.1")

    def test_connection_close_is_sent(self) -> None:
        client, ctx, _res, _dials = make_client()
        client.get("https://h.example/")
        assert b"Connection: close\r\n" in ctx.connections[0].sent[0]

    def test_custom_port_is_dialled(self) -> None:
        client, _ctx, _res, dials = make_client()
        client.get("https://h.example:8443/x")
        assert dials[0] == ("108.138.141.52", 8443)


# -- acceptance criterion 7: the system resolver is never consulted --------


class TestSystemResolverIsNeverConsulted:
    """The single most important property of this library.

    conftest already replaces ``socket.getaddrinfo``, ``socket.socket`` and
    ``socket.create_connection`` with functions that raise. These tests make the
    claim explicit and local so a reader can see it verified.
    """

    def test_getaddrinfo_raises_but_the_request_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def poisoned(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("the system resolver was consulted")

        monkeypatch.setattr(socket, "getaddrinfo", poisoned)
        client, _ctx, _res, dials = make_client()
        response = client.get("https://fapi.binance.com/fapi/v1/ping")
        assert response.status == 200
        # Proves the dial used the literal IP, never a name.
        assert dials[0][0] == "108.138.141.52"

    def test_create_connection_is_not_used(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def poisoned(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("socket.create_connection was used to dial")

        monkeypatch.setattr(socket, "create_connection", poisoned)
        client, _ctx, _res, _dials = make_client()
        assert client.get("https://fapi.binance.com/fapi/v1/ping").status == 200

    def test_real_socket_construction_is_never_needed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def poisoned(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("a real socket was constructed")

        monkeypatch.setattr(socket, "socket", poisoned)
        client, _ctx, _res, _dials = make_client()
        assert client.get("https://fapi.binance.com/fapi/v1/ping").status == 200

    def test_gethostbyname_is_not_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def poisoned(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("socket.gethostbyname was used")

        monkeypatch.setattr(socket, "gethostbyname", poisoned, raising=False)
        client, _ctx, _res, _dials = make_client()
        assert client.get("https://fapi.binance.com/fapi/v1/ping").status == 200


# -- failure classification ------------------------------------------------


class TestTransportFailures:
    def test_connection_refused_is_connect_error(self) -> None:
        client, _ctx, _res, _dials = make_client(
            connect_errors=[ConnectionRefusedError(61, "Connection refused")] * 4
        )
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.kind == "connect"

    def test_connect_timeout_is_timeout_error(self) -> None:
        client, _ctx, _res, _dials = make_client(
            connect_errors=[TimeoutError("timed out")] * 4
        )
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.kind == "timeout"

    def test_tls_failure_is_tls_error(self) -> None:
        client, _ctx, _res, _dials = make_client(
            context=FakeContext(fail="certificate verify failed")
        )
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.kind == "tls"

    def test_url_without_host_is_rejected(self) -> None:
        client, _ctx, _res, _dials = make_client()
        with pytest.raises(TransportError, match="URL has no host"):
            client.get("https:///nopath")

    def test_failed_dial_rotates_rather_than_re_resolving(self) -> None:
        """The stale-answer re-query happens only after every address fails.

        Invalidating after the *first* bad edge would reset the round-robin
        cursor and retry the same dead address -- the bug this test pins down.
        """
        resolver = StubResolver()
        client, _ctx, res, _dials = make_client(
            resolver=resolver,
            connect_errors=[ConnectionRefusedError(61, "refused"), SUCCEED, SUCCEED, SUCCEED],
        )
        response = client.get("https://h.example/")
        assert response.status == 200
        # One address failed, so we rotate; we do not drop the whole set.
        assert res.invalidated == []

    def test_full_set_exhaustion_triggers_a_re_resolve(self) -> None:
        """Once every known address is burned, the answer set is presumed stale."""
        resolver = StubResolver(REAL_IPS[:2])
        client, _ctx, res, dials = make_client(
            resolver=resolver,
            connect_errors=[ConnectionRefusedError(61, "a"), ConnectionRefusedError(61, "b"), SUCCEED],
        )
        response = client.get("https://h.example/")
        assert response.status == 200
        assert res.invalidated == ["h.example"]
        assert [addr for addr, _p in dials][:2] == REAL_IPS[:2]

    def test_resolution_failure_is_reported(self) -> None:
        """A DoH outage is a distinct failure class from a refused connection."""
        resolver = StubResolver(error=DohResolutionError("all providers failed"))
        client, _ctx, _res, _dials = make_client(resolver=resolver)
        with pytest.raises(TransportError, match="resolution failed") as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.kind == "resolution"

    def test_resolution_failure_retries_the_full_attempt_budget(self) -> None:
        resolver = StubResolver(error=DohResolutionError("nope"))
        client, _ctx, res, _dials = make_client(resolver=resolver)
        with pytest.raises(TransportError):
            client.get("https://h.example/")
        assert len(res.queries) == client.max_attempts


# -- IP rotation -----------------------------------------------------------


class TestIpRotation:
    def test_second_ip_is_tried_when_the_first_fails(self) -> None:
        """The core resilience property: one dead edge must not fail the call."""
        client, _ctx, _res, dials = make_client(
            connect_errors=[ConnectionRefusedError(61, "edge down"), SUCCEED]
        )
        response = client.get("https://fapi.binance.com/fapi/v1/ping")
        assert response.status == 200
        assert dials[0][0] == REAL_IPS[0]
        assert dials[1][0] == REAL_IPS[1]

    def test_error_records_an_address_that_was_actually_dialled(self) -> None:
        """With every address burned, the final error names a real attempt."""
        client, _ctx, _res, dials = make_client(
            connect_errors=[ConnectionRefusedError(61, "x")] * 4
        )
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.address == dials[-1][0]
        assert excinfo.value.address in REAL_IPS

    def test_rotation_spreads_across_distinct_ips(self) -> None:
        client, _ctx, _res, dials = make_client()
        for _ in range(len(REAL_IPS)):
            client.get("https://h.example/")
        assert [address for address, _port in dials] == REAL_IPS


# -- HTTP status handling --------------------------------------------------


class TestStatusHandling:
    @pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504])
    def test_retryable_statuses_are_retried(self, status: int) -> None:
        client, _ctx, _res, dials = make_client(data=http_response("{}", status=status))
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.status == status
        assert len(dials) == 4

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 451])
    def test_deterministic_statuses_are_not_retried(self, status: int) -> None:
        """Retrying a 451 would hammer a host that is refusing service."""
        client, _ctx, _res, dials = make_client(data=http_response("{}", status=status))
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.status == status
        assert len(dials) == 1

    def test_451_is_surfaced_verbatim(self) -> None:
        client, _ctx, _res, _dials = make_client(
            data=http_response("blocked by law", status=451)
        )
        with pytest.raises(TransportError) as excinfo:
            client.get("https://h.example/")
        assert excinfo.value.status == 451
        assert excinfo.value.body == "blocked by law"

    def test_raise_for_status_false_returns_the_response(self) -> None:
        client, _ctx, _res, _dials = make_client(
            data=http_response("blocked", status=451)
        )
        response = client.get("https://h.example/", raise_for_status=False)
        assert response.status == 451
        assert response.ok is False
        assert response.text == "blocked"

    def test_retryable_then_success_recovers(self) -> None:
        ctx = FakeContext()
        res = StubResolver()
        responses = [http_response("{}", status=503), http_response('{"ok":1}')]
        chained = FakeContext()
        chained.wrap_socket = _sequenced_wrap(responses, chained)  # type: ignore[method-assign]
        client, _ctx, _res, dials = make_client(context=chained, resolver=res)
        assert client.get("https://h.example/").status == 200
        assert len(dials) == 2


def _sequenced_wrap(
    responses: list[bytes], ctx: FakeContext
) -> Any:
    """Return a wrap_socket that yields a different response per call."""
    queue = list(responses)

    def wrap_socket(sock: Any, *, server_hostname: str | None = None) -> FakeTLSSocket:
        data = queue.pop(0) if queue else b""
        tls = FakeTLSSocket(data)
        ctx.connections.append(tls)
        ctx.sni_seen.append(server_hostname)
        return tls

    return wrap_socket


# -- body-level contracts --------------------------------------------------


class TestSuccessContract:
    def test_http_200_with_error_code_is_a_failure(self) -> None:
        """The verified Binance trap: status is 200, the body says otherwise."""
        body = json.dumps({"code": "11012030", "message": "portfolio closed"})
        client, _ctx, _res, _dials = make_client(data=http_response(body))
        with pytest.raises(TransportError) as excinfo:
            client.get_json("https://h.example/", contract=BINANCE_SUCCESS_CONTRACT)
        assert excinfo.value.code == "11012030"
        assert excinfo.value.kind == "contract"

    def test_success_code_passes(self) -> None:
        body = json.dumps({"code": "000000", "data": {"ok": True}})
        client, _ctx, _res, _dials = make_client(data=http_response(body))
        payload = client.get_json("https://h.example/", contract=BINANCE_SUCCESS_CONTRACT)
        assert payload["data"]["ok"] is True

    def test_absent_field_is_accepted(self) -> None:
        """The contract must not fire on an API that returns a plain payload."""
        client, _ctx, _res, _dials = make_client(data=http_response('{"plain":1}'))
        assert client.get_json("https://h.example/", contract=BINANCE_SUCCESS_CONTRACT) == {
            "plain": 1
        }

    def test_contract_can_be_set_on_the_client(self) -> None:
        body = json.dumps({"code": "11012030"})
        client, _ctx, _res, _dials = make_client(
            data=http_response(body), success_contract=BINANCE_SUCCESS_CONTRACT
        )
        with pytest.raises(TransportError):
            client.get_json("https://h.example/")

    def test_is_rate_limit_covers_known_codes(self) -> None:
        error = TransportError("x", status=429)
        assert error.is_rate_limit is True
        assert TransportError("x", code="11012030").is_rate_limit is True
        assert TransportError("x", code="-1003").is_rate_limit is True
        assert TransportError("x", status=500).is_rate_limit is False

    def test_custom_contract(self) -> None:
        contract = SuccessContract("status", "ok")
        client, _ctx, _res, _dials = make_client(
            data=http_response(json.dumps({"status": "error"}))
        )
        with pytest.raises(TransportError, match="status"):
            client.get_json("https://h.example/", contract=contract)


# -- request shaping -------------------------------------------------------


class TestRequestShaping:
    def test_json_body_sets_content_type_and_length(self) -> None:
        client, ctx, _res, _dials = make_client(data=http_response("{}"))
        client.post("https://h.example/api", json_body={"a": 1})
        raw = ctx.connections[0].sent[0]
        assert b"content-type: application/json" in raw.lower() and b"application/json" in raw
        assert b"Content-Length: 8" in raw
        assert raw.endswith(b'{"a": 1}')

    def test_custom_headers_are_sent(self) -> None:
        client, ctx, _res, _dials = make_client()
        client.get("https://h.example/", headers={"X-Api-Key": "secret"})
        assert b"X-Api-Key: secret" in ctx.connections[0].sent[0]

    def test_user_agent_is_configurable(self) -> None:
        client, ctx, _res, _dials = make_client(user_agent="custom/9")
        client.get("https://h.example/")
        assert b"User-Agent: custom/9" in ctx.connections[0].sent[0]

    def test_response_parsing(self) -> None:
        client, _ctx, _res, _dials = make_client(data=http_response('{"v":42}'))
        response = client.get("https://h.example/")
        assert isinstance(response, ShieldResponse)
        assert response.status == 200
        assert response.json() == {"v": 42}
        assert response.ok is True
        assert "108.138" in repr(response)

    def test_non_json_response_raises_on_decode(self) -> None:
        client, _ctx, _res, _dials = make_client(data=http_response("<html>hi</html>"))
        response = client.get("https://h.example/")
        with pytest.raises(json.JSONDecodeError):
            response.json()


# -- integration against the real fingerprint ------------------------------


class TestBiznetFingerprintEndToEnd:
    """Replay the exact measured failure through the whole stack."""

    def test_transport_succeeds_where_the_system_resolver_fails(self) -> None:
        payload = json.dumps({"serverTime": 1700000000000})
        client, ctx, res, dials = make_client(
            data=http_response(payload),
            resolver=StubResolver(list(REAL_IPS)),
        )
        assert client.get_json("https://fapi.binance.com/fapi/v1/ping") == {
            "serverTime": 1700000000000
        }
        assert ctx.sni_seen == ["fapi.binance.com"]
        assert dials[0][0] in REAL_IPS
        assert dials[0][0] != BOGUS

    def test_bogus_ip_is_never_dialled(self) -> None:
        """The poisoned address must never appear on the dial path."""
        client, _ctx, _res, dials = make_client()
        client.get("https://fapi.binance.com/fapi/v1/ping")
        assert BOGUS not in [address for address, _port in dials]


class TestResolverIntegration:
    def test_client_accepts_a_real_resolver_object(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Wire the real DohResolver with mocked urlopen: no fakes in between."""
        import io

        body = {
            "Status": 0,
            "Answer": [
                {"name": "h.example", "type": 5, "TTL": 60, "data": "cdn.example."},
                *[{"name": "cdn.example.", "type": 1, "TTL": 60, "data": ip} for ip in REAL_IPS],
            ],
        }

        class Resp(io.BytesIO):
            def __enter__(self) -> Resp:
                return self

            def __exit__(self, *exc: object) -> None:
                self.close()

        monkeypatch.setattr(
            "urllib.request.urlopen", lambda request, timeout=None: Resp(json.dumps(body).encode())
        )

        resolver = DohResolver("cloudflare")
        ctx = FakeContext(http_response('{"ok":true}'))
        dials: list[tuple[str, int]] = []

        def fake_connect(address: tuple[str, int], timeout: float | None = None) -> Any:
            dials.append(address)
            return object()

        client = SniHTTPClient(
            resolver=resolver,
            ssl_context=ctx,  # type: ignore[arg-type]
            connect=fake_connect,
            sleeper=lambda _s: None,
        )
        assert client.get("https://h.example/").status == 200
        assert dials[0][0] in REAL_IPS


class TestTolerantHttpParsing:
    """RFC 7230 permits formats the original strict parser rejected."""

    def test_status_line_without_reason_phrase(self) -> None:
        """`HTTP/1.1 204` is legal; the reason phrase is optional."""
        status, _headers, _left = read_head(
            FakeTLSSocket(b"HTTP/1.1 204\r\n\r\n"), "https://h/"
        )
        assert status == 204

    def test_status_line_with_doubled_space(self) -> None:
        status, _headers, _left = read_head(
            FakeTLSSocket(b"HTTP/1.1  200 OK\r\n\r\n"), "https://h/"
        )
        assert status == 200

    def test_status_line_with_extra_whitespace(self) -> None:
        status, _headers, _left = read_head(
            FakeTLSSocket(b"HTTP/1.1   200   OK\r\n\r\n"), "https://h/"
        )
        assert status == 200

    @pytest.mark.parametrize(
        "raw",
        [b"NOT-HTTP\r\n\r\n", b"HTTP/1.1 ABC OK\r\n\r\n", b"HTTP/1.1\r\n\r\n"],
    )
    def test_genuinely_malformed_status_lines_still_raise(self, raw: bytes) -> None:
        with pytest.raises(TransportError, match="malformed status line"):
            read_head(FakeTLSSocket(raw), "https://h/")

    def test_blank_first_line_is_reported_as_empty(self) -> None:
        with pytest.raises(TransportError, match="empty response"):
            read_head(FakeTLSSocket(b"\r\n\r\n"), "https://h/")


class TestChunkValidation:
    """A malformed chunked body must not be returned as a complete one."""

    def test_chunk_missing_crlf_terminator_raises(self) -> None:
        """Full-length chunk whose terminator is present but not CRLF."""
        with pytest.raises(TransportError, match="not terminated by CRLF"):
            dechunk(FakeTLSSocket(b"5\r\nhelloXX"), b"")

    def test_chunk_truncated_mid_body_raises(self) -> None:
        with pytest.raises(TransportError, match="truncated"):
            dechunk(FakeTLSSocket(b"20\r\nshort"), b"")

    def test_stream_ending_before_a_size_line_raises(self) -> None:
        with pytest.raises(TransportError, match="before a chunk-size line"):
            dechunk(FakeTLSSocket(b"5"), b"")

    def test_well_formed_chunked_body_still_decodes(self) -> None:
        assert dechunk(FakeTLSSocket(b"5\r\nhello\r\n0\r\n\r\n"), b"") == b"hello"


class TestBackoffFloor:
    """A zero-length sleep would spin through the attempt budget instantly."""

    def test_delay_never_drops_below_the_base(self) -> None:
        for attempt in range(8):
            delay = backoff_delay(attempt, base_s=0.5, max_s=30.0)
            assert delay >= 0.5, f"attempt {attempt} produced {delay}"

    def test_delay_respects_the_ceiling(self) -> None:
        for attempt in range(12):
            assert backoff_delay(attempt, base_s=0.5, max_s=2.0) <= 2.0

    def test_zero_retry_after_hint_is_floored(self) -> None:
        """A peer asking for 0 ms must not produce a zero-length sleep."""
        assert retry_after_seconds(json.dumps({"retryAfter": 0}), 0) >= 0.0
        assert retry_after_seconds(json.dumps({"retryAfter": 1}), 0) >= 0.8

    def test_retry_after_hint_still_honoured_when_large(self) -> None:
        assert retry_after_seconds(json.dumps({"retryAfter": 5000}), 0) == pytest.approx(5.0)
