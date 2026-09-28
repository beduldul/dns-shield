"""Tests for the measurement primitives in :mod:`dns_shield.detect`.

These exercise ``system_resolve``, ``probe_connect``, ``probe_http`` and the
``diagnose`` orchestration with mocked sockets, so the measured fingerprint is
covered without touching the network.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

import pytest

from dns_shield import detect
from dns_shield.detect import (
    Evidence,
    FailureKind,
    ProbeResult,
    Verdict,
    diagnose,
    probe_connect,
    probe_http,
    system_resolve,
)
from dns_shield.resolve import DohResolutionError, RecordSet

BOGUS = "202.169.44.80"
REAL = "108.138.141.52"
CNAME = "d2ukl3c6tymv7q.cloudfront.net"


class FakeSocket:
    """A socket double whose ``connect`` either succeeds, refuses, or times out."""

    def __init__(
        self,
        *,
        behaviour: str = "ok",
        response: bytes = b"",
        cert: dict[str, object] | None = None,
    ) -> None:
        self.behaviour = behaviour
        self.response = response
        self.closed = False
        self.sent: list[bytes] = []
        self.connected_to: tuple[str, int] | None = None
        self.cert: dict[str, object] = cert if cert is not None else {}

    def settimeout(self, _timeout: float) -> None:
        return None

    def connect(self, address: tuple[str, int]) -> None:
        self.connected_to = address
        if self.behaviour == "refused":
            raise ConnectionRefusedError(61, "Connection refused")
        if self.behaviour == "timeout":
            raise TimeoutError("timed out")
        if self.behaviour == "oserror":
            raise OSError(51, "Network is unreachable")

    def recv(self, size: int) -> bytes:
        data, self.response = self.response[:size], self.response[size:]
        return data

    def getpeercert(self) -> dict[str, object]:
        """Return an empty cert dict, as a real socket does before a handshake."""
        return dict(self.cert)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeSSLContext:
    """Stand-in for ``ssl.SSLContext``."""

    def __init__(self, *, fail: str | None = None, response: bytes = b"") -> None:
        self.fail = fail
        self.response = response
        self.sni_seen: list[str | None] = []

    def wrap_socket(self, sock: FakeSocket, *, server_hostname: str | None = None) -> FakeSocket:
        self.sni_seen.append(server_hostname)
        if self.fail is not None:
            raise ssl.SSLError(self.fail)
        sock.response = self.response
        return sock


def install_socket(monkeypatch: pytest.MonkeyPatch, sock: FakeSocket) -> None:
    """Make ``socket.socket(...)`` return the given double.

    The conftest ``no_network`` fixture replaces ``socket.socket`` with a guard
    that raises; we overwrite that replacement here, which is the intended
    mechanism for injecting a fake.
    """
    monkeypatch.setattr(socket, "socket", lambda *a, **k: sock)


# -- system_resolve --------------------------------------------------------


class TestSystemResolve:
    def test_returns_deduplicated_addresses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **k: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("2.2.2.2", 443)),
            ],
        )
        assert system_resolve("h.example") == ("1.1.1.1", "2.2.2.2")

    def test_returns_empty_when_no_records(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
        assert system_resolve("h.example") == ()

    def test_propagates_resolver_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail(*a: Any, **k: Any) -> None:
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fail)
        with pytest.raises(OSError):
            system_resolve("nope.example")


# -- probe_connect ---------------------------------------------------------


class TestProbeConnect:
    def test_success_records_latency(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sock = FakeSocket(behaviour="ok")
        install_socket(monkeypatch, sock)
        result = probe_connect(REAL, 443, timeout_s=1.0)
        assert result.kind is FailureKind.SUCCESS
        assert result.connected is True
        assert result.latency_ms >= 0
        assert sock.connected_to == (REAL, 443)

    def test_refused_is_classified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket(behaviour="refused"))
        result = probe_connect(BOGUS)
        assert result.kind is FailureKind.REFUSED
        assert result.connected is False

    def test_timeout_is_classified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket(behaviour="timeout"))
        result = probe_connect(BOGUS)
        assert result.kind is FailureKind.TIMEOUT

    def test_generic_oserror_is_classified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket(behaviour="oserror"))
        result = probe_connect(BOGUS)
        assert result.kind is FailureKind.OTHER_ERROR

    def test_socket_is_always_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sock = FakeSocket(behaviour="refused")
        install_socket(monkeypatch, sock)
        probe_connect(BOGUS)
        assert sock.closed is True


# -- probe_http ------------------------------------------------------------


def http_response(
    *,
    status: int = 200,
    reason: str = "OK",
    body: bytes = b"",
    content_length: bool = True,
) -> bytes:
    """Build a raw HTTP/1.1 response."""
    extra = f"Content-Length: {len(body)}\r\n" if content_length else ""
    return f"HTTP/1.1 {status} {reason}\r\n{extra}\r\n".encode() + body


class TestProbeHttp:
    def test_successful_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket())
        ctx = FakeSSLContext(response=http_response(status=200))
        result = probe_http("fapi.binance.com", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.SUCCESS
        assert result.status == 200

    def test_sni_is_set_to_the_hostname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket())
        ctx = FakeSSLContext(response=http_response())
        probe_http("fapi.binance.com", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert ctx.sni_seen == ["fapi.binance.com"]

    def test_request_uses_head_and_host_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sock = FakeSocket()
        install_socket(monkeypatch, sock)
        ctx = FakeSSLContext(response=http_response())
        probe_http("fapi.binance.com", REAL, path="/health", ssl_context=ctx)  # type: ignore[arg-type]
        request = sock.sent[0]
        assert request.startswith(b"GET /health HTTP/1.1")
        assert b"Host: fapi.binance.com\r\n" in request

    @pytest.mark.parametrize("status", [451, 403, 404, 500])
    def test_http_error_status_is_captured(
        self, monkeypatch: pytest.MonkeyPatch, status: int
    ) -> None:
        """A 451 is a real answer and must be reported as such."""
        install_socket(monkeypatch, FakeSocket())
        ctx = FakeSSLContext(response=http_response(status=status))
        result = probe_http("h.example", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.HTTP_ERROR
        assert result.status == status
        assert result.connected is True
        assert result.works is False

    def test_tls_failure_is_classified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket())
        ctx = FakeSSLContext(fail="certificate verify failed")
        result = probe_http("h.example", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.TLS_FAILURE

    def test_connect_refused_before_tls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket(behaviour="refused"))
        ctx = FakeSSLContext()
        result = probe_http("h.example", BOGUS, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.REFUSED
        assert ctx.sni_seen == []

    def test_connect_timeout_before_tls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket(behaviour="timeout"))
        ctx = FakeSSLContext()
        result = probe_http("h.example", BOGUS, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.TIMEOUT

    def test_connect_oserror(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket(behaviour="oserror"))
        ctx = FakeSSLContext()
        result = probe_http("h.example", BOGUS, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.OTHER_ERROR

    def test_empty_response_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket())
        ctx = FakeSSLContext(response=b"")
        result = probe_http("h.example", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.OTHER_ERROR
        assert "closed without a response" in result.detail

    def test_unparsable_status_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_socket(monkeypatch, FakeSocket())
        ctx = FakeSSLContext(response=b"GARBAGE\r\n\r\n")
        result = probe_http("h.example", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.OTHER_ERROR

    def test_timeout_after_tls_handshake(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sock = FakeSocket()

        def recv(_size: int) -> bytes:
            raise TimeoutError("no response")

        sock.recv = recv  # type: ignore[method-assign]
        install_socket(monkeypatch, sock)
        ctx = FakeSSLContext(response=http_response())
        result = probe_http("h.example", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.TIMEOUT
        assert "after TLS handshake" in result.detail

    def test_error_after_tls_is_classified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sock = FakeSocket()

        def recv(_size: int) -> bytes:
            raise OSError(54, "Connection reset by peer")

        sock.recv = recv  # type: ignore[method-assign]
        install_socket(monkeypatch, sock)
        ctx = FakeSSLContext()
        result = probe_http("h.example", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.kind is FailureKind.OTHER_ERROR


# -- diagnose orchestration ------------------------------------------------


class StubResolver:
    """A resolver double returning a fixed answer set."""

    def __init__(self, records: RecordSet | Exception) -> None:
        self.records = records
        self.queried: list[str] = []

    def query_records(self, host: str, record_type: str = "A") -> RecordSet:
        self.queried.append(host)
        if isinstance(self.records, Exception):
            raise self.records
        return self.records


class TestDiagnoseOrchestration:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, *, system: tuple[str, ...]) -> None:
        monkeypatch.setattr(detect, "system_resolve", lambda host, port=443: system)

    def test_poisoned_end_to_end(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The full measured fingerprint, driven through diagnose()."""
        self._patch(monkeypatch, system=(BOGUS,))

        def fake_probe_http(
            host: str, address: str, **kwargs: Any
        ) -> ProbeResult:
            if address == BOGUS:
                return ProbeResult(BOGUS, FailureKind.REFUSED, 11.0)
            return ProbeResult(REAL, FailureKind.SUCCESS, 140.0, status=200)

        monkeypatch.setattr(detect, "probe_http", fake_probe_http)
        resolver = StubResolver(
            RecordSet("fapi.binance.com", (REAL,), (CNAME,), 57.0, "cloudflare")
        )
        result = diagnose("fapi.binance.com", resolver=resolver)  # type: ignore[arg-type]
        assert result.verdict is Verdict.POISONED
        assert result.evidence.cnames == (CNAME,)
        assert result.evidence.doh_provider == "cloudflare"

    def test_healthy_when_both_agree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, system=(REAL,))
        monkeypatch.setattr(
            detect, "probe_http",
            lambda host, address, **k: ProbeResult(address, FailureKind.SUCCESS, 40.0, status=200),
        )
        resolver = StubResolver(RecordSet("h", (REAL,), (), 60.0, "cloudflare"))
        result = diagnose("h", resolver=resolver)  # type: ignore[arg-type]
        assert result.verdict is Verdict.HEALTHY

    def test_system_resolver_error_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail(host: str, port: int = 443) -> tuple[str, ...]:
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(detect, "system_resolve", fail)
        monkeypatch.setattr(
            detect, "probe_http",
            lambda host, address, **k: ProbeResult(address, FailureKind.SUCCESS, 40.0, status=200),
        )
        resolver = StubResolver(RecordSet("h", (REAL,), (), 60.0, "cloudflare"))
        result = diagnose("h", resolver=resolver)  # type: ignore[arg-type]
        assert "gaierror" in result.evidence.system_error
        assert any("system resolver error" in n for n in result.evidence.notes)

    def test_doh_error_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, system=(BOGUS,))
        monkeypatch.setattr(
            detect, "probe_http",
            lambda host, address, **k: ProbeResult(address, FailureKind.REFUSED, 10.0),
        )
        resolver = StubResolver(DohResolutionError("all providers failed"))
        result = diagnose("h", resolver=resolver)  # type: ignore[arg-type]
        assert result.verdict is Verdict.UNKNOWN
        assert "all providers failed" in result.evidence.doh_error
        assert any("DoH error" in n for n in result.evidence.notes)

    def test_shared_ip_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sibling hostnames on the same bogus address are surfaced."""
        by_host = {"a.example": (BOGUS,), "b.example": (BOGUS,), "c.example": ("9.9.9.9",)}
        monkeypatch.setattr(
            detect, "system_resolve", lambda host, port=443: by_host.get(host, ())
        )
        monkeypatch.setattr(
            detect, "probe_http",
            lambda host, address, **k: (
                ProbeResult(BOGUS, FailureKind.REFUSED, 10.0)
                if address == BOGUS
                else ProbeResult(REAL, FailureKind.SUCCESS, 100.0, status=200)
            ),
        )
        resolver = StubResolver(RecordSet("a.example", (REAL,), (), 60.0, "cloudflare"))
        result = diagnose(
            "a.example",
            resolver=resolver,  # type: ignore[arg-type]
            compare_hosts=["b.example", "c.example"],
        )
        assert result.evidence.shared_ip_hosts == ("b.example",)
        assert result.verdict is Verdict.POISONED

    def test_sibling_resolution_failure_is_tolerated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def resolve(host: str, port: int = 443) -> tuple[str, ...]:
            if host == "sibling.example":
                raise socket.gaierror("nope")
            return (BOGUS,)

        monkeypatch.setattr(detect, "system_resolve", resolve)
        monkeypatch.setattr(
            detect, "probe_http",
            lambda host, address, **k: ProbeResult(address, FailureKind.SUCCESS, 10.0, status=200),
        )
        resolver = StubResolver(RecordSet("h", (BOGUS,), (), 60.0, "cloudflare"))
        result = diagnose("h", resolver=resolver, compare_hosts=["sibling.example"])  # type: ignore[arg-type]
        assert result.evidence.shared_ip_hosts == ()

    def test_connect_only_skips_the_http_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, system=(BOGUS,))
        called: list[str] = []

        def fake_connect(address: str, port: int = 443, **k: Any) -> ProbeResult:
            called.append(address)
            return ProbeResult(address, FailureKind.REFUSED, 11.0)

        monkeypatch.setattr(detect, "probe_connect", fake_connect)
        resolver = StubResolver(RecordSet("h", (REAL,), (), 60.0, "cloudflare"))
        diagnose("h", resolver=resolver, do_http_probe=False)  # type: ignore[arg-type]
        assert BOGUS in called and REAL in called

    def test_custom_port_and_path_are_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, system=(REAL,))
        seen: list[dict[str, Any]] = []

        def fake_probe_http(host: str, address: str, **kwargs: Any) -> ProbeResult:
            seen.append(kwargs)
            return ProbeResult(address, FailureKind.SUCCESS, 10.0, status=200)

        monkeypatch.setattr(detect, "probe_http", fake_probe_http)
        resolver = StubResolver(RecordSet("h", (REAL,), (), 60.0, "cloudflare"))
        diagnose("h", resolver=resolver, port=8443, path="/health")  # type: ignore[arg-type]
        assert seen[0]["port"] == 8443
        assert seen[0]["path"] == "/health"

    def test_no_system_ips_still_diagnoses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A host the system resolver cannot resolve at all must not crash."""
        self._patch(monkeypatch, system=())
        monkeypatch.setattr(
            detect, "probe_http",
            lambda host, address, **k: ProbeResult(address, FailureKind.SUCCESS, 10.0, status=200),
        )
        resolver = StubResolver(RecordSet("h", (REAL,), (), 60.0, "cloudflare"))
        result = diagnose("h", resolver=resolver)  # type: ignore[arg-type]
        assert result.evidence.system_probe is None
        # Reachable, but the name does not resolve locally -- reported, not hidden.
        assert result.verdict is Verdict.UNREACHABLE


# -- certificate identity --------------------------------------------------


class TestCertificateParsing:
    """The peer certificate is the strongest evidence in the whole diagnosis."""

    def test_common_name_extracted_from_subject(self) -> None:
        from dns_shield.detect import _common_name

        subject = ((("commonName", "*.binance.com"),), (("organizationName", "X"),))
        assert _common_name(subject) == "*.binance.com"

    def test_common_name_found_after_other_attributes(self) -> None:
        from dns_shield.detect import _common_name

        subject = ((("countryName", "US"),), (("commonName", "example.com"),))
        assert _common_name(subject) == "example.com"

    @pytest.mark.parametrize("value", [None, "", (), "not-a-tuple", [("x",)], 42])
    def test_malformed_fields_return_empty(self, value: object) -> None:
        from dns_shield.detect import _common_name

        assert _common_name(value) == ""

    def test_subject_without_common_name_returns_empty(self) -> None:
        from dns_shield.detect import _common_name

        assert _common_name((("organizationName", "X"),)) == ""

    def test_peer_names_from_a_certificate(self) -> None:
        from dns_shield.detect import _peer_certificate_names

        class Tls:
            def getpeercert(self) -> dict[str, object]:
                return {
                    "subject": ((("commonName", "*.binance.com"),),),
                    "issuer": ((("commonName", "GeoTrust TLS RSA CA G1"),),),
                }

        assert _peer_certificate_names(Tls()) == (  # type: ignore[arg-type]
            "*.binance.com",
            "GeoTrust TLS RSA CA G1",
        )

    def test_empty_certificate_returns_empties(self) -> None:
        from dns_shield.detect import _peer_certificate_names

        class Tls:
            def getpeercert(self) -> dict[str, object]:
                return {}

        assert _peer_certificate_names(Tls()) == ("", "")  # type: ignore[arg-type]

    def test_getpeercert_failure_is_tolerated(self) -> None:
        """A probe must never fail because certificate inspection failed."""
        from dns_shield.detect import _peer_certificate_names

        class Tls:
            def getpeercert(self) -> dict[str, object]:
                raise ValueError("no certificate")

        assert _peer_certificate_names(Tls()) == ("", "")  # type: ignore[arg-type]

    def test_probe_records_the_certificate_subject(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The measured Binance case: the real IP serves *.binance.com."""
        sock = FakeSocket(
            cert={
                "subject": ((("commonName", "*.binance.com"),),),
                "issuer": ((("commonName", "GeoTrust TLS RSA CA G1"),),),
            }
        )
        install_socket(monkeypatch, sock)
        ctx = FakeSSLContext(response=http_response(status=200))
        result = probe_http("fapi.binance.com", REAL, ssl_context=ctx)  # type: ignore[arg-type]
        assert result.cert_subject == "*.binance.com"
        assert result.cert_issuer == "GeoTrust TLS RSA CA G1"
        assert result.cert_valid is True
        assert "*.binance.com" in result.describe()

    def test_certificate_verification_failure_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_socket(monkeypatch, FakeSocket())

        class BadCert:
            def wrap_socket(self, sock: object, *, server_hostname: str | None = None) -> None:
                raise ssl.SSLCertVerificationError("hostname mismatch")

        result = probe_http(
            "fapi.binance.com", BOGUS, ssl_context=BadCert()  # type: ignore[arg-type]
        )
        assert result.kind is FailureKind.TLS_FAILURE
        assert result.cert_valid is False

    def test_server_is_alive_is_distinct_from_works(self) -> None:
        assert ProbeResult("a", FailureKind.SUCCESS, 1.0, status=200).server_is_alive is True
        assert ProbeResult("a", FailureKind.HTTP_ERROR, 1.0, status=403).server_is_alive is True
        assert ProbeResult("a", FailureKind.HTTP_ERROR, 1.0, status=500).server_is_alive is True
        assert ProbeResult("a", FailureKind.REFUSED, 1.0).server_is_alive is False
        assert ProbeResult("a", FailureKind.TIMEOUT, 1.0).server_is_alive is False
        assert ProbeResult("a", FailureKind.TLS_FAILURE, 1.0).server_is_alive is False
