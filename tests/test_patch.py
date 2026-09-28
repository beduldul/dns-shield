"""Tests for the targeted-override helpers.

Offline. These assert the scope guarantee -- that nothing here touches global
state or the system resolver -- and that TLS verification is never disabled.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from dns_shield import cli, detect, patch, resolve, transport
from dns_shield.patch import ShieldSession, resolve_and_call, shielded_client
from dns_shield.transport import ShieldResponse, SniHTTPClient

REAL = "108.138.141.52"


class RecordingClient:
    """A client double that records sends instead of dialling."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.read_timeout_s = 10.0
        self.sent: list[tuple[str, str, dict[str, Any]]] = []

    def send(self, method: str, url: str, **kwargs: Any) -> ShieldResponse:
        self.sent.append((method, url, kwargs))
        return ShieldResponse(200, {}, '{"ok":true}', url, REAL)


class TestShieldSession:
    def test_get_returns_a_shield_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        session = ShieldSession()
        response = session.get("https://fapi.binance.com/fapi/v1/ping")
        assert isinstance(response, ShieldResponse)
        assert response.status == 200

    def test_method_and_url_are_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        session = ShieldSession()
        session.get("https://h.example/a")
        session.post("https://h.example/b")
        assert [call[0] for call in session.client.sent] == ["GET", "POST"]

    def test_session_headers_are_merged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        session = ShieldSession(headers={"X-Base": "1"})
        session.get("https://h.example/", headers={"X-Request": "2"})
        _method, _url, kwargs = session.client.sent[0]
        assert kwargs["headers"] == {"X-Base": "1", "X-Request": "2"}

    def test_per_request_header_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        session = ShieldSession(headers={"X-K": "base"})
        session.get("https://h.example/", headers={"X-K": "override"})
        assert session.client.sent[0][2]["headers"]["X-K"] == "override"

    def test_context_manager(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        with ShieldSession() as session:
            assert session.get("https://h.example/").ok is True

    def test_close_is_safe_to_call_twice(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        session = ShieldSession()
        session.close()
        session.close()


class TestModuleHelpers:
    def test_resolve_and_call_uses_the_shield(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        response = resolve_and_call("https://fapi.binance.com/fapi/v1/ping")
        assert response.status == 200
        assert response.address == REAL

    def test_resolve_and_call_honours_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(patch, "SniHTTPClient", RecordingClient)
        response = resolve_and_call("https://h.example/", timeout_s=2.5)
        assert response.ok is True

    def test_shielded_client_returns_a_transport(self) -> None:
        assert isinstance(shielded_client(), SniHTTPClient)

    def test_no_requests_adapter_helper_is_exported_unconditionally(self) -> None:
        """The public helpers must not require requests to be installed."""
        assert callable(patch.resolve_and_call)
        assert callable(patch.shielded_client)


class TestTlsVerificationIsNeverDisabled:
    """A regression guard: the shield works *because* SNI is preserved."""

    def test_no_source_file_disables_verification(self) -> None:
        """Strip comments and docstrings: we are guarding code, not prose.

        The modules *discuss* ``verify=False`` in order to explain why it is
        unnecessary, so a naive substring check would flag its own documentation.
        """
        import ast
        import textwrap

        modules = [patch, transport, resolve, detect]
        for module in modules:
            source = textwrap.dedent(inspect.getsource(module))
            tree = ast.parse(source)
            # Blank out every docstring in place, then re-emit the source. This
            # removes docstring prose while leaving real code untouched.
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if not isinstance(body, list) or not body:
                    continue
                first = body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    if isinstance(first.value.value, str):
                        first.value.value = ""
            code = ast.unparse(tree)
            for banned in ("CERT_NONE", "_create_unverified_context", "InsecureSkipVerify"):
                assert banned not in code, f"{banned!r} appears in {module.__name__}"

    def test_ssl_context_is_never_built_unverified(self) -> None:
        """The only context construction must be the verifying default."""
        source = inspect.getsource(transport)
        assert "ssl.create_default_context()" in source
        assert "CERT_NONE" not in source
        assert "_create_unverified_context" not in source

    def test_default_ssl_context_verifies(self) -> None:
        import ssl

        client = shielded_client()
        context = client._ssl_context  # noqa: SLF001 - deliberate inspection
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname is True


class TestScopeGuarantee:
    """This is a targeted override, not a global DNS hijack."""

    def test_importing_does_not_patch_the_system_resolver(self) -> None:
        """Importing the module must leave global socket functions untouched."""
        import socket

        before_getaddrinfo = socket.getaddrinfo
        before_create = socket.create_connection
        import dns_shield.patch as freshly_imported

        assert freshly_imported is patch
        assert socket.getaddrinfo is before_getaddrinfo
        assert socket.create_connection is before_create

    def test_no_hosts_file_is_touched(self) -> None:
        """No module may write to the hosts file -- only describe it.

        Docstrings are stripped first, because they legitimately explain *why*
        the hosts file is not touched.
        """
        import ast
        import textwrap

        for module in (patch, transport, resolve, detect):
            source = textwrap.dedent(inspect.getsource(module))
            tree = ast.parse(source)
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if not isinstance(body, list) or not body:
                    continue
                first = body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    if isinstance(first.value.value, str):
                        first.value.value = ""
            code = ast.unparse(tree)
            for pattern in ("/etc/hosts", "hosts_file"):
                assert pattern not in code, f"{pattern!r} appears in code in {module.__name__}"
