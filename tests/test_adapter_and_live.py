"""Tests for the optional ``requests`` adapter and the live integration test.

The adapter tests need ``requests``; they skip cleanly if it is absent, so the
suite stays green on a minimal install. The live test is marked ``live`` and is
deselected by default.
"""

from __future__ import annotations

from typing import Any

import pytest

from dns_shield import patch
from dns_shield.patch import RequestsShieldAdapter, requests_available
from dns_shield.transport import ShieldResponse

requests = pytest.importorskip("requests", reason="optional dependency")

REAL = "108.138.141.52"


class TestRequestsAvailability:
    def test_requests_available_reports_true_when_installed(self) -> None:
        assert requests_available() is True

    def test_import_requests_returns_the_module(self) -> None:
        assert patch._import_requests() is requests  # noqa: SLF001


class TestRequestsShieldAdapter:
    def test_adapter_construction_mounts_a_session(self) -> None:
        adapter = RequestsShieldAdapter("https://fapi.binance.com/")
        assert adapter.prefix == "https://fapi.binance.com/"
        assert isinstance(adapter.session, requests.Session)

    def test_mount_into_target_session_is_prefix_scoped(self) -> None:
        """Only the mounted prefix may be affected -- nothing global."""
        session = requests.Session()
        adapter = RequestsShieldAdapter("https://shielded.example/")
        adapter.mount_into(session)
        assert "https://shielded.example/" in session.adapters
        # The default adapters are untouched.
        assert "https://" in session.adapters

    def test_adapted_request_routes_through_the_shield(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The adapter must call the shield client, not urllib3 directly."""
        calls: list[tuple[str, str]] = []

        class FakeClient:
            def send(self, method: str, url: str, **kwargs: Any) -> ShieldResponse:
                calls.append((method, url))
                return ShieldResponse(200, {}, '{"ok":true}', url, REAL)

        adapter = RequestsShieldAdapter("https://h.example/")
        adapter._client = FakeClient()  # type: ignore[assignment]  # noqa: SLF001
        session = adapter.mount_into(requests.Session())

        response = session.get("https://h.example/api")
        assert calls == [("GET", "https://h.example/api")]
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_adapted_response_exposes_the_dialled_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A caller must be able to see which address actually served them."""
        class FakeClient:
            def send(self, method: str, url: str, **kwargs: Any) -> ShieldResponse:
                return ShieldResponse(200, {}, "{}", url, REAL)

        adapter = RequestsShieldAdapter("https://h.example/")
        adapter._client = FakeClient()  # type: ignore[assignment]  # noqa: SLF001
        session = adapter.mount_into(requests.Session())
        response = session.get("https://h.example/")
        assert response.headers["X-DNS-Shield-Address"] == REAL

    def test_unmounted_prefix_is_unaffected(self) -> None:
        """A URL outside the mount must not go through the shield."""
        adapter = RequestsShieldAdapter("https://shielded.example/")
        session = adapter.mount_into(requests.Session())
        adapter_for_prefix = session.get_adapter("https://other.example/")
        assert adapter_for_prefix is not session.get_adapter("https://shielded.example/")

    def test_error_status_is_returned_not_raised(self) -> None:
        """The adapter must not raise on 4xx; requests semantics return it."""
        class FakeClient:
            def send(self, method: str, url: str, **kwargs: Any) -> ShieldResponse:
                return ShieldResponse(451, {}, "blocked", url, REAL)

        adapter = RequestsShieldAdapter("https://h.example/")
        adapter._client = FakeClient()  # type: ignore[assignment]  # noqa: SLF001
        session = adapter.mount_into(requests.Session())
        response = session.get("https://h.example/")
        assert response.status_code == 451
        assert response.text == "blocked"


class TestAdapterDoesNotDisableVerification:
    def test_no_verify_false_is_passed_by_the_adapter(self) -> None:
        """A regression guard: the shield needs no verification bypass."""
        import inspect

        source = inspect.getsource(patch)
        assert "verify=False" not in source.replace("``verify=False``", "")

    def test_adapter_send_does_not_accept_a_verify_override(self) -> None:
        import inspect

        adapter_cls = RequestsShieldAdapter("https://h.example/").__class__
        source = inspect.getsource(adapter_cls)
        assert "verify" not in source


# -- live integration (opt-in) --------------------------------------------


@pytest.mark.live
class TestLiveIntegration:
    """Real-network checks. Deselected unless ``-m live`` is passed.

    These are deliberately few and slow-tolerant: they exist to catch the case
    where every mocked test passes but the real world has moved on.
    """

    def test_known_good_public_host_resolves_and_connects(self) -> None:
        """example.com is stable, has no CDN trickery, and is never poisoned."""
        from dns_shield.resolve import DohResolver
        from dns_shield.transport import SniHTTPClient

        resolver = DohResolver("cloudflare")
        ips = resolver.query("example.com")
        assert ips, "DoH returned no addresses for example.com"

        client = SniHTTPClient(resolver=resolver)
        response = client.get("https://example.com/", raise_for_status=False)
        assert response.status == 200
        assert response.address in ips
        assert "example" in response.text.lower()

    def test_all_providers_answer_consistently(self) -> None:
        """Independent resolvers should agree on a stable public host."""
        from dns_shield.resolve import DohResolver

        answers = {}
        for provider in ("cloudflare", "google", "quad9"):
            try:
                answers[provider] = set(DohResolver(provider).query("example.com"))
            except Exception as exc:  # noqa: BLE001 - a provider may be blocked locally
                pytest.skip(f"{provider} unreachable from this network: {exc}")
        assert len(answers) >= 2
        overlapping = set.intersection(*answers.values())
        assert overlapping, f"providers disagree entirely: {answers}"

    def test_diagnose_reports_a_healthy_verdict_for_a_good_host(self) -> None:
        from dns_shield.detect import Verdict, diagnose

        result = diagnose("example.com", timeout_s=5.0)
        assert result.verdict is Verdict.HEALTHY
