"""Tests for the DoH resolver. Fully offline: ``urlopen`` is mocked."""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from dns_shield.resolve import (
    PROVIDERS,
    DohProvider,
    DohResolutionError,
    DohResolver,
    ResolvedHost,
    _build_record_set,
    looks_like_ipv4,
    looks_like_ipv6,
)

BOGUS = "202.169.44.80"
REAL_IPS = ["108.138.141.52", "108.138.141.24", "108.138.141.5", "108.138.141.35"]
CNAME = "d2ukl3c6tymv7q.cloudfront.net"


def doh_payload(addresses: list[str], *, cname: str | None = None, ttl: int = 57) -> dict[str, Any]:
    """Build a Cloudflare-shaped DoH JSON body."""
    answers: list[dict[str, Any]] = []
    if cname:
        answers.append({"name": "fapi.binance.com", "type": 5, "TTL": ttl, "data": cname + "."})
    target = cname + "." if cname else "fapi.binance.com"
    for address in addresses:
        answers.append({"name": target, "type": 1, "TTL": ttl, "data": address})
    return {
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "Question": [{"name": "fapi.binance.com", "type": 1}],
        "Answer": answers,
    }


class FakeResponse(io.BytesIO):
    """Minimal stand-in for ``http.client.HTTPResponse``."""

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def install_urlopen(
    monkeypatch: pytest.MonkeyPatch,
    payloads: dict[str, Any] | list[Any],
) -> list[str]:
    """Patch ``urllib.request.urlopen`` and record the URLs it was asked for.

    ``payloads`` may be a dict keyed by provider name, or a list consumed in
    call order (to simulate failover).
    """
    calls: list[str] = []
    queue = list(payloads) if isinstance(payloads, list) else None
    by_host = payloads if isinstance(payloads, dict) else None

    def fake_urlopen(request: Any, timeout: float | None = None) -> FakeResponse:
        url = request.full_url if hasattr(request, "full_url") else str(request)
        calls.append(url)
        if queue is not None:
            item = queue.pop(0) if queue else {"Status": 3}
        else:
            assert by_host is not None
            item = {"Status": 3}
            for name, candidate in by_host.items():
                if name in url:
                    item = candidate
                    break
        if isinstance(item, Exception):
            raise item
        return FakeResponse(json.dumps(item).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


# -- provider plumbing -----------------------------------------------------


class TestProviders:
    def test_builtin_providers_present(self) -> None:
        assert set(PROVIDERS) >= {"cloudflare", "google", "quad9"}

    def test_named_provider_selects_endpoint(self) -> None:
        resolver = DohResolver("google")
        assert resolver.providers[0].json_endpoint == PROVIDERS["google"].json_endpoint

    def test_url_string_becomes_provider(self) -> None:
        resolver = DohResolver("https://dns.example/dns-query")
        assert resolver.providers[0].json_endpoint == "https://dns.example/dns-query"

    def test_custom_provider_object(self) -> None:
        custom = DohProvider("mine", "https://doh.mine/query")
        assert DohResolver(custom).providers == (custom,)

    def test_sequence_builds_failover_chain(self) -> None:
        resolver = DohResolver(["cloudflare", "google", "quad9"])
        assert [p.name for p in resolver.providers] == ["cloudflare", "google", "quad9"]

    def test_default_is_config_endpoint(self) -> None:
        assert DohResolver().providers[0].json_endpoint.startswith("https://")

    def test_unknown_provider_name_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown DoH provider"):
            DohResolver("not-a-provider")

    def test_empty_sequence_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            DohResolver([])

    def test_query_url_quotes_the_name(self) -> None:
        url = PROVIDERS["cloudflare"].query_url("fapi.binance.com", "A")
        assert url.endswith("?name=fapi.binance.com&type=A")


# -- address parsing -------------------------------------------------------


class TestAddressValidation:
    @pytest.mark.parametrize("value", ["1.2.3.4", "0.0.0.0", "255.255.255.255", "202.169.44.80"])
    def test_valid_ipv4(self, value: str) -> None:
        assert looks_like_ipv4(value) is True

    @pytest.mark.parametrize("value", ["256.1.1.1", "1.2.3", "not-an-ip", "", "1.2.3.4.5", "::1"])
    def test_invalid_ipv4(self, value: str) -> None:
        assert looks_like_ipv4(value) is False

    @pytest.mark.parametrize("value", ["::1", "2001:db8::1", "fe80::1"])
    def test_valid_ipv6(self, value: str) -> None:
        assert looks_like_ipv6(value) is True

    @pytest.mark.parametrize("value", ["1.2.3.4", "nope", ""])
    def test_invalid_ipv6(self, value: str) -> None:
        assert looks_like_ipv6(value) is False


class TestRecordSetBuilding:
    def test_extracts_addresses_and_cname_chain(self) -> None:
        records = _build_record_set(doh_payload(REAL_IPS, cname=CNAME), "fapi.binance.com", "A", "cf")
        assert records.addresses == tuple(REAL_IPS)
        assert records.cnames == (CNAME,)
        assert records.ttl_s == 57
        assert records.provider == "cf"

    def test_address_order_is_preserved(self) -> None:
        """Answer order is a real signal: CDNs return nearest edge first."""
        ordered = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        records = _build_record_set(
            {"Status": 0, "Answer": [{"type": 1, "TTL": 10, "data": a} for a in ordered]},
            "h", "A", "cf",
        )
        assert list(records.addresses) == ordered

    def test_missing_answer_section_is_empty_not_an_error(self) -> None:
        records = _build_record_set({"Status": 0}, "h", "A", "cf")
        assert records.is_empty
        assert records.addresses == ()

    def test_malformed_entries_are_skipped(self) -> None:
        payload = {
            "Status": 0,
            "Answer": [
                "not-a-dict",
                {"type": 1, "TTL": 5},  # no data
                {"type": 1, "TTL": 5, "data": "garbage"},
                {"type": 1, "TTL": 5, "data": "9.9.9.9"},
            ],
        }
        records = _build_record_set(payload, "h", "A", "cf")
        assert records.addresses == ("9.9.9.9",)

    def test_aaaa_requests_filter_to_ipv6(self) -> None:
        payload = {
            "Status": 0,
            "Answer": [
                {"type": 28, "TTL": 5, "data": "2001:db8::1"},
                {"type": 1, "TTL": 5, "data": "9.9.9.9"},
            ],
        }
        records = _build_record_set(payload, "h", "AAAA", "cf")
        assert records.addresses == ("2001:db8::1",)

    def test_type_a_ignores_aaaa_answers(self) -> None:
        payload = {
            "Status": 0,
            "Answer": [
                {"type": 28, "TTL": 5, "data": "2001:db8::1"},
                {"type": 1, "TTL": 5, "data": "9.9.9.9"},
            ],
        }
        assert _build_record_set(payload, "h", "A", "cf").addresses == ("9.9.9.9",)

    def test_ttl_zero_is_reported_as_zero(self) -> None:
        records = _build_record_set(
            {"Status": 0, "Answer": [{"type": 1, "TTL": 0, "data": "9.9.9.9"}]}, "h", "A", "cf"
        )
        assert records.ttl_s == 0.0


# -- resolution ------------------------------------------------------------


class TestResolveQuery:
    def test_query_returns_addresses_in_answer_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS, cname=CNAME)})
        assert DohResolver("cloudflare").query("fapi.binance.com") == REAL_IPS

    def test_query_sends_accept_header_and_user_agent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, str] = {}

        def capture(request: Any, timeout: float | None = None) -> FakeResponse:
            seen.update({k.lower(): v for k, v in request.header_items()})
            return FakeResponse(json.dumps(doh_payload(REAL_IPS)).encode())

        monkeypatch.setattr("urllib.request.urlopen", capture)
        DohResolver("cloudflare").query("fapi.binance.com")
        assert seen["accept"] == "application/dns-json"
        assert "dns-shield" in seen["user-agent"]

    def test_nxdomain_status_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": {"Status": 3}})
        with pytest.raises(DohResolutionError, match="status 3"):
            DohResolver("cloudflare").query("nope.example")

    def test_servfail_status_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": {"Status": 2}})
        with pytest.raises(DohResolutionError):
            DohResolver("cloudflare").query("nope.example")

    def test_empty_answer_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": {"Status": 0, "Answer": []}})
        with pytest.raises(DohResolutionError):
            DohResolver("cloudflare").query("h")

    def test_network_error_is_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": urllib.error.URLError("unreachable")})
        with pytest.raises(DohResolutionError, match="query failed"):
            DohResolver("cloudflare").query("h")

    def test_non_object_payload_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": [1, 2, 3]})
        with pytest.raises(DohResolutionError, match="not an object"):
            DohResolver("cloudflare").query("h")


class TestFailover:
    def test_second_provider_used_when_first_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = install_urlopen(
            monkeypatch,
            [urllib.error.URLError("down"), doh_payload(REAL_IPS)],
        )
        records = DohResolver(["cloudflare", "google"]).query_records("h", "A")
        assert records.provider == "google"
        assert len(calls) == 2

    def test_second_provider_used_when_first_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_urlopen(monkeypatch, [{"Status": 0, "Answer": []}, doh_payload(REAL_IPS)])
        assert DohResolver(["cloudflare", "google"]).query("h") == REAL_IPS

    def test_all_providers_failing_lists_every_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_urlopen(
            monkeypatch,
            [urllib.error.URLError("a"), urllib.error.URLError("b")],
        )
        with pytest.raises(DohResolutionError) as excinfo:
            DohResolver(["cloudflare", "google"]).query("h")
        message = str(excinfo.value)
        assert "cloudflare" in message and "google" in message


class TestCache:
    def test_second_resolve_uses_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare")
        resolver.resolve("h")
        resolver.resolve("h")
        assert len(calls) == 1

    def test_cache_rotates_through_the_address_pool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Consecutive calls must hit different edge nodes."""
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare")
        seen = [resolver.resolve("h") for _ in range(len(REAL_IPS))]
        assert sorted(seen) == sorted(REAL_IPS)

    def test_rotation_wraps_around(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare")
        first = resolver.resolve("h")
        # Consume the remaining len-1 slots to come back to the start.
        for _ in range(len(REAL_IPS) - 1):
            resolver.resolve("h")
        assert resolver.resolve("h") == first

    def test_force_bypasses_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare")
        resolver.resolve("h")
        resolver.resolve("h", force=True)
        assert len(calls) == 2

    def test_invalidate_forces_requery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare")
        resolver.resolve("h")
        resolver.invalidate("h")
        resolver.resolve("h")
        assert len(calls) == 2

    def test_invalidate_unknown_host_is_a_noop(self) -> None:
        DohResolver("cloudflare").invalidate("never-seen")  # must not raise

    def test_expired_entry_is_requeried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS, ttl=1)})
        resolver = DohResolver("cloudflare", ttl_s=1.0)
        entry = resolver.resolve_host("h")
        # Force expiry without sleeping: rewind the deadline directly.
        entry.expires_at = 0.0
        resolver.resolve_host("h")
        assert len(calls) == 2

    def test_ttl_remaining_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare", ttl_s=60.0)
        assert resolver.cache_ttl_remaining("h") == 0.0
        resolver.resolve_host("h")
        assert 0.0 < resolver.cache_ttl_remaining("h") <= 60.0

    def test_ttl_is_capped_by_server_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS, ttl=5)})
        resolver = DohResolver("cloudflare", ttl_s=600.0)
        assert resolver.cache_ttl_remaining("h") == 0.0
        resolver.resolve_host("h")
        assert resolver.cache_ttl_remaining("h") <= 5.0

    def test_separate_hosts_cached_independently(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        resolver = DohResolver("cloudflare")
        assert resolver.resolve("a.example") in REAL_IPS
        assert resolver.resolve("b.example") in REAL_IPS


class TestResolvedHost:
    def test_requires_at_least_one_ip(self) -> None:
        with pytest.raises(ValueError, match="at least one IP"):
            ResolvedHost(host="h", ips=[], expires_at=0.0)

    def test_next_ip_round_robins(self) -> None:
        entry = ResolvedHost("h", ["1.1.1.1", "2.2.2.2"], expires_at=0.0)
        assert [entry.next_ip() for _ in range(4)] == [
            "1.1.1.1", "2.2.2.2", "1.1.1.1", "2.2.2.2",
        ]

    def test_rotate_advances_without_returning(self) -> None:
        entry = ResolvedHost("h", ["1.1.1.1", "2.2.2.2"], expires_at=0.0)
        entry.rotate()
        assert entry.next_ip() == "2.2.2.2"

    def test_expired_flag(self) -> None:
        assert ResolvedHost("h", ["1.1.1.1"], expires_at=0.0).expired is True
        assert ResolvedHost("h", ["1.1.1.1"], expires_at=1e18).expired is False


class TestNoSystemResolverUse:
    """The resolver must never fall back to the OS resolver."""

    def test_query_works_with_getaddrinfo_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """conftest already blocks socket.getaddrinfo; prove DoH still works."""
        install_urlopen(monkeypatch, {"cloudflare": doh_payload(REAL_IPS)})
        assert DohResolver("cloudflare").query("fapi.binance.com") == REAL_IPS
