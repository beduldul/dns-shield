"""Tests for the CLI: exit codes, JSON output, and formatting.

Offline. The commands are driven through :func:`dns_shield.cli.main` with the
network layers monkeypatched, so exit-code semantics are tested directly.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from dns_shield import cli
from dns_shield.detect import Diagnosis, Evidence, FailureKind, ProbeResult, Verdict
from dns_shield.resolve import RecordSet
from dns_shield.transport import ShieldResponse

BOGUS = "202.169.44.80"
REAL = "108.138.141.52"
CNAME = "d2ukl3c6tymv7q.cloudfront.net"


def fake_diagnosis(verdict: Verdict) -> Diagnosis:
    """Build a Diagnosis of the requested verdict with realistic evidence."""
    if verdict is Verdict.POISONED:
        evidence = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            cnames=(CNAME,),
            system_probe=ProbeResult(BOGUS, FailureKind.REFUSED, 11.0),
            doh_probe=ProbeResult(REAL, FailureKind.SUCCESS, 142.0, status=200),
        )
    elif verdict is Verdict.HEALTHY:
        evidence = Evidence(
            host="good.example",
            system_ips=("10.0.0.1",),
            doh_ips=("10.0.0.1",),
            doh_provider="cloudflare",
            system_probe=ProbeResult("10.0.0.1", FailureKind.SUCCESS, 40.0, status=200),
            doh_probe=ProbeResult("10.0.0.1", FailureKind.SUCCESS, 42.0, status=200),
        )
    else:
        evidence = Evidence(host="down.example", doh_ips=(REAL,), doh_provider="cloudflare",
                            doh_probe=ProbeResult(REAL, FailureKind.TIMEOUT, 3000.0))
    from dns_shield.detect import classify

    return classify(evidence)


# -- check -----------------------------------------------------------------


class TestCheckCommand:
    def test_poisoned_exits_one(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "diagnose", lambda *a, **k: fake_diagnosis(Verdict.POISONED))
        assert cli.main(["check", "fapi.binance.com"]) == 1
        out = capsys.readouterr().out
        assert "POISONED" in out
        assert BOGUS in out and REAL in out
        assert "cloudfront" in out

    def test_healthy_exits_zero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "diagnose", lambda *a, **k: fake_diagnosis(Verdict.HEALTHY))
        assert cli.main(["check", "good.example"]) == 0
        assert "HEALTHY" in capsys.readouterr().out

    def test_unreachable_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "diagnose", lambda *a, **k: fake_diagnosis(Verdict.UNREACHABLE))
        assert cli.main(["check", "down.example"]) == 2
        assert "UNREACHABLE" in capsys.readouterr().out

    def test_json_output_is_valid_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "diagnose", lambda *a, **k: fake_diagnosis(Verdict.POISONED))
        cli.main(["check", "fapi.binance.com", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["verdict"] == "poisoned"
        assert payload["host"] == "fapi.binance.com"
        assert payload["evidence"]["doh_ips"] == [REAL]
        assert payload["evidence"]["system_probe"]["latency_ms"] == 11.0

    def test_poisoned_output_suggests_fetch(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "diagnose", lambda *a, **k: fake_diagnosis(Verdict.POISONED))
        cli.main(["check", "fapi.binance.com"])
        assert "dns-shield fetch" in capsys.readouterr().out

    def test_sibling_flags_are_passed_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def spy(host: str, **kwargs: Any) -> Diagnosis:
            captured.update(kwargs, host=host)
            return fake_diagnosis(Verdict.HEALTHY)

        monkeypatch.setattr(cli, "diagnose", spy)
        cli.main(
            ["check", "h.example", "--sibling", "a.example", "--sibling", "b.example",
             "--timeout", "1.5", "--port", "8443"]
        )
        assert captured["compare_hosts"] == ["a.example", "b.example"]
        assert captured["timeout_s"] == 1.5
        assert captured["port"] == 8443

    def test_connect_only_disables_http_probe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}
        monkeypatch.setattr(
            cli, "diagnose",
            lambda host, **kw: (captured.update(kw), fake_diagnosis(Verdict.HEALTHY))[1],
        )
        cli.main(["check", "h.example", "--connect-only"])
        assert captured["do_http_probe"] is False

    def test_provider_flag_builds_a_resolver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}
        monkeypatch.setattr(
            cli, "diagnose",
            lambda host, **kw: (captured.update(kw), fake_diagnosis(Verdict.HEALTHY))[1],
        )
        cli.main(["check", "h.example", "--provider", "google", "--provider", "quad9"])
        names = [p.name for p in captured["resolver"].providers]
        assert names == ["google", "quad9"]


# -- fetch -----------------------------------------------------------------


class TestFetchCommand:
    def _client(self, monkeypatch: pytest.MonkeyPatch, status: int, body: str) -> None:
        class FakeClient:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def send(self, method: str, url: str, **kwargs: Any) -> ShieldResponse:
                return ShieldResponse(status, {}, body, url, REAL)

        monkeypatch.setattr(cli, "SniHTTPClient", FakeClient)

    def test_successful_fetch_exits_zero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._client(monkeypatch, 200, '{"serverTime":123}')
        assert cli.main(["fetch", "https://fapi.binance.com/fapi/v1/ping"]) == 0
        out = capsys.readouterr().out
        assert "HTTP 200" in out and REAL in out and "serverTime" in out

    def test_json_fetch_is_valid_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._client(monkeypatch, 200, '{"ok":true}')
        cli.main(["fetch", "https://h.example/x", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == 200
        assert payload["address"] == REAL
        assert payload["ok"] is True

    def test_http_error_status_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._client(monkeypatch, 451, "blocked")
        assert cli.main(["fetch", "https://h.example/"]) == 2
        assert "HTTP 451" in capsys.readouterr().out

    def test_snippet_is_truncated(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._client(monkeypatch, 200, "x" * 1000)
        cli.main(["fetch", "https://h.example/", "--snippet", "10"])
        out = capsys.readouterr().out
        assert "more bytes" in out
        assert "x" * 11 not in out

    def test_transport_error_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from dns_shield.transport import TransportError

        class FakeClient:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def send(self, *a: Any, **k: Any) -> ShieldResponse:
                raise TransportError("connect failed", kind="connect", address=BOGUS)

        monkeypatch.setattr(cli, "SniHTTPClient", FakeClient)
        assert cli.main(["fetch", "https://h.example/"]) == 2
        assert "FETCH FAILED" in capsys.readouterr().err

    def test_transport_error_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from dns_shield.transport import TransportError

        class FakeClient:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def send(self, *a: Any, **k: Any) -> ShieldResponse:
                raise TransportError("nope", kind="connect", address=BOGUS)

        monkeypatch.setattr(cli, "SniHTTPClient", FakeClient)
        cli.main(["fetch", "https://h.example/", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is False
        assert payload["kind"] == "connect"
        assert payload["address"] == BOGUS


# -- hosts -----------------------------------------------------------------


class TestHostsCommand:
    def _resolver(
        self, monkeypatch: pytest.MonkeyPatch, records: RecordSet | Exception
    ) -> None:
        class FakeResolver:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def query_records(self, host: str, rtype: str = "A") -> RecordSet:
                if isinstance(records, Exception):
                    raise records
                return records

        monkeypatch.setattr(cli, "DohResolver", FakeResolver)

    def test_prints_addresses(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._resolver(
            monkeypatch,
            RecordSet("h", (REAL, "108.138.141.24"), (CNAME,), 57.0, "cloudflare"),
        )
        assert cli.main(["hosts", "fapi.binance.com"]) == 0
        out = capsys.readouterr().out
        assert REAL in out and CNAME in out and "TTL" in out

    def test_hosts_file_fragment_warns_about_fragility(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The /etc/hosts path must be presented as the fragile option."""
        self._resolver(monkeypatch, RecordSet("h", (REAL,), (), 57.0, "cloudflare"))
        cli.main(["hosts", "fapi.binance.com", "--hosts-file"])
        out = capsys.readouterr().out
        assert "FRAGILE" in out
        assert "rotate" in out
        assert f"{REAL}\tfapi.binance.com" in out
        assert "sudo" in out

    def test_json_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._resolver(monkeypatch, RecordSet("h", (REAL,), (CNAME,), 57.0, "cloudflare"))
        cli.main(["hosts", "fapi.binance.com", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["addresses"] == [REAL]
        assert payload["cnames"] == [CNAME]
        assert payload["provider"] == "cloudflare"

    def test_json_fragment_included_with_flag(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._resolver(monkeypatch, RecordSet("h", (REAL,), (), 57.0, "cloudflare"))
        cli.main(["hosts", "fapi.binance.com", "--json", "--hosts-file"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["fragile"] is True
        assert REAL in payload["fragment"]

    def test_empty_records_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._resolver(monkeypatch, RecordSet("h", (), (), 0.0, "cloudflare"))
        assert cli.main(["hosts", "h.example"]) == 2

    def test_resolution_error_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from dns_shield.resolve import DohResolutionError

        self._resolver(monkeypatch, DohResolutionError("all providers failed"))
        assert cli.main(["hosts", "h.example"]) == 2
        assert "resolution failed" in capsys.readouterr().err

    def test_resolution_error_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from dns_shield.resolve import DohResolutionError

        self._resolver(monkeypatch, DohResolutionError("nope"))
        cli.main(["hosts", "h.example", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is False
        assert "nope" in payload["error"]


# -- argument handling -----------------------------------------------------


class TestArgumentHandling:
    def test_missing_subcommand_exits_with_usage_error(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            cli.main([])
        assert excinfo.value.code == 2

    def test_unknown_subcommand_exits_with_usage_error(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["nonsense"])
        assert excinfo.value.code == 2

    def test_unknown_provider_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            cli.main(["check", "h.example", "--provider", "not-real"])

    def test_missing_host_argument_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            cli.main(["check"])

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--version"])
        assert excinfo.value.code == 0
        assert "dns-shield" in capsys.readouterr().out


# -- offline safety --------------------------------------------------------


class TestCliIsOfflineByDefault:
    def test_help_does_not_touch_the_network(self, capsys: pytest.CaptureFixture[str]) -> None:
        """conftest blocks sockets; --help must still work."""
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        assert "usage" in capsys.readouterr().out.lower()
