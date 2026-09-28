"""Tests for the verdict classifier.

These are the tests that decide whether the tool can be trusted. A tool that
prints "POISONED" for everything is worse than no tool, so the negative cases
here matter at least as much as the positive one.

All offline: the classifier is a pure function over :class:`Evidence`.
"""

from __future__ import annotations

import pytest

from dns_shield.detect import (
    Diagnosis,
    Evidence,
    FailureKind,
    ProbeResult,
    Verdict,
    classify,
)

BOGUS = "202.169.44.80"
REAL = "108.138.141.52"
REAL_IPS = ("108.138.141.52", "108.138.141.24", "108.138.141.5", "108.138.141.35")
CNAME = "d2ukl3c6tymv7q.cloudfront.net"


def probe(address: str, kind: FailureKind, latency_ms: float, status: int | None = None) -> ProbeResult:
    """Build a ProbeResult tersely."""
    return ProbeResult(address, kind, latency_ms, status=status)


# -- the motivating case ---------------------------------------------------


class TestPoisoning:
    """The exact fingerprint measured on the affected machine."""

    def test_instant_rst_plus_working_doh_is_poisoned(self) -> None:
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            cnames=(CNAME,),
            system_probe=probe(BOGUS, FailureKind.REFUSED, 11.0),
            doh_probe=probe(REAL, FailureKind.SUCCESS, 140.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.POISONED
        assert result.exit_code == 1
        assert "false answer" in result.summary
        assert any("synthetic reset" in r for r in result.reasons)

    def test_timeout_on_bogus_ip_is_still_poisoned(self) -> None:
        """Measured non-determinism: the blackhole sometimes drops, not resets.

        A timeout must not be read as evidence *against* poisoning, because the
        same appliance produced both behaviours within seconds on the real
        machine.
        """
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.TIMEOUT, 2001.0),
            doh_probe=probe(REAL, FailureKind.SUCCESS, 150.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.POISONED
        assert any("timed out rather than being refused" in r for r in result.reasons)

    def test_slow_refusal_is_still_poisoned(self) -> None:
        """Latency alone must not decide the verdict."""
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.REFUSED, 1012.0),
            doh_probe=probe(REAL, FailureKind.SUCCESS, 150.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.POISONED

    def test_shared_ip_is_surfaced_as_evidence(self) -> None:
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.REFUSED, 12.0),
            doh_probe=probe(REAL, FailureKind.SUCCESS, 130.0, status=200),
            shared_ip_hosts=("api.binance.com", "www.binance.com"),
        )
        result = classify(ev)
        assert result.verdict is Verdict.POISONED
        assert any("unrelated hostnames" in r for r in result.reasons)


# -- the cases that must NOT be called poisoning ---------------------------


class TestNotPoisoned:
    """Getting these wrong makes the tool untrustworthy."""

    def test_genuinely_down_host_is_unreachable_not_poisoned(self) -> None:
        """Both resolvers agree; the host is simply dead."""
        ev = Evidence(
            host="down.example",
            system_ips=("1.2.3.4",),
            doh_ips=("1.2.3.4",),
            doh_provider="cloudflare",
            system_probe=probe("1.2.3.4", FailureKind.TIMEOUT, 3000.0),
            doh_probe=probe("1.2.3.4", FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert result.verdict is not Verdict.POISONED
        assert result.exit_code == 2

    def test_real_address_down_and_answers_disagree_is_unreachable(self) -> None:
        """Disagreement alone is not proof: the DoH address must also work."""
        ev = Evidence(
            host="odd.example",
            system_ips=(BOGUS,),
            doh_ips=("8.8.8.8",),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.TIMEOUT, 3000.0),
            doh_probe=probe("8.8.8.8", FailureKind.REFUSED, 2000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert any("not the fault" in r for r in result.reasons)

    def test_http_451_geo_block_is_unreachable_not_poisoned(self) -> None:
        """A 451 is a real server answering. That is a genuine restriction."""
        ev = Evidence(
            host="geo.example",
            system_ips=(BOGUS,),
            doh_ips=("9.9.9.9",),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.REFUSED, 12.0),
            doh_probe=probe("9.9.9.9", FailureKind.HTTP_ERROR, 300.0, status=451),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert "451" in result.summary
        assert "not DNS poisoning" in result.summary

    def test_http_403_is_unreachable_not_poisoned(self) -> None:
        ev = Evidence(
            host="forbidden.example",
            system_ips=(BOGUS,),
            doh_ips=("9.9.9.10",),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.REFUSED, 12.0),
            doh_probe=probe("9.9.9.10", FailureKind.HTTP_ERROR, 280.0, status=403),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE

    def test_http_500_on_real_address_is_not_poisoned(self) -> None:
        """A 5xx from the true address is the host's problem, not the resolver's."""
        ev = Evidence(
            host="broken.example",
            system_ips=(BOGUS,),
            doh_ips=("9.9.9.11",),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.REFUSED, 12.0),
            doh_probe=probe("9.9.9.11", FailureKind.HTTP_ERROR, 400.0, status=500),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert "500" in result.summary

    def test_both_paths_working_with_different_ips_is_healthy(self) -> None:
        """Different answers that both work is CDN rotation, not a lie."""
        ev = Evidence(
            host="cdn.example",
            system_ips=("10.0.0.1",),
            doh_ips=("10.0.0.2",),
            doh_provider="cloudflare",
            system_probe=probe("10.0.0.1", FailureKind.SUCCESS, 50.0, status=200),
            doh_probe=probe("10.0.0.2", FailureKind.SUCCESS, 60.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.HEALTHY
        assert result.exit_code == 0
        assert "rotating CDN" in result.summary

    def test_agreeing_resolvers_and_working_host_is_healthy(self) -> None:
        ev = Evidence(
            host="good.example",
            system_ips=("10.0.0.5",),
            doh_ips=("10.0.0.5",),
            doh_provider="cloudflare",
            system_probe=probe("10.0.0.5", FailureKind.SUCCESS, 40.0, status=200),
            doh_probe=probe("10.0.0.5", FailureKind.SUCCESS, 45.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.HEALTHY
        assert result.exit_code == 0

    def test_tls_interception_on_real_address_is_not_poisoning(self) -> None:
        """TCP to the real address works but TLS fails: a different problem."""
        ev = Evidence(
            host="mitm.example",
            system_ips=(BOGUS,),
            doh_ips=("10.0.0.9",),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.REFUSED, 10.0),
            doh_probe=probe("10.0.0.9", FailureKind.TLS_FAILURE, 90.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert "TLS" in result.summary

    def test_disagreement_with_dead_doh_address_is_suspicious(self) -> None:
        """Unresolvable ambiguity must be admitted, not guessed."""
        ev = Evidence(
            host="ambiguous.example",
            system_ips=(BOGUS,),
            doh_ips=("8.8.4.4",),
            doh_provider="cloudflare",
            system_probe=probe(BOGUS, FailureKind.SUCCESS, 30.0, status=200),
            doh_probe=probe("8.8.4.4", FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.SUSPICIOUS
        assert result.exit_code == 1

    def test_no_doh_answer_is_unknown(self) -> None:
        ev = Evidence(
            host="nx.example",
            system_ips=("1.1.1.1",),
            doh_error="all DoH providers failed",
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNKNOWN
        assert result.exit_code == 2


# -- ProbeResult semantics -------------------------------------------------


class TestProbeResultSemantics:
    def test_fast_refusal_threshold_boundary(self) -> None:
        assert probe(BOGUS, FailureKind.REFUSED, 10.0).fast_refusal is True
        assert probe(BOGUS, FailureKind.REFUSED, 250.0).fast_refusal is True
        assert probe(BOGUS, FailureKind.REFUSED, 250.1).fast_refusal is False

    def test_timeout_is_never_a_fast_refusal(self) -> None:
        """The discriminator is the failure kind, not just the clock."""
        assert probe(BOGUS, FailureKind.TIMEOUT, 5.0).fast_refusal is False

    def test_works_requires_success_not_mere_connectivity(self) -> None:
        assert probe(REAL, FailureKind.SUCCESS, 20.0, status=200).works is True
        assert probe(REAL, FailureKind.HTTP_ERROR, 20.0, status=451).works is False
        assert probe(REAL, FailureKind.TLS_FAILURE, 20.0).works is False

    def test_connected_distinguishes_tls_from_connect_failure(self) -> None:
        assert probe(REAL, FailureKind.TLS_FAILURE, 20.0).connected is True
        assert probe(REAL, FailureKind.HTTP_ERROR, 20.0, status=500).connected is True
        assert probe(REAL, FailureKind.REFUSED, 20.0).connected is False
        assert probe(REAL, FailureKind.TIMEOUT, 20.0).connected is False

    def test_describe_is_human_readable(self) -> None:
        assert "HTTP 200" in probe(REAL, FailureKind.SUCCESS, 12.3, status=200).describe()
        assert "RST" in probe(BOGUS, FailureKind.REFUSED, 11.0).describe()
        assert "timed out" in probe(BOGUS, FailureKind.TIMEOUT, 2000.0).describe()


# -- serialisation ---------------------------------------------------------


class TestDiagnosisSerialisation:
    def test_to_dict_is_json_serialisable(self) -> None:
        import json

        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            cnames=(CNAME,),
            system_probe=probe(BOGUS, FailureKind.REFUSED, 11.0),
            doh_probe=probe(REAL, FailureKind.SUCCESS, 140.0, status=200),
        )
        result = classify(ev)
        payload = json.loads(json.dumps(result.to_dict()))
        assert payload["verdict"] == "poisoned"
        assert payload["exit_code"] == 1
        assert payload["evidence"]["answers_disagree"] is True
        assert payload["evidence"]["system_probe"]["fast_refusal"] is True
        assert payload["evidence"]["doh_probe"]["status"] == 200
        assert payload["evidence"]["cnames"] == [CNAME]

    def test_exit_codes_are_distinct_per_verdict(self) -> None:
        assert Diagnosis("h", Verdict.HEALTHY, "", Evidence("h")).exit_code == 0
        assert Diagnosis("h", Verdict.POISONED, "", Evidence("h")).exit_code == 1
        assert Diagnosis("h", Verdict.SUSPICIOUS, "", Evidence("h")).exit_code == 1
        assert Diagnosis("h", Verdict.UNREACHABLE, "", Evidence("h")).exit_code == 2
        assert Diagnosis("h", Verdict.UNKNOWN, "", Evidence("h")).exit_code == 2


# -- Evidence helpers ------------------------------------------------------


class TestEvidenceHelpers:
    def test_answers_disagree_ignores_empty_sides(self) -> None:
        assert Evidence("h", system_ips=(), doh_ips=("1.1.1.1",)).answers_disagree is False
        assert Evidence("h", system_ips=("1.1.1.1",), doh_ips=()).answers_disagree is False

    def test_answers_disagree_detects_partial_overlap_as_agreement(self) -> None:
        """One shared address means the resolvers are not in conflict."""
        ev = Evidence("h", system_ips=("1.1.1.1", "2.2.2.2"), doh_ips=("2.2.2.2", "3.3.3.3"))
        assert ev.answers_disagree is False

    def test_answers_disagree_true_on_disjoint_sets(self) -> None:
        ev = Evidence("h", system_ips=(BOGUS,), doh_ips=(REAL,))
        assert ev.answers_disagree is True

    def test_first_ip_accessors(self) -> None:
        ev = Evidence("h", system_ips=(BOGUS, "1.1.1.1"), doh_ips=(REAL,))
        assert ev.system_ip == BOGUS
        assert ev.doh_ip == REAL
        assert Evidence("h").system_ip is None


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (FailureKind.REFUSED, Verdict.POISONED),
        (FailureKind.TIMEOUT, Verdict.POISONED),
        (FailureKind.OTHER_ERROR, Verdict.POISONED),
    ],
)
def test_every_transport_failure_kind_on_bogus_ip_is_poisoned_when_doh_works(
    kind: FailureKind, expected: Verdict
) -> None:
    """The label must not hinge on *how* the bogus address failed."""
    ev = Evidence(
        host="h.example",
        system_ips=(BOGUS,),
        doh_ips=(REAL,),
        doh_provider="cloudflare",
        system_probe=probe(BOGUS, kind, 30.0),
        doh_probe=probe(REAL, FailureKind.SUCCESS, 100.0, status=200),
    )
    assert classify(ev).verdict is expected


class TestMeasuredRealWorldCases:
    """Regression guards for behaviour found by running against the live host.

    Both of these were bugs that only appeared against the real network, not
    against the mocks. They are the reason the classifier keys on "did a server
    answer" rather than "was the status 2xx".
    """

    def test_403_on_root_is_not_poisoning(self) -> None:
        """The API host returns 403 for `/` while serving 200 on its real routes.

        Treating that as a block would report a healthy, correctly-resolved host
        as poisoned -- the exact false accusation this tool exists to avoid.
        """
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            cnames=(CNAME,),
            probed_path="/",
            system_probe=ProbeResult(BOGUS, FailureKind.TIMEOUT, 3015.0),
            doh_probe=ProbeResult(
                REAL, FailureKind.HTTP_ERROR, 106.0, status=403,
                cert_subject="*.binance.com", cert_valid=True,
            ),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert result.verdict is not Verdict.POISONED
        assert "/" in result.summary
        assert any("not the problem" in r for r in result.reasons)

    def test_the_real_fingerprint_with_a_working_path_is_poisoned(self) -> None:
        """The exact live output: bogus address times out, DoH serves 200.

        Note the system probe is a *timeout*, not the ~10 ms RST in the original
        report. The address failed non-deterministically when re-measured, and
        the verdict must not depend on which way it failed.
        """
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=REAL_IPS,
            doh_provider="cloudflare",
            cnames=(CNAME,),
            probed_path="/fapi/v1/ping",
            system_probe=ProbeResult(BOGUS, FailureKind.TIMEOUT, 3015.0),
            doh_probe=ProbeResult(
                REAL_IPS[0], FailureKind.SUCCESS, 350.0, status=200,
                cert_subject="*.binance.com", cert_valid=True,
            ),
        )
        result = classify(ev)
        assert result.verdict is Verdict.POISONED
        assert result.exit_code == 1
        assert any("valid certificate for *.binance.com" in r for r in result.reasons)

    def test_valid_certificate_on_doh_address_is_cited_as_evidence(self) -> None:
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=ProbeResult(BOGUS, FailureKind.REFUSED, 1039.0),
            doh_probe=ProbeResult(
                REAL, FailureKind.SUCCESS, 172.0, status=200,
                cert_subject="*.binance.com", cert_issuer="GeoTrust TLS RSA CA G1",
                cert_valid=True,
            ),
        )
        result = classify(ev)
        assert result.verdict is Verdict.POISONED
        assert any("really is serving this host" in r for r in result.reasons)

    def test_http_error_on_doh_address_never_yields_poisoned(self) -> None:
        """Exhaustive guard: a real server answering cannot mean poisoning."""
        for status in (400, 401, 403, 404, 405, 418, 451, 500, 502, 503):
            ev = Evidence(
                host="h.example",
                system_ips=(BOGUS,),
                doh_ips=(REAL,),
                doh_provider="cloudflare",
                system_probe=ProbeResult(BOGUS, FailureKind.REFUSED, 11.0),
                doh_probe=ProbeResult(REAL, FailureKind.HTTP_ERROR, 100.0, status=status),
            )
            result = classify(ev)
            assert result.verdict is not Verdict.POISONED, f"HTTP {status} was called poisoning"


class TestRemainingClassifierBranches:
    """Cover the branches that decide between the inconclusive verdicts."""

    def test_agreeing_resolvers_with_a_dead_address_is_unreachable(self) -> None:
        """Both resolvers name the same address and it does not serve the host.

        This is the outage case: blaming the resolver here would be a lie.
        """
        ev = Evidence(
            host="outage.example",
            system_ips=("10.0.0.7",),
            doh_ips=("10.0.0.7",),
            doh_provider="cloudflare",
            system_probe=ProbeResult("10.0.0.7", FailureKind.TIMEOUT, 3000.0),
            doh_probe=ProbeResult("10.0.0.7", FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert result.verdict is not Verdict.POISONED
        assert any("not the fault" in r for r in result.reasons)

    def test_no_system_answer_with_an_error_is_unreachable(self) -> None:
        ev = Evidence(
            host="broken-resolver.example",
            system_ips=(),
            system_error="gaierror: Name or service not known",
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            doh_probe=ProbeResult(REAL, FailureKind.SUCCESS, 100.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert "gaierror" in result.summary or any("gaierror" in r for r in result.reasons)

    def test_no_system_answer_without_an_error_is_a_resolution_failure(self) -> None:
        """The host is reachable but the local resolver produced nothing.

        Reported as UNREACHABLE rather than HEALTHY: from the user's point of
        view the name does not resolve, which is a real problem even though it
        is not poisoning.
        """
        ev = Evidence(
            host="quiet-resolver.example",
            system_ips=(),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            doh_probe=ProbeResult(REAL, FailureKind.SUCCESS, 100.0, status=200),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert "not poisoning" in result.summary
        assert any("no contradictory answer" in r for r in result.reasons)

    def test_system_alive_doh_dead_with_disagreement_is_suspicious(self) -> None:
        ev = Evidence(
            host="odd.example",
            system_ips=("10.0.0.1",),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=ProbeResult("10.0.0.1", FailureKind.SUCCESS, 50.0, status=200),
            doh_probe=ProbeResult(REAL, FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.SUSPICIOUS
        assert result.exit_code == 1

    def test_system_alive_and_doh_dead_without_disagreement_is_unreachable(self) -> None:
        """Same address on both paths, system works, DoH probe failed."""
        ev = Evidence(
            host="flaky.example",
            system_ips=("10.0.0.2",),
            doh_ips=("10.0.0.2",),
            doh_provider="cloudflare",
            system_probe=ProbeResult("10.0.0.2", FailureKind.SUCCESS, 40.0, status=200),
            doh_probe=ProbeResult("10.0.0.2", FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE

    def test_doh_timeout_with_disjoint_answers_is_unreachable(self) -> None:
        """The final SUSPICIOUS fallback: disagree, DoH address dead, system fine."""
        ev = Evidence(
            host="ambiguous.example",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=ProbeResult(BOGUS, FailureKind.TIMEOUT, 3000.0),
            doh_probe=ProbeResult(REAL, FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        assert result.verdict is Verdict.UNREACHABLE
        assert result.exit_code == 2

    def test_suspicious_fallback_is_reachable(self) -> None:
        """Construct the genuine ambiguity directly and pin the verdict."""
        ev = Evidence(
            host="ambiguous.example",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            system_probe=ProbeResult(BOGUS, FailureKind.HTTP_ERROR, 200.0, status=200),
            doh_probe=ProbeResult(REAL, FailureKind.TIMEOUT, 3000.0),
        )
        result = classify(ev)
        # System serves the host (HTTP 200), DoH address is dead, answers differ.
        assert result.verdict is Verdict.SUSPICIOUS
        assert "does not support calling this poisoning" in result.summary


class TestSameAddressIsNeverPoisoning:
    """Regression guards for a false-positive found in review.

    The poisoning rule must require the two resolvers to *disagree*. When both
    returned the same address, one probe failing is a transient condition, not
    evidence about the resolver -- and calling it poisoning is precisely the
    false accusation this project exists to avoid.
    """

    def test_identical_address_with_one_probe_failing_is_not_poisoned(self) -> None:
        """Both paths name the same IP; only the system probe failed."""
        ev = Evidence(
            host="rate-limited.example",
            system_ips=("1.2.3.4",),
            doh_ips=("1.2.3.4",),
            doh_provider="cloudflare",
            system_probe=ProbeResult("1.2.3.4", FailureKind.TIMEOUT, 3000.0),
            doh_probe=ProbeResult("1.2.3.4", FailureKind.SUCCESS, 50.0, status=200),
        )
        assert ev.answers_disagree is False
        result = classify(ev)
        assert result.verdict is not Verdict.POISONED
        assert result.verdict is Verdict.SUSPICIOUS
        assert "transient" in result.summary

    def test_identical_address_with_refusal_is_not_poisoned(self) -> None:
        ev = Evidence(
            host="congested.example",
            system_ips=("1.2.3.4",),
            doh_ips=("1.2.3.4",),
            doh_provider="cloudflare",
            system_probe=ProbeResult("1.2.3.4", FailureKind.REFUSED, 11.0),
            doh_probe=ProbeResult("1.2.3.4", FailureKind.SUCCESS, 50.0, status=200),
        )
        assert classify(ev).verdict is not Verdict.POISONED

    def test_partial_overlap_is_not_poisoned(self) -> None:
        """One shared address means the resolvers are not in conflict."""
        ev = Evidence(
            host="cdn.example",
            system_ips=("1.1.1.1", "2.2.2.2"),
            doh_ips=("2.2.2.2", "3.3.3.3"),
            doh_provider="cloudflare",
            system_probe=ProbeResult("1.1.1.1", FailureKind.REFUSED, 10.0),
            doh_probe=ProbeResult("2.2.2.2", FailureKind.SUCCESS, 50.0, status=200),
        )
        assert ev.answers_disagree is False
        assert classify(ev).verdict is not Verdict.POISONED

    def test_poisoned_summary_never_claims_a_shared_address_is_bogus(self) -> None:
        """The wording must not contradict the evidence."""
        ev = Evidence(
            host="h.example",
            system_ips=("1.2.3.4",),
            doh_ips=("1.2.3.4",),
            doh_provider="cloudflare",
            system_probe=ProbeResult("1.2.3.4", FailureKind.TIMEOUT, 3000.0),
            doh_probe=ProbeResult("1.2.3.4", FailureKind.SUCCESS, 50.0, status=200),
        )
        result = classify(ev)
        assert "does not serve the host" not in result.summary

    def test_genuine_disagreement_still_yields_poisoned(self) -> None:
        """The fix must not weaken real detection."""
        ev = Evidence(
            host="fapi.binance.com",
            system_ips=(BOGUS,),
            doh_ips=(REAL,),
            doh_provider="cloudflare",
            cnames=(CNAME,),
            system_probe=ProbeResult(BOGUS, FailureKind.REFUSED, 12.0),
            doh_probe=ProbeResult(REAL, FailureKind.SUCCESS, 150.0, status=200),
        )
        assert ev.answers_disagree is True
        assert classify(ev).verdict is Verdict.POISONED

    def test_poisoned_requires_disagreement_invariant(self) -> None:
        """Exhaustive: no non-disagreeing input may produce POISONED."""
        probes = [
            ProbeResult("1.2.3.4", FailureKind.REFUSED, 5.0),
            ProbeResult("1.2.3.4", FailureKind.REFUSED, 2000.0),
            ProbeResult("1.2.3.4", FailureKind.TIMEOUT, 3000.0),
            ProbeResult("1.2.3.4", FailureKind.OTHER_ERROR, 100.0),
            ProbeResult("1.2.3.4", FailureKind.TLS_FAILURE, 100.0),
            ProbeResult("1.2.3.4", FailureKind.HTTP_ERROR, 100.0, status=403),
        ]
        for system_probe in probes:
            for doh_probe in probes:
                ev = Evidence(
                    host="h.example",
                    system_ips=("1.2.3.4",),
                    doh_ips=("1.2.3.4",),
                    doh_provider="cloudflare",
                    system_probe=system_probe,
                    doh_probe=doh_probe,
                )
                assert ev.answers_disagree is False
                result = classify(ev)
                assert result.verdict is not Verdict.POISONED, (
                    f"non-disagreeing input classified as POISONED: "
                    f"system={system_probe.kind} doh={doh_probe.kind}"
                )
