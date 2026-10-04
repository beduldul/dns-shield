# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-04

### Changed

- Packaging and release metadata only; no code or behaviour changes from the
  entries below. Added complete PyPI metadata (PEP 639 `license` expression,
  author, project URLs and classifiers) and a Trusted Publishing (OIDC) release
  workflow that publishes on `v*` tags.

### Fixed

- **A false `POISONED` verdict when both resolvers returned the same address.**
  The poisoning rule's guard was `answers_disagree or not system_alive`, and by
  the time that rule was reached `not system_alive` was always true — so the
  disagreement condition was never actually consulted. A host whose system probe
  transiently failed while the DoH probe to the *same* address succeeded was
  reported as poisoning, with a summary claiming the address "does not serve the
  host" about an address the tool had just fetched HTTP 200 from. Two probes to
  one literal IP, seconds apart, is a transient failure, not a resolver lie. The
  rule now requires genuine disagreement, with an explicit branch for the
  agreed-address case. Guarded by `TestSameAddressIsNeverPoisoning`, including an
  exhaustive test over every probe-outcome combination asserting that no
  non-disagreeing input can ever yield `POISONED`.
- `ConnectionResetError` was classified as `other-error` rather than `refused`.
  It is not a subclass of `ConnectionRefusedError`, so it fell through to the
  generic handler — an active refusal was reported as an unknown error. Both are
  now classified by one shared `classify_connection_error`, so the mapping cannot
  drift between probe paths.
- `read_head` accepted a header block truncated by a peer close, returning a
  status with no headers and no body — indistinguishable from a legitimate empty
  `200`, with the failure surfacing later as a confusing JSON decode error. It
  now raises `connection closed before headers were complete`.
- `dechunk` silently dropped data on a malformed chunk terminator. It now
  validates the CRLF and raises rather than presenting a short body as complete.
- Status-line parsing used `split(" ", 2)`, rejecting legal responses such as
  `HTTP/1.1 204` (no reason phrase) and doubled spaces. Now parsed tolerantly.
- `backoff_delay` used pure full jitter with no floor, admitting a zero-length
  sleep and a near-instant retry loop against a fast-refusing endpoint. A
  `base_s` floor is now applied, including to honoured `retryAfter` hints.
- Resolution failures were labelled `kind="connect"`, misdirecting diagnosis of
  a DoH outage as a connection problem. Now `kind="resolution"`.

### Changed

- `ProbeResult` gains `slow_refusal` and `refusal_mode`, so an active refusal is
  distinguished from a blackhole timeout in the evidence output.
- README: the poisoning fingerprint now documents **both** observed failure
  modes (active refusal and blackhole timeout) with the ten-trial measurement
  that shows the mode varies run to run, rather than asserting only the ~10 ms
  RST from the original report. Exit-code and `--sibling` descriptions corrected
  to match what the code actually does.

## [0.1.0] - 2026-09-28

Initial release.

### Added

- **`dns_shield.detect`** — diagnoses ISP DNS poisoning by comparing the system
  resolver against DNS-over-HTTPS, then probing both answers.
  - `Verdict` enum: `HEALTHY`, `POISONED`, `SUSPICIOUS`, `UNREACHABLE`, `UNKNOWN`.
  - `FailureKind` classification: `SUCCESS`, `REFUSED`, `TIMEOUT`, `DNS_FAILURE`,
    `TLS_FAILURE`, `HTTP_ERROR`, `OTHER_ERROR`.
  - `ProbeResult` records connect latency, HTTP status, and the peer TLS
    certificate subject/issuer, so a verdict can be audited.
  - Deliberately distinguishes DNS poisoning from a genuine outage, a real
    HTTP 451/403 geo-restriction, and TLS interception. The classifier reports
    `UNREACHABLE` rather than accusing the resolver when the true address fails
    as well.
- **`dns_shield.resolve`** — DNS-over-HTTPS resolver.
  - Pluggable providers: Cloudflare, Google, Quad9, any `application/dns-json`
    endpoint, or a chain of them with per-provider failover.
  - TTL-aware cache; answers kept in the resolver's order and consumed
    round-robin across the address pool.
  - Returns the CNAME chain alongside A/AAAA records.
- **`dns_shield.transport`** — SNI-preserving HTTP/1.1 client.
  - Resolves over DoH, then dials the resulting address with SNI and `Host` set
    to the hostname. Never calls `socket.getaddrinfo` on the request path.
  - Rotates across the resolved address set before failing; re-resolves only
    after every known address has failed.
  - Retries only genuinely retryable statuses (408, 425, 429, 500, 502, 503,
    504) with exponential backoff and jitter, honouring a `retryAfter` hint.
  - Optional `SuccessContract` for APIs that signal failure inside an
    HTTP 200 body, with a Binance BAPI preset.
- **`dns_shield.patch`** — targeted override helpers.
  - `ShieldSession` and `resolve_and_call()` for one-line use.
  - `RequestsShieldAdapter` for opt-in, per-prefix `requests` integration.
  - Explicitly scoped: nothing here patches global state or touches `/etc/hosts`.
- **`dns_shield.cli`** — `check`, `fetch` and `hosts` subcommands.
  - Meaningful exit codes: 0 healthy, 1 poisoned/suspicious, 2
    unreachable/unknown, 3 usage error.
  - `--json` output on every subcommand.
- Typed throughout (`py.typed`), Python 3.10+, zero runtime dependencies.
- Offline test suite: 246 tests, with an autouse fixture that blocks real
  sockets so no test can silently acquire a network dependency. Opt-in `live`
  marker for integration tests.

### Notes

- Measured against the motivating case: an Indonesian ISP (Biznet) returning a
  single bogus address for every `*.binance.com` hostname, while the real hosts
  behind CloudFront answered HTTP 200.
- The bogus address was observed to fail non-deterministically — sometimes an
  instant RST, sometimes a 2-second timeout. The classifier treats both as
  consistent with poisoning and records the latency as evidence rather than
  making it the verdict.

[Unreleased]: https://github.com/beduldul/dns-shield/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/beduldul/dns-shield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/beduldul/dns-shield/releases/tag/v0.1.0
