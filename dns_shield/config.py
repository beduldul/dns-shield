"""Tunable defaults for :mod:`dns_shield`.

Every value here is a *default*. Nothing is read from the environment at import
time, and importing this module has no side effects -- see the package
``__init__`` docstring for the no-side-effects guarantee.

Values are plain module constants rather than a settings class so they can be
overridden by keyword argument on the object that consumes them, without any
global mutation.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "BACKOFF_BASE_S",
    "BACKOFF_MAX_S",
    "CONNECT_TIMEOUT_S",
    "DOH_ENDPOINT",
    "DOH_TIMEOUT_S",
    "DNS_CACHE_TTL_S",
    "MAX_RETRIES",
    "MITM_PROBE_HOST",
    "READ_TIMEOUT_S",
    "RETRYABLE_STATUS",
    "RST_LATENCY_FAST_MS",
    "RST_LATENCY_SLOW_MS",
    "USER_AGENT",
]

#: Version reported to servers. Kept generic: it should not advertise the tool.
USER_AGENT: Final[str] = "dns-shield/0.1.1 (+https://github.com/beduldul/dns-shield)"

# -- Resolution ------------------------------------------------------------

#: Default DNS-over-HTTPS JSON endpoint (RFC 8484 @ ``application/dns-json``).
DOH_ENDPOINT: Final[str] = "https://cloudflare-dns.com/dns-query"

#: Per-query socket timeout for a DoH lookup.
DOH_TIMEOUT_S: Final[float] = 8.0

#: How long a resolved answer is trusted before it is re-queried.
DNS_CACHE_TTL_S: Final[float] = 120.0

# -- Transport -------------------------------------------------------------

#: TCP connect timeout for a shielded request.
CONNECT_TIMEOUT_S: Final[float] = 8.0

#: Socket read timeout for a shielded request.
READ_TIMEOUT_S: Final[float] = 20.0

#: Total attempts (not retries) for a shielded request.
MAX_RETRIES: Final[int] = 4

#: Base of the exponential backoff, in seconds.
BACKOFF_BASE_S: Final[float] = 0.8

#: Ceiling for a single backoff sleep, in seconds.
BACKOFF_MAX_S: Final[float] = 30.0

#: Statuses that are worth retrying. A considered set: these are the codes
#: that mean "the server could not serve you *right now*". Notably absent are
#: 401/403/404/451, which are deterministic answers and must not be retried --
#: retrying a 451 would hammer a host that is legally or administratively
#: refusing service.
RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({408, 425, 429, 500, 502, 503, 504})

# -- Diagnosis thresholds --------------------------------------------------

#: A TCP refusal (RST) at or below this latency is "instant" -- the signature of
#: a synthetic reset from a blackhole appliance rather than a real server.
RST_LATENCY_FAST_MS: Final[float] = 250.0

#: Above this, a refusal looks like it traversed real network distance.
RST_LATENCY_SLOW_MS: Final[float] = 1500.0

#: Host used to detect TLS interception by an on-path proxy.
MITM_PROBE_HOST: Final[str] = "example.com"
