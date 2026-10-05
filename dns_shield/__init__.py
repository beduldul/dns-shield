"""dns-shield -- detect ISP DNS poisoning and transparently work around it.

Whose problem this solves
-------------------------
An ISP that answers DNS with a false address makes a reachable service look
blocked. The site appears "geo-blocked" or "banned", the user gives up, and the
conclusion is wrong: only name resolution was broken. This library measures the
difference and, when it is safe to say so, works around it.

The documented motivating case: Biznet (Indonesia) answered every
``*.binance.com`` name with a single bogus address whose connections died, while
the real hosts sat on CloudFront and answered HTTP 200.

Zero side effects on import
---------------------------
Importing this package performs **no** network I/O, reads no environment
variables, starts no threads, and registers no atexit hooks. Network calls only
happen when you explicitly call something. Tests rely on this and assert it.

Quick start
-----------
::

    from dns_shield import diagnose, resolve_and_call

    diagnosis = diagnose("fapi.binance.com")
    print(diagnosis.verdict, diagnosis.summary)

    response = resolve_and_call("https://fapi.binance.com/fapi/v1/ping")
    print(response.status, response.text[:80])

Licence: MIT.
"""

from __future__ import annotations

from .detect import (
    Diagnosis,
    Evidence,
    FailureKind,
    ProbeResult,
    Verdict,
    classify,
    diagnose,
    probe_connect,
    probe_http,
    system_resolve,
)
from .patch import (
    RequestsShieldAdapter,
    ShieldSession,
    resolve_and_call,
    shielded_client,
)
from .resolve import (
    PROVIDERS,
    DohProvider,
    DohResolutionError,
    DohResolver,
    RecordSet,
    ResolvedHost,
)
from .transport import (
    BINANCE_SUCCESS_CONTRACT,
    ShieldResponse,
    SniHTTPClient,
    SuccessContract,
    TransportError,
)

__version__ = "0.1.3"

__all__ = [
    "BINANCE_SUCCESS_CONTRACT",
    "Diagnosis",
    "DohProvider",
    "DohResolutionError",
    "DohResolver",
    "Evidence",
    "FailureKind",
    "PROVIDERS",
    "ProbeResult",
    "RecordSet",
    "RequestsShieldAdapter",
    "ResolvedHost",
    "ShieldResponse",
    "ShieldSession",
    "SniHTTPClient",
    "SuccessContract",
    "TransportError",
    "Verdict",
    "__version__",
    "classify",
    "diagnose",
    "probe_connect",
    "probe_http",
    "resolve_and_call",
    "shielded_client",
    "system_resolve",
]
