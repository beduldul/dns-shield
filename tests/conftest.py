"""Shared fixtures and the offline-by-default guarantee.

The suite must pass with no network. Two mechanisms enforce that:

1. ``--offline`` is effectively always on unless ``-m live`` is selected;
   the ``no_network`` fixture autouse-blocks real sockets.
2. Tests that genuinely need the network are marked ``live`` and skipped
   unless the marker is explicitly selected.

A library about network failure whose own tests depend on the network is a
library nobody can trust in CI.
"""

from __future__ import annotations

import socket
from typing import Iterator, NoReturn

import pytest

#: The address the affected ISP poisoned every *.binance.com name to.
BOGUS_IP = "202.169.44.80"

#: Real CloudFront addresses observed for fapi.binance.com (rotating /24).
REAL_IPS = ("108.138.141.52", "108.138.141.24", "108.138.141.5", "108.138.141.35")

#: The CNAME chain actually observed.
REAL_CNAME = "d2ukl3c6tymv7q.cloudfront.net"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add ``--allow-network`` for the rare intentional live-adjacent run."""
    parser.addoption(
        "--allow-network",
        action="store_true",
        default=False,
        help="permit real sockets in unit tests (off by default)",
    )


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail loudly if a non-live test opens a real socket.

    This is the enforcement arm of the offline guarantee. It is autouse, so a
    new test cannot accidentally acquire network dependence.
    """
    if request.node.get_closest_marker("live"):
        yield
        return
    if request.config.getoption("--allow-network"):
        yield
        return

    def guarded(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError(
            "a unit test attempted real network I/O; "
            "mock it, or mark the test with @pytest.mark.live"
        )

    monkeypatch.setattr(socket, "socket", guarded)
    monkeypatch.setattr(socket, "create_connection", guarded)
    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    yield


@pytest.fixture
def bogus_ip() -> str:
    """The poisoned address."""
    return BOGUS_IP


@pytest.fixture
def real_ips() -> tuple[str, ...]:
    """The genuine CloudFront addresses."""
    return REAL_IPS


@pytest.fixture
def real_cname() -> str:
    """The genuine CNAME target."""
    return REAL_CNAME
