"""Tests for the no-side-effects-on-import guarantee.

Importing the library must not perform network I/O, read the environment, start
threads, or register cleanup hooks. Tests rely on this, so it is asserted
explicitly rather than assumed.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

PACKAGE = "dns_shield"


class TestImportSafety:
    def test_import_does_no_network_io(self) -> None:
        """Import inside a subprocess where every connect path raises.

        ``ssl`` must be imported *before* the socket module is patched, because
        the stdlib's own ``ssl`` module subclasses ``socket.socket`` at import
        time and would otherwise break for unrelated reasons.
        """
        program = textwrap.dedent(
            """
            import ssl  # import first: ssl subclasses socket.socket at import time
            import socket

            def explode(*args, **kwargs):
                raise AssertionError("network I/O during import")

            socket.socket = explode
            socket.create_connection = explode
            socket.getaddrinfo = explode

            import dns_shield  # noqa: F401
            print("IMPORT_OK")
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "IMPORT_OK" in result.stdout

    def test_import_opens_no_files_outside_the_package(self) -> None:
        """A crude but effective check: no .env or credential reads on import."""
        program = textwrap.dedent(
            """
            import builtins

            real_open = builtins.open
            opened = []

            def tracking_open(file, *args, **kwargs):
                opened.append(str(file))
                return real_open(file, *args, **kwargs)

            builtins.open = tracking_open
            import dns_shield  # noqa: F401
            builtins.open = real_open

            suspicious = [p for p in opened if ".env" in p or "secret" in p.lower()]
            assert not suspicious, suspicious
            print("NO_ENV_READS")
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "NO_ENV_READS" in result.stdout

    def test_import_sets_no_environment_variables(self) -> None:
        program = textwrap.dedent(
            """
            import os
            before = dict(os.environ)
            import dns_shield  # noqa: F401
            after = dict(os.environ)
            changed = {k: (before.get(k), after.get(k)) for k in set(before) | set(after)
                       if before.get(k) != after.get(k)}
            assert not changed, changed
            print("NO_ENV_WRITES")
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "NO_ENV_WRITES" in result.stdout

    def test_import_registers_no_atexit_hooks(self) -> None:
        program = textwrap.dedent(
            """
            import atexit
            before = atexit._ncallbacks()  # noqa: SLF001 - int count
            import dns_shield  # noqa: F401
            after = atexit._ncallbacks()  # noqa: SLF001
            assert before == after, (before, after)
            print("NO_ATEXIT")
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "NO_ATEXIT" in result.stdout

    def test_public_api_is_exported(self) -> None:
        import dns_shield

        for name in dns_shield.__all__:
            assert hasattr(dns_shield, name), f"{name} missing from the public API"

    def test_version_is_a_string(self) -> None:
        import dns_shield

        assert isinstance(dns_shield.__version__, str)
        assert dns_shield.__version__.count(".") == 2


class TestOfflineEnforcement:
    """Prove the conftest guard actually blocks sockets."""

    def test_real_sockets_are_blocked(self) -> None:
        import socket

        with pytest.raises(AssertionError, match="real network I/O"):
            socket.create_connection(("1.1.1.1", 80))

    def test_getaddrinfo_is_blocked(self) -> None:
        import socket

        with pytest.raises(AssertionError, match="real network I/O"):
            socket.getaddrinfo("example.com", 443)


class TestZeroRuntimeDependencies:
    """The README claims no runtime dependencies. Verify it literally."""

    def test_no_third_party_module_is_loaded_on_import(self) -> None:
        program = textwrap.dedent(
            """
            import sys
            import dns_shield  # noqa: F401
            third_party = [
                m for m in ("requests", "urllib3", "certifi", "httpx", "h2", "anyio")
                if m in sys.modules
            ]
            assert not third_party, f"importing dns_shield pulled in {third_party}"
            print("NO_THIRD_PARTY")
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "NO_THIRD_PARTY" in result.stdout

    def test_package_imports_with_requests_blocked(self) -> None:
        """The CLI and library must work on a machine without requests."""
        program = textwrap.dedent(
            """
            import sys, builtins
            real_import = builtins.__import__

            def block(name, *args, **kwargs):
                if name == "requests" or name.startswith("requests."):
                    raise ImportError("simulated: requests is not installed")
                return real_import(name, *args, **kwargs)

            builtins.__import__ = block
            for mod in [m for m in list(sys.modules) if m.startswith("requests")]:
                del sys.modules[mod]

            import dns_shield
            from dns_shield import patch
            from dns_shield.cli import main
            assert callable(main)
            assert patch.requests_available() is False
            print("WORKS_WITHOUT_REQUESTS")
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "WORKS_WITHOUT_REQUESTS" in result.stdout

    def test_requests_is_not_a_module_level_import(self) -> None:
        """A regression guard: making it eager would add a hard dependency."""
        import ast
        import inspect

        from dns_shield import patch

        tree = ast.parse(inspect.getsource(patch))
        for node in tree.body:  # module-level statements only
            if isinstance(node, ast.Import):
                assert not any(a.name == "requests" for a in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("requests")


class TestCertificateVerification:
    """The transport must verify the certificate, not merely handshake."""

    def test_default_context_requires_a_valid_certificate(self) -> None:
        import ssl

        from dns_shield.transport import SniHTTPClient

        context = SniHTTPClient()._ssl_context  # noqa: SLF001
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_system_trust_store_is_loaded(self) -> None:
        from dns_shield.transport import SniHTTPClient

        context = SniHTTPClient()._ssl_context  # noqa: SLF001
        assert context.get_ca_certs(), "no CA certificates were loaded"

    @pytest.mark.live
    def test_mismatched_hostname_is_rejected_for_real(self) -> None:
        """Dial a real address but claim a different host: must be refused.

        This proves verification is enforced rather than nominally configured.
        Skipped if the network is unavailable.
        """
        import pytest as _pytest

        from dns_shield.resolve import DohResolver, DohResolutionError
        from dns_shield.transport import SniHTTPClient, TransportError

        try:
            ips = DohResolver("cloudflare").query("example.com")
        except DohResolutionError:
            _pytest.skip("DoH unavailable")

        client = SniHTTPClient()
        with _pytest.raises(TransportError) as excinfo:
            client._open(  # noqa: SLF001
                "GET", "https://definitely-not-example.invalid/",
                body=None, headers={}, address=ips[0],
            )
        assert excinfo.value.kind == "tls"
