"""Command-line interface for dns-shield.

Exit codes are part of the contract and are stable for use in scripts and CI:

===== ==========================================================
Code  Meaning
===== ==========================================================
0     healthy -- resolvers agree and the host responds
1     poisoned or suspicious -- the resolver is lying to you
2     unreachable or unknown -- the host is genuinely down, or
      there was not enough evidence to conclude anything
3     bad usage -- invalid arguments or an unsupported operation
===== ==========================================================

Every subcommand supports ``--json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .detect import Diagnosis, Verdict, diagnose
from .resolve import PROVIDERS, DohResolutionError, DohResolver
from .transport import SniHTTPClient, TransportError

__all__ = ["EXIT_OK", "EXIT_POISONED", "EXIT_INCONCLUSIVE", "EXIT_USAGE", "main"]

EXIT_OK = 0
EXIT_POISONED = 1
EXIT_INCONCLUSIVE = 2
EXIT_USAGE = 3

#: Hostnames probed alongside the target to expose a shared bogus address.
_DEFAULT_SIBLINGS: tuple[str, ...] = ()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-shield",
        description=(
            "Detect ISP DNS poisoning and work around it. "
            "Diagnoses whether a resolver is returning false answers, and can "
            "fetch a URL through a DNS-over-HTTPS verified path."
        ),
    )
    parser.add_argument("--version", action="version", version=f"dns-shield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- check -----------------------------------------------------------
    check = sub.add_parser(
        "check",
        help="diagnose whether a hostname is being DNS-poisoned",
        description=(
            "Compare the system resolver against DoH, probe both answers, and "
            "classify the failure. Says 'unreachable' when the host is "
            "genuinely down rather than blaming the resolver."
        ),
    )
    check.add_argument("host", help="hostname to diagnose, e.g. fapi.binance.com")
    check.add_argument("--port", type=int, default=443, help="port to probe (default: 443)")
    check.add_argument("--path", default="/", help="HTTP path to probe (default: /)")
    check.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="per-probe timeout in seconds (default: 3)",
    )
    check.add_argument(
        "--provider",
        action="append",
        choices=sorted(PROVIDERS),
        help="DoH provider to trust; repeatable, tried in order",
    )
    check.add_argument(
        "--sibling",
        action="append",
        default=None,
        help=(
            "another hostname expected to share the bogus address; repeatable. "
            "Used to demonstrate the shared-IP pattern."
        ),
    )
    check.add_argument(
        "--connect-only",
        action="store_true",
        help="skip the TLS/HTTP probe and only test raw TCP reachability",
    )
    check.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    # -- fetch -----------------------------------------------------------
    fetch = sub.add_parser(
        "fetch",
        help="perform a GET through the shield (DoH + SNI-preserving dial)",
        description=(
            "Resolve the URL's host over DoH, then connect to that address while "
            "preserving SNI and Host. This bypasses a poisoned system resolver "
            "for this one request."
        ),
    )
    fetch.add_argument("url", help="absolute URL to fetch")
    fetch.add_argument(
        "--snippet", type=int, default=400, help="bytes of body to print (default: 400)"
    )
    fetch.add_argument(
        "--timeout", type=float, default=8.0, help="retry sleep base, in seconds"
    )
    fetch.add_argument(
        "--provider",
        action="append",
        choices=sorted(PROVIDERS),
        help="DoH provider to use; repeatable, tried in order",
    )
    fetch.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    # -- hosts -----------------------------------------------------------
    hosts = sub.add_parser(
        "hosts",
        help="print the real addresses for a hostname (and an optional hosts fragment)",
        description=(
            "Show the addresses DoH returns. With --hosts-file, emit a fragment "
            "suitable for /etc/hosts. That fragment is a FRAGILE workaround: the "
            "addresses rotate and stale entries cause outages."
        ),
    )
    hosts.add_argument("host", help="hostname to resolve over DoH")
    hosts.add_argument(
        "--provider",
        action="append",
        choices=sorted(PROVIDERS),
        help="DoH provider to use; repeatable, tried in order",
    )
    hosts.add_argument(
        "--hosts-file",
        action="store_true",
        help="emit an /etc/hosts fragment instead of plain addresses",
    )
    hosts.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    return parser


def _resolver_from(providers: Sequence[str] | None) -> DohResolver:
    if providers:
        return DohResolver(list(providers))
    return DohResolver()


# -- check -----------------------------------------------------------------


def _print_check(diagnosis: Diagnosis) -> None:
    ev = diagnosis.evidence
    print(f"dns-shield check: {diagnosis.host}")
    print("=" * 68)
    print(f"system DNS : {', '.join(ev.system_ips) or '(no answer)'}")
    if ev.system_error:
        print(f"             error: {ev.system_error}")
    print(
        f"DoH ({ev.doh_provider or 'n/a'}) : {', '.join(ev.doh_ips) or '(no answer)'}"
    )
    if ev.cnames:
        print(f"             CNAME -> {' -> '.join(ev.cnames)}")
    if ev.doh_error:
        print(f"             error: {ev.doh_error}")
    print()
    if ev.system_probe:
        print(f"probe sys  : {ev.system_probe.describe()}")
    if ev.doh_probe:
        print(f"probe doh  : {ev.doh_probe.describe()}")
    if ev.shared_ip_hosts:
        print(f"shared IP  : also served for {', '.join(ev.shared_ip_hosts)}")
    print()
    print("evidence:")
    for reason in diagnosis.reasons:
        print(f"  - {reason}")
    if ev.notes:
        for note in ev.notes:
            print(f"  ! {note}")
    print()
    print(f"VERDICT: {diagnosis.verdict.value.upper()}")
    print(f"  {diagnosis.summary}")
    if diagnosis.verdict is Verdict.POISONED:
        print()
        print("  Work around it for one request:")
        print(f"    dns-shield fetch https://{diagnosis.host}/")


def _cmd_check(args: argparse.Namespace) -> int:
    resolver = _resolver_from(args.provider)
    siblings = args.sibling if args.sibling is not None else list(_DEFAULT_SIBLINGS)
    diagnosis = diagnose(
        args.host,
        resolver=resolver,
        port=args.port,
        path=args.path,
        timeout_s=args.timeout,
        compare_hosts=siblings,
        do_http_probe=not args.connect_only,
    )
    if args.json:
        print(json.dumps(diagnosis.to_dict(), indent=2, sort_keys=True))
    else:
        _print_check(diagnosis)
    return diagnosis.exit_code


# -- fetch -----------------------------------------------------------------


def _cmd_fetch(args: argparse.Namespace) -> int:
    resolver = _resolver_from(args.provider)
    client = SniHTTPClient(resolver=resolver)
    try:
        response = client.send("GET", args.url, raise_for_status=False)
    except TransportError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "url": args.url,
                        "ok": False,
                        "error": str(exc),
                        "kind": exc.kind,
                        "address": exc.address,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"FETCH FAILED: {exc}", file=sys.stderr)
            if exc.kind:
                print(f"  failure kind: {exc.kind}", file=sys.stderr)
            if exc.address:
                print(f"  dialled address: {exc.address}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    snippet = response.text[: args.snippet]
    if args.json:
        print(
            json.dumps(
                {
                    "url": args.url,
                    "ok": response.ok,
                    "status": response.status,
                    "address": response.address,
                    "snippet": snippet,
                    "body_bytes": len(response.text),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"HTTP {response.status} via {response.address}")
        print(f"url: {args.url}")
        print("-" * 68)
        print(snippet)
        if len(response.text) > len(snippet):
            print(f"... [{len(response.text) - len(snippet)} more bytes]")
    return EXIT_OK if response.ok else EXIT_INCONCLUSIVE


# -- hosts -----------------------------------------------------------------


def _cmd_hosts(args: argparse.Namespace) -> int:
    resolver = _resolver_from(args.provider)
    try:
        records = resolver.query_records(args.host, "A")
    except DohResolutionError as exc:
        if args.json:
            print(json.dumps({"host": args.host, "ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"resolution failed: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    if args.json:
        print(
            json.dumps(
                {
                    "host": args.host,
                    "ok": not records.is_empty,
                    "provider": records.provider,
                    "addresses": list(records.addresses),
                    "cnames": list(records.cnames),
                    "ttl_s": records.ttl_s,
                    "fragment": (
                        _hosts_fragment(args.host, records.addresses)
                        if args.hosts_file
                        else None
                    ),
                    "fragile": args.hosts_file,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return EXIT_OK if records.addresses else EXIT_INCONCLUSIVE

    if not records.addresses:
        print(f"no A records for {args.host}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    if args.hosts_file:
        print("# dns-shield /etc/hosts fragment -- FRAGILE, read the warning below.")
        print("# These addresses rotate. Stale entries cause hard-to-debug outages.")
        print("# Prefer `dns-shield fetch` for a targeted, always-fresh override.")
        print()
        print(_hosts_fragment(args.host, records.addresses))
        print()
        print("# To apply (requires sudo):")
        print(f"#   dns-shield hosts {args.host} --hosts-file | sudo tee -a /etc/hosts")
        print("# To undo:")
        print(f"#   sudo sed -i '' '/dns-shield/d' /etc/hosts   # macOS")
        print(f"#   sudo sed -i '/dns-shield/d' /etc/hosts      # Linux")
    else:
        print(f"{args.host} (via {records.provider})")
        if records.cnames:
            print(f"  CNAME: {' -> '.join(records.cnames)}")
        for address in records.addresses:
            print(f"  {address}")
        if records.ttl_s:
            print(f"  TTL: {records.ttl_s:.0f}s")
    return EXIT_OK


def _hosts_fragment(host: str, addresses: Sequence[str]) -> str:
    lines = [f"# dns-shield {host} (regenerated {_now_iso()})"]
    for address in addresses:
        lines.append(f"{address}\t{host}")
    return "\n".join(lines)


def _now_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- entry point -----------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns the process exit code.

    A usage error exits :data:`EXIT_USAGE` (3), as documented. ``argparse``
    exits ``2`` on its own for a bad command line, which would contradict the
    documented contract (and collide with the "inconclusive" code), so its
    ``SystemExit`` is caught and re-raised with the documented code.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 0 for --help/--version and 2 for a usage error.
        code = exc.code if isinstance(exc.code, int) else 2
        if code == 0:
            raise
        raise SystemExit(EXIT_USAGE) from None

    if args.command == "check":
        return _cmd_check(args)
    if args.command == "fetch":
        return _cmd_fetch(args)
    if args.command == "hosts":
        return _cmd_hosts(args)

    parser.error(f"unknown command {args.command!r}")  # pragma: no cover
    return EXIT_USAGE  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
