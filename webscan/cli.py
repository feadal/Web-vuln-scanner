"""Command-line entry point for webscan."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from webscan import __version__
from webscan.checks import all_active, all_names, all_passive, select
from webscan.http_client import HttpClient
from webscan.models import Severity
from webscan.report import render_html, render_json, render_text
from webscan.scanner import Scanner

_BANNER = (
    "webscan sends active probes. Use it ONLY against systems you own or are "
    "explicitly authorized to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscan",
        description="Active web vulnerability scanner for authorized testing.",
        epilog=_BANNER,
    )
    parser.add_argument("target", nargs="?", help="Target URL or host, e.g. https://example.com")
    parser.add_argument(
        "--checks",
        help="Comma-separated checks to run (default: all). See --list-checks.",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Run only passive checks; send no active probes",
    )
    parser.add_argument(
        "--list-checks", action="store_true", help="List available checks and exit"
    )
    parser.add_argument(
        "--max-pages", type=int, default=10, help="Max pages to crawl for inputs (default 10)"
    )
    parser.add_argument(
        "--guess-params",
        action="store_true",
        help="Also probe common parameter names (page, file, url, id, ...)",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=1000,
        help="Hard cap on total HTTP requests for the scan (default 1000)",
    )
    parser.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        help="Only report findings at or above this severity",
    )
    parser.add_argument(
        "--cookie",
        help="Send a cookie header, e.g. 'session=abc; role=admin' (scan behind login)",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Add a request header 'Name: value' (repeatable)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default text)",
    )
    parser.add_argument("--output", "-o", help="Write the report to a file instead of stdout")
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default 10)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.0, help="Delay between requests in seconds (politeness)"
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Do not verify the TLS certificate (for lab self-signed certs)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default="medium",
        help="Minimum severity that makes the exit code 1 (default medium)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"webscan {__version__}")
    return parser


def _print_checks() -> None:
    print("Passive checks (always safe):\n")
    for check in all_passive():
        print(f"  {check.name.ljust(18)} {check.description}")
    print("\nActive checks (send probes — authorized targets only):\n")
    for check in all_active():
        print(f"  {check.name.ljust(18)} {check.description}")


def _parse_cookies(value: Optional[str]) -> dict:
    if not value:
        return {}
    out = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            name, val = part.split("=", 1)
            out[name.strip()] = val.strip()
    return out


def _parse_headers(values: Sequence[str]) -> dict:
    out = {}
    for item in values:
        if ":" in item:
            name, val = item.split(":", 1)
            out[name.strip()] = val.strip()
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.list_checks:
        _print_checks()
        return 0

    if not args.target:
        parser.error("no target given. Example: webscan https://example.com")

    try:
        if args.checks:
            passive, active = select(_split(args.checks))
        else:
            passive, active = all_passive(), all_active()
    except KeyError as exc:
        parser.error(f"unknown check: {exc}. Available: {', '.join(all_names())}")

    if args.passive_only:
        active = []

    if args.format == "text":
        print(_BANNER, file=sys.stderr)

    client = HttpClient(
        timeout=args.timeout,
        verify_tls=not args.insecure,
        delay=args.delay,
        max_requests=args.max_requests,
        headers=_parse_headers(args.header),
        cookies=_parse_cookies(args.cookie),
    )
    scanner = Scanner(
        client=client,
        passive_checks=passive,
        active_checks=active,
        active=bool(active),
        max_pages=args.max_pages,
        guess_params=args.guess_params,
    )

    try:
        result = scanner.scan(args.target)
    finally:
        client.close()

    if args.min_severity:
        threshold = Severity(args.min_severity)
        result.findings = [f for f in result.findings if f.severity >= threshold]

    output = _render(result, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return _exit_code(result, args.fail_on)


def _render(result, fmt: str) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "html":
        return render_html(result)
    return render_text(result)


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def _exit_code(result, fail_on: str) -> int:
    threshold = Severity(fail_on)
    max_sev = result.max_severity()
    if max_sev is not None and max_sev >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
