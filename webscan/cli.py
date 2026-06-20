"""Command-line entry point for webscan."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from webscan import __version__, nuclei
from webscan.checks import all_active, all_names, all_passive, select
from webscan.http_client import HttpClient
from webscan.models import Severity
from webscan.progress import NullReporter, Reporter
from webscan.report import render_html, render_json, render_sarif, render_text
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
    parser.add_argument("--checks", help="Comma-separated checks to run (default: all)")
    parser.add_argument(
        "--passive-only", action="store_true", help="Run only passive checks; send no active probes"
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
        "--threads", type=int, default=10, help="Concurrent workers for the active pass (default 10)"
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Use a headless browser to crawl SPA/JS apps (needs the 'browser' extra)",
    )
    parser.add_argument(
        "--oob",
        action="store_true",
        help="Detect blind vulns out-of-band via a built-in HTTP collaborator",
    )
    parser.add_argument(
        "--oob-host",
        default="127.0.0.1",
        help="Advertised collaborator host the target can reach (your public IP/forward)",
    )
    parser.add_argument("--oob-port", type=int, default=0, help="Collaborator port (default: random)")
    parser.add_argument(
        "--oob-wait", type=float, default=5.0, help="Seconds to wait for OOB callbacks (default 5)"
    )
    parser.add_argument(
        "--max-requests", type=int, default=1000, help="Hard cap on total HTTP requests (default 1000)"
    )
    parser.add_argument(
        "--nuclei", action="store_true", help="Also run nuclei (if installed) and merge findings"
    )
    parser.add_argument(
        "--templates",
        nargs="?",
        const="__builtin__",
        default=None,
        metavar="DIR",
        help="Run YAML detection templates from DIR (bundled ones if no DIR; needs 'templates' extra)",
    )
    parser.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        help="Only report findings at or above this severity",
    )
    parser.add_argument(
        "--tamper",
        help="WAF-evasion transforms applied to SQLi probes, e.g. 'url,randomcase' (url, double-url, space2comment, space2tab, randomcase)",
    )
    parser.add_argument("--cookie", help="Send a cookie header, e.g. 'session=abc; role=admin'")
    parser.add_argument(
        "--header", action="append", default=[], help="Add a request header 'Name: value' (repeatable)"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html", "sarif"],
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
        "--insecure", "-k", action="store_true", help="Do not verify the TLS certificate"
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default="medium",
        help="Minimum severity that makes the exit code 1 (default medium)",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress live progress output")
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
    templates = None
    if args.templates is not None:
        from webscan import templates_engine

        if not templates_engine.available():
            print(
                'pyyaml not installed; --templates skipped (pip install -e ".[templates]")',
                file=sys.stderr,
            )
        else:
            path = None if args.templates == "__builtin__" else args.templates
            templates = templates_engine.load_templates(path)
            print(f"loaded {len(templates)} template(s)", file=sys.stderr)

    collaborator = None
    if args.oob:
        from webscan.collaborator import HttpCollaborator

        collaborator = HttpCollaborator(advertised_host=args.oob_host, port=args.oob_port)
        collaborator.start()
        print(
            f"OOB collaborator on {collaborator.advertised} — the target must be able to reach it",
            file=sys.stderr,
        )

    scanner = Scanner(
        client=client,
        passive_checks=passive,
        active_checks=active,
        active=bool(active),
        max_pages=args.max_pages,
        guess_params=args.guess_params,
        threads=args.threads,
        browser=args.browser,
        oob=args.oob,
        collaborator=collaborator,
        oob_wait=args.oob_wait,
        templates=templates,
        tamper=_split(args.tamper) if args.tamper else None,
        reporter=NullReporter() if args.quiet else Reporter(),
    )

    try:
        result = scanner.scan(args.target)
    finally:
        client.close()
        if collaborator is not None:
            collaborator.stop()

    if args.nuclei:
        _run_nuclei(result)

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


def _run_nuclei(result) -> None:
    if not nuclei.available():
        result.errors.append("nuclei not found on PATH; skipped --nuclei")
        return
    try:
        for finding in nuclei.run(result.target):
            result.add(finding)
    except Exception as exc:
        result.errors.append(f"nuclei: {exc}")


def _render(result, fmt: str) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "html":
        return render_html(result)
    if fmt == "sarif":
        return render_sarif(result)
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
