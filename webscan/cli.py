"""Command-line entry point for webscan."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from webscan import __version__
from webscan.checks import all_checks, check_names, select_checks
from webscan.http_client import HttpClient
from webscan.models import Severity
from webscan.report import render_json, render_text
from webscan.scanner import Scanner

_BANNER = (
    "webscan — используйте ТОЛЬКО для систем, на тестирование которых у вас есть "
    "разрешение."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscan",
        description="Лёгкий пассивный сканер веб-уязвимостей для авторизованного тестирования.",
        epilog=_BANNER,
    )
    parser.add_argument("target", nargs="?", help="URL или хост цели, напр. https://example.com")
    parser.add_argument(
        "--checks",
        help="Список проверок через запятую (по умолчанию — все). См. --list-checks.",
    )
    parser.add_argument(
        "--list-checks", action="store_true", help="Показать доступные проверки и выйти"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Формат вывода (по умолчанию text)"
    )
    parser.add_argument("--output", "-o", help="Записать отчёт в файл вместо stdout")
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Таймаут запроса в секундах (по умолчанию 10)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.0, help="Пауза между запросами в секундах (вежливость)"
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Не проверять TLS-сертификат (для лабораторных self-signed)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default="medium",
        help="Минимальная серьёзность находки, при которой код возврата = 1 (по умолчанию medium)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Подробный лог")
    parser.add_argument("--version", action="version", version=f"webscan {__version__}")
    return parser


def _print_checks() -> None:
    print("Доступные проверки:\n")
    for check in all_checks():
        print(f"  {check.name.ljust(18)} {check.description}")


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
        parser.error("не указана цель (target). Пример: webscan https://example.com")

    try:
        checks = select_checks(_split(args.checks)) if args.checks else all_checks()
    except KeyError as exc:
        parser.error(f"неизвестная проверка: {exc}. Доступные: {', '.join(check_names())}")

    if args.format == "text":
        print(_BANNER, file=sys.stderr)

    client = HttpClient(
        timeout=args.timeout,
        verify_tls=not args.insecure,
        delay=args.delay,
    )
    scanner = Scanner(client=client, checks=checks)

    try:
        result = scanner.scan(args.target)
    finally:
        client.close()

    output = render_json(result) if args.format == "json" else render_text(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"Отчёт записан в {args.output}", file=sys.stderr)
    else:
        print(output)

    return _exit_code(result, args.fail_on)


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def _exit_code(result, fail_on: str) -> int:
    threshold = Severity(fail_on)
    max_sev = result.max_severity()
    if max_sev is not None and max_sev >= threshold:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
