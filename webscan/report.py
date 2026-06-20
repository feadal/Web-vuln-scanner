"""Render a :class:`~webscan.models.ScanResult` as text or JSON."""

from __future__ import annotations

import json
import sys

from webscan import __version__
from webscan.models import ScanResult, Severity

# ANSI colours per severity (only used when the stream is a TTY).
_COLORS = {
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[36m",  # cyan
    Severity.INFO: "\033[90m",  # grey
}
_RESET = "\033[0m"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def render_text(result: ScanResult, *, color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty()

    lines: list[str] = []
    lines.append(f"webscan {__version__} — target: {result.target}")
    lines.append(
        f"crawled injection points: {result.injection_points} · "
        f"requests sent: {result.requests_made}"
    )
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("No findings. ✓")
    else:
        for f in findings:
            tag = f"[{f.severity.value.upper()}]".ljust(9)
            if color:
                tag = _COLORS[f.severity] + tag + _RESET
            suffix = "  (tentative)" if f.confidence == "tentative" else ""
            where = f"  →  param '{f.param}'" if f.param else ""
            lines.append(f"{tag} {f.check.ljust(17)} {f.title}{suffix}")
            if f.evidence:
                lines.append(f"          ↳ {f.evidence}{where}")
            elif where:
                lines.append(f"          ↳{where}")

    lines.append("")
    lines.append(_summary_line(result))

    if result.errors:
        lines.append("")
        lines.append("Scan notes:")
        for err in result.errors:
            lines.append(f"  ! {err}")

    return "\n".join(lines)


def _summary_line(result: ScanResult) -> str:
    counts = result.counts()
    total = sum(counts.values())
    if total == 0:
        return "Total: 0 findings"
    parts = [
        f"{counts[s.value]} {s.value}"
        for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if counts[s.value]
    ]
    return f"Total: {total} findings ({', '.join(parts)})"
