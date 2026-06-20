"""Render a ScanResult as text, JSON, HTML or SARIF."""

from __future__ import annotations

import html
import json
import sys

from webscan import __version__
from webscan.models import ScanResult, Severity

_COLORS = {
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"

_HTML_COLORS = {
    Severity.HIGH: "#d83232",
    Severity.MEDIUM: "#d98c1f",
    Severity.LOW: "#2f7fb5",
    Severity.INFO: "#888",
}

_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


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
            cwe = f"  {f.cwe}" if f.cwe else ""
            where = f"  →  param '{f.param}'" if f.param else ""
            lines.append(f"{tag} {f.check.ljust(17)} {f.title}{suffix}{cwe}")
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


def render_html(result: ScanResult) -> str:
    rows = []
    for f in result.sorted_findings():
        color = _HTML_COLORS[f.severity]
        conf = " (tentative)" if f.confidence == "tentative" else ""
        rows.append(
            "<tr>"
            f'<td><span style="color:{color};font-weight:600">{f.severity.value.upper()}</span></td>'
            f"<td>{html.escape(f.check)}</td>"
            f"<td>{html.escape(f.title)}{conf}</td>"
            f"<td>{html.escape(f.owasp)}</td>"
            f"<td>{html.escape(f.cwe)}</td>"
            f"<td>{html.escape(f.param)}</td>"
            f"<td><code>{html.escape(f.evidence)}</code></td>"
            "</tr>"
        )
    counts = result.counts()
    summary = ", ".join(
        f"{counts[s.value]} {s.value}"
        for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if counts[s.value]
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>webscan report — {html.escape(result.target)}</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#222}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px;vertical-align:top}"
        "th{background:#f4f4f4}code{font-size:12px;word-break:break-all}</style></head><body>"
        f"<h1>webscan {__version__}</h1>"
        f"<p>Target: <strong>{html.escape(result.target)}</strong><br>"
        f"Injection points: {result.injection_points} · Requests: {result.requests_made}<br>"
        f"Findings: {summary or '0'}</p>"
        "<table><thead><tr><th>Severity</th><th>Check</th><th>Title</th>"
        "<th>OWASP</th><th>CWE</th><th>Param</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>"
    )


def render_sarif(result: ScanResult) -> str:
    findings = result.sorted_findings()
    rule_ids = sorted({f.check for f in findings})
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": rid}} for rid in rule_ids]
    results = []
    for f in findings:
        props = {"security-severity": _SECURITY_SEVERITY[f.severity], "confidence": f.confidence}
        tags = [t for t in (f.cwe, f.owasp) if t]
        if f.mitre:
            tags.extend(m.strip() for m in f.mitre.split(",") if m.strip())
        if tags:
            props["tags"] = tags
        results.append(
            {
                "ruleId": f.check,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.evidence}".strip()},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f.url or result.target}}}
                ],
                "properties": props,
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "webscan",
                        "version": __version__,
                        "informationUri": "https://github.com/feadal/Web-vuln-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


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
