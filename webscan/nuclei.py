"""Optional integration with ProjectDiscovery's nuclei for template coverage."""

from __future__ import annotations

import json
import shutil
import subprocess

from webscan.models import Finding, Severity

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.HIGH,
    "unknown": Severity.INFO,
}


def available() -> bool:
    return shutil.which("nuclei") is not None


def parse_jsonl(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info", {})
        template = item.get("template-id", item.get("templateID", "nuclei"))
        severity = _SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        classification = info.get("classification") or {}
        cwe_ids = classification.get("cwe-id") or []
        cwe = ", ".join(c.upper() for c in cwe_ids) if isinstance(cwe_ids, list) else str(cwe_ids)
        findings.append(
            Finding(
                check=f"nuclei:{template}",
                title=str(info.get("name", template)),
                severity=severity,
                confidence="firm",
                description=" ".join(info.get("tags", [])) if isinstance(info.get("tags"), list) else "",
                evidence=str(item.get("matched-at", item.get("matched", ""))),
                url=str(item.get("host", item.get("matched-at", ""))),
                cwe=cwe,
            )
        )
    return findings


def run(target: str, *, timeout: int = 600, extra_args=None) -> list[Finding]:
    if not available():
        raise RuntimeError("nuclei not found on PATH (https://github.com/projectdiscovery/nuclei)")
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color"]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return parse_jsonl(proc.stdout)
