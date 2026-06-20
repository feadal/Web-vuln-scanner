"""A small nuclei-style YAML template engine.

Templates describe HTTP requests and matchers (status / word / regex) in YAML,
so detections can be added without writing Python. The matcher logic is pure and
testable; loading YAML needs the optional 'templates' extra (pyyaml).
"""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass, field
from pathlib import Path

from webscan.models import Finding, Severity

_BUILTIN_DIR = Path(__file__).resolve().parent / "templates"

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.HIGH,
}


@dataclass
class Template:
    id: str
    name: str
    severity: Severity
    cwe: str = ""
    requests: list = field(default_factory=list)


def available() -> bool:
    return importlib.util.find_spec("yaml") is not None


def parse_template(data: dict) -> Template:
    info = data.get("info", {}) or {}
    classification = info.get("classification", {}) or {}
    cwe = classification.get("cwe-id", "") or info.get("cwe", "")
    if isinstance(cwe, list):
        cwe = ", ".join(c.upper() for c in cwe)
    return Template(
        id=str(data.get("id", "template")),
        name=str(info.get("name", data.get("id", "template"))),
        severity=_SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO),
        cwe=str(cwe).upper() if cwe else "",
        requests=data.get("requests", data.get("http", [])) or [],
    )


def load_templates(path) -> list[Template]:
    import yaml

    directory = Path(path) if path else _BUILTIN_DIR
    templates: list[Template] = []
    for file in sorted(directory.glob("*.y*ml")):
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            templates.append(parse_template(data))
    return templates


def _part(response, part: str) -> str:
    if part == "header" or part == "all_headers":
        return "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    return response.text or ""


def match_one(matcher: dict, response) -> bool:
    mtype = matcher.get("type")
    negative = bool(matcher.get("negative", False))
    condition = matcher.get("condition", "or")
    result = False

    if mtype == "status":
        result = response.status_code in matcher.get("status", [])
    elif mtype == "word":
        text = _part(response, matcher.get("part", "body"))
        words = matcher.get("words", [])
        hits = [w for w in words if w in text]
        result = len(hits) == len(words) if condition == "and" else bool(hits)
    elif mtype == "regex":
        text = _part(response, matcher.get("part", "body"))
        regexes = matcher.get("regex", [])
        hits = [r for r in regexes if re.search(r, text)]
        result = len(hits) == len(regexes) if condition == "and" else bool(hits)

    return (not result) if negative else result


def evaluate_matchers(matchers: list, condition: str, response) -> bool:
    if not matchers:
        return False
    results = [match_one(m, response) for m in matchers]
    return all(results) if condition == "and" else any(results)


def run_template(template: Template, base_url: str, client) -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    for req in template.requests:
        method = str(req.get("method", "GET")).upper()
        condition = req.get("matchers-condition", "or")
        matchers = req.get("matchers", [])
        for raw_path in req.get("path", []):
            url = raw_path.replace("{{BaseURL}}", base)
            try:
                resp = client.request(method, url, allow_redirects=False)
            except Exception:
                continue
            if evaluate_matchers(matchers, condition, resp):
                findings.append(
                    Finding(
                        check=f"template:{template.id}",
                        title=template.name,
                        severity=template.severity,
                        confidence="firm",
                        description="Matched a YAML detection template.",
                        evidence=url,
                        url=url,
                        cwe=template.cwe,
                    )
                )
                return findings
    return findings
