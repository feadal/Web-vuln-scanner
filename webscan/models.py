"""Core data structures shared across the scanner and its checks."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    import requests

    from webscan.http_client import HttpClient


class Severity(enum.Enum):
    """Severity levels ordered from least to most important."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]


@dataclass
class Finding:
    """A single issue reported by a check."""

    check: str
    title: str
    severity: Severity
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "url": self.url,
        }


@dataclass
class ScanContext:
    """Everything a check needs to do its work.

    The scanner fetches the target's landing page once and shares the response
    (and its decoded HTML body) with every check, so most checks make zero
    additional requests. Checks that need more requests use ``client``.
    """

    target: str
    client: "HttpClient"
    base_response: Optional["requests.Response"] = None
    base_html: str = ""


@dataclass
class ScanResult:
    """Aggregated output of a full scan."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered from highest to lowest severity, stable by check name."""
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.check))

    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "counts": self.counts(),
            "errors": self.errors,
        }
