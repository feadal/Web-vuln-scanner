"""Report headers that leak the server software and its version."""

from __future__ import annotations

import re

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

# Headers that commonly disclose technology / version details.
_DISCLOSURE_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
    "x-generator": "X-Generator",
}

_VERSION_RE = re.compile(r"\d+\.\d+")


class ServerDisclosureCheck(PassiveCheck):
    name = "server-disclosure"
    description = "Looks for software/version disclosure in headers (Server, X-Powered-By, ...)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []

        findings: list[Finding] = []
        for key, label in _DISCLOSURE_HEADERS.items():
            value = resp.headers.get(key)
            if not value:
                continue
            has_version = bool(_VERSION_RE.search(value))
            findings.append(
                self.finding(
                    title=f"{label} header discloses technology"
                    + (" version" if has_version else ""),
                    severity=Severity.LOW if has_version else Severity.INFO,
                    description=(
                        "Disclosing the exact version makes it easier for an attacker "
                        "to look up known vulnerabilities."
                    ),
                    evidence=f"{label}: {value}",
                    remediation=f"Remove or obfuscate the {label} header.",
                    url=resp.url,
                )
            )
        return findings
