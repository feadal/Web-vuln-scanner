"""Report headers that leak the server software and its version."""

from __future__ import annotations

import re

from webscan.checks.base import Check
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


class ServerDisclosureCheck(Check):
    name = "server-disclosure"
    description = "Ищет раскрытие версий ПО в заголовках (Server, X-Powered-By, ...)"

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
                    title=f"Заголовок {label} раскрывает технологию"
                    + (": версия видна" if has_version else ""),
                    severity=Severity.LOW if has_version else Severity.INFO,
                    description=(
                        "Раскрытие точной версии упрощает атакующему подбор "
                        "известных уязвимостей."
                    ),
                    evidence=f"{label}: {value}",
                    remediation=f"Уберите или обезличьте заголовок {label}.",
                    url=resp.url,
                )
            )
        return findings
