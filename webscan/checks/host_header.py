"""Detect Host header injection / reflection."""

from __future__ import annotations

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity
from webscan.payloads import HOST_EVIL


class HostHeaderCheck(PassiveCheck):
    name = "host-header"
    description = "Checks whether a spoofed Host / X-Forwarded-Host is reflected"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.client.try_get(
            ctx.target,
            headers={"Host": HOST_EVIL, "X-Forwarded-Host": HOST_EVIL},
            allow_redirects=False,
        )
        if resp is None:
            return []
        location = resp.headers.get("Location", "")
        body = (resp.text or "")[:8000]
        if HOST_EVIL in location or HOST_EVIL in body:
            where = "redirect Location" if HOST_EVIL in location else "response body"
            return [
                self.finding(
                    title="Host header is reflected (injection)",
                    severity=Severity.MEDIUM,
                    description="A spoofed Host is reflected, enabling cache poisoning or password-reset poisoning.",
                    evidence=f"'{HOST_EVIL}' reflected in {where}",
                    remediation="Validate the Host header against an allow-list; don't build URLs from it.",
                    url=ctx.target,
                )
            ]
        return []
