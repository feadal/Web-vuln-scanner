"""Detect dangerous enabled HTTP methods."""

from __future__ import annotations

import requests

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity
from webscan.payloads import DANGEROUS_METHODS


class HttpMethodsCheck(PassiveCheck):
    name = "http-methods"
    description = "Checks for dangerous enabled HTTP methods (PUT, DELETE, TRACE)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.client.request("OPTIONS", ctx.target)
        except requests.RequestException:
            return []
        allow = resp.headers.get("Allow", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        dangerous = sorted(methods & DANGEROUS_METHODS)
        if not dangerous:
            return []
        severity = Severity.MEDIUM if "TRACE" in dangerous else Severity.LOW
        return [
            self.finding(
                title=f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                severity=severity,
                description="Methods like PUT/DELETE/TRACE can allow file changes or cross-site tracing (XST).",
                evidence=f"Allow: {allow}",
                remediation="Disable unused methods at the server; never allow TRACE.",
                url=ctx.target,
            )
        ]
