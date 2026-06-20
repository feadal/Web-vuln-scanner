"""Detect permissive CORS configurations."""

from __future__ import annotations

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity
from webscan.payloads import CORS_EVIL_ORIGIN


class CorsCheck(PassiveCheck):
    name = "cors"
    description = "Checks for permissive CORS (reflected Origin, credentials)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.client.try_get(ctx.target, headers={"Origin": CORS_EVIL_ORIGIN})
        if resp is None:
            return []
        acao = resp.headers.get("Access-Control-Allow-Origin")
        if not acao:
            return []
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if acao == CORS_EVIL_ORIGIN:
            return [
                self.finding(
                    title="CORS reflects an arbitrary Origin"
                    + (" with credentials" if acac else ""),
                    severity=Severity.HIGH if acac else Severity.MEDIUM,
                    description="The server echoes any Origin, letting other sites read authenticated responses.",
                    evidence=f"Access-Control-Allow-Origin: {acao}"
                    + (" + Allow-Credentials: true" if acac else ""),
                    remediation="Allow-list specific trusted origins; never reflect the Origin.",
                    url=ctx.target,
                )
            ]
        if acao == "*":
            return [
                self.finding(
                    title="CORS allows any origin (wildcard)",
                    severity=Severity.LOW,
                    description="Access-Control-Allow-Origin is '*', exposing responses to any site.",
                    evidence="Access-Control-Allow-Origin: *",
                    remediation="Restrict CORS to specific trusted origins if responses are sensitive.",
                    url=ctx.target,
                )
            ]
        return []
