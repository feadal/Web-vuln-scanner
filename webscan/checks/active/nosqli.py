"""NoSQL injection detection (database error signatures)."""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import NOSQLI_PAYLOADS, match_nosql_error


class NoSqlInjectionCheck(ActiveCheck):
    name = "nosqli"
    description = "Detects NoSQL injection via database error signatures"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        for payload in NOSQLI_PAYLOADS:
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            fragment = match_nosql_error(resp.text or "")
            if fragment:
                return [
                    self.finding(
                        title="NoSQL injection",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="A NoSQL operator produced a database error, indicating unsanitised input.",
                        evidence=f"NoSQL error on '{point.param}': {fragment}",
                        remediation="Validate types and reject query operators in user input.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []
