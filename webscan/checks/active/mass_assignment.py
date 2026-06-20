"""Detect mass assignment by injecting privileged fields into POST bodies.

Derived from the cybersecurity skills 'exploiting-mass-assignment-in-rest-apis'
and 'testing-api-for-mass-assignment-vulnerability'.
"""

from __future__ import annotations

import secrets

import requests

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity


class MassAssignmentCheck(ActiveCheck):
    name = "mass-assignment"
    description = "Detects mass assignment (privileged fields accepted and reflected)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        if point.method != "POST":
            return []
        canary = f"wvsadmin{secrets.token_hex(3)}"
        extra = {"role": canary, "is_admin": "true", "isAdmin": "true", "admin": "true"}
        added = {k: v for k, v in extra.items() if k not in point.params}
        if "role" not in added:
            return []
        values = dict(point.params)
        values.update(added)
        try:
            resp = client.request("POST", point.url, data=values, allow_redirects=False)
        except requests.RequestException:
            return []
        if canary in (resp.text or ""):
            return [
                self.finding(
                    title="Possible mass assignment (privileged field accepted)",
                    severity=Severity.MEDIUM,
                    confidence="tentative",
                    description="An unexpected 'role' field was accepted and reflected, suggesting unguarded binding.",
                    evidence=f"injected role={canary} reflected in the response",
                    remediation="Bind only an explicit allow-list of fields; never trust client-supplied roles.",
                    url=point.url,
                    param=point.param,
                )
            ]
        return []
