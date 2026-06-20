"""Detect GraphQL endpoints with introspection enabled.

Derived from the cybersecurity skill 'performing-graphql-introspection-attack'.
"""

from __future__ import annotations

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/query", "/v1/graphql"]
_QUERY = {"query": "{__schema{queryType{name}}}"}
_MARKERS = ("__schema", "queryType", "\"data\"")


class GraphqlIntrospectionCheck(PassiveCheck):
    name = "graphql"
    description = "Detects GraphQL endpoints with introspection enabled"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _PATHS:
            url = ctx.client.join(ctx.target, path)
            resp = ctx.client.try_get(url, params=_QUERY, allow_redirects=False)
            if resp is None or resp.status_code >= 400:
                continue
            body = resp.text or ""
            if "__schema" in body or ("queryType" in body and '"data"' in body):
                findings.append(
                    self.finding(
                        title="GraphQL introspection is enabled",
                        severity=Severity.MEDIUM,
                        confidence="firm",
                        description="Introspection exposes the full schema, aiding attackers in mapping the API.",
                        evidence=f"Schema returned by {url}",
                        remediation="Disable introspection in production.",
                        url=url,
                    )
                )
                break
        return findings
