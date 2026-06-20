"""Forced browsing for exposed admin panels, dashboards and debug endpoints.

Derived from the cybersecurity skill 'bypassing-authentication-with-forced-browsing'.
"""

from __future__ import annotations

import secrets

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_ENDPOINTS = {
    "/admin": (Severity.MEDIUM, "Admin area reachable"),
    "/administrator": (Severity.MEDIUM, "Admin area reachable"),
    "/admin/login": (Severity.MEDIUM, "Admin login reachable"),
    "/phpmyadmin/": (Severity.HIGH, "phpMyAdmin reachable"),
    "/adminer.php": (Severity.HIGH, "Adminer database tool reachable"),
    "/actuator": (Severity.HIGH, "Spring Boot Actuator exposed"),
    "/actuator/env": (Severity.HIGH, "Actuator /env leaks configuration"),
    "/manager/html": (Severity.HIGH, "Tomcat Manager reachable"),
    "/wp-admin/": (Severity.MEDIUM, "WordPress admin reachable"),
    "/console": (Severity.MEDIUM, "Web console reachable"),
    "/debug": (Severity.MEDIUM, "Debug endpoint reachable"),
    "/swagger-ui/": (Severity.LOW, "Swagger UI exposed"),
    "/swagger-ui.html": (Severity.LOW, "Swagger UI exposed"),
    "/graphql": (Severity.LOW, "GraphQL endpoint reachable"),
    "/graphiql": (Severity.LOW, "GraphiQL IDE exposed"),
    "/cpanel": (Severity.MEDIUM, "cPanel reachable"),
}


class ForcedBrowsingCheck(PassiveCheck):
    name = "forced-browsing"
    description = "Probes for exposed admin panels, dashboards and debug endpoints"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if self._catch_all_200(ctx):
            return []
        findings: list[Finding] = []
        for path, (severity, why) in _ENDPOINTS.items():
            url = ctx.client.join(ctx.target, path)
            resp = ctx.client.try_get(url, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code == 200:
                findings.append(
                    self.finding(
                        title=f"Exposed endpoint: {path}",
                        severity=severity,
                        description=why,
                        evidence=f"HTTP 200 at {url}",
                        remediation="Restrict access (auth / IP allow-list) or remove the endpoint.",
                        url=url,
                    )
                )
            elif resp.status_code in (401, 403):
                findings.append(
                    self.finding(
                        title=f"Endpoint present but protected: {path}",
                        severity=Severity.INFO,
                        description=f"{why} (returns {resp.status_code}).",
                        evidence=f"HTTP {resp.status_code} at {url}",
                        url=url,
                    )
                )
        return findings

    def _catch_all_200(self, ctx: ScanContext) -> bool:
        probe = ctx.client.join(ctx.target, "/wvs-" + secrets.token_hex(6))
        resp = ctx.client.try_get(probe, allow_redirects=False)
        return resp is not None and resp.status_code == 200
