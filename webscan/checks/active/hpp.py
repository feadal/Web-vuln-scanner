"""HTTP Parameter Pollution detection.

Derived from the cybersecurity skill 'performing-http-parameter-pollution-attack'.
Sends the parameter twice; if both values end up reflected/used, the app handles
duplicate parameters inconsistently (a tentative signal worth manual review).
"""

from __future__ import annotations

import requests

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity


class HppCheck(ActiveCheck):
    name = "hpp"
    description = "Detects HTTP parameter pollution (duplicate parameters both used)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        a, b = "wvshppA1", "wvshppB2"
        pairs = [(k, v) for k, v in point.params.items() if k != point.param]
        pairs.append((point.param, a))
        pairs.append((point.param, b))
        try:
            if point.method == "POST":
                resp = client.request("POST", point.url, data=pairs, allow_redirects=False)
            else:
                resp = client.request("GET", point.url, params=pairs, allow_redirects=False)
        except requests.RequestException:
            return []

        body = resp.text or ""
        if a in body and b in body:
            return [
                self.finding(
                    title="HTTP parameter pollution",
                    severity=Severity.MEDIUM,
                    confidence="tentative",
                    description="Both duplicate parameter values are reflected, so back-end components may disagree on which to use.",
                    evidence=f"both values of '{point.param}' reflected",
                    remediation="Normalise duplicate parameters consistently across all layers.",
                    url=point.url,
                    param=point.param,
                )
            ]
        return []
