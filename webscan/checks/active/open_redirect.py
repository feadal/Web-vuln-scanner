"""Open redirect detection.

Injects a benign external URL into redirect-like parameters and checks whether
the server sends us there via a Location header. Redirects are followed with
``allow_redirects=False`` so the probe never actually leaves the target.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlparse

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import REDIRECT_PARAM_NAMES


class OpenRedirectCheck(ActiveCheck):
    name = "open-redirect"
    description = "Detects open redirects in redirect-like parameters"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        if not self._is_candidate(point):
            return []

        token = secrets.token_hex(3)
        host = f"wvs-{token}.example.org"
        for payload in (f"https://{host}/", f"//{host}/"):
            resp = self.send(client, point, payload, allow_redirects=False)
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if _redirects_to(location, host):
                return [
                    self.finding(
                        title="Open redirect",
                        severity=Severity.MEDIUM,
                        confidence="firm",
                        description="The parameter controls the redirect target, allowing redirection to any site.",
                        evidence=f"Location -> {location} (param '{point.param}')",
                        remediation="Allow-list redirect targets or use relative paths only.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []

    def _is_candidate(self, point: InjectionPoint) -> bool:
        if point.param.lower() in REDIRECT_PARAM_NAMES:
            return True
        # Or a parameter whose current value already looks like a URL/path.
        value = point.params.get(point.param, "")
        return value.startswith(("http://", "https://", "/"))


def _redirects_to(location: str, host: str) -> bool:
    if not location:
        return False
    if location.startswith(f"//{host}"):
        return True
    return urlparse(location).hostname == host
