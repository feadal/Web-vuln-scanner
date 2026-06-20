"""Reflected XSS detection.

Injects a unique token wrapped in HTML metacharacters. If the metacharacters
come back un-encoded next to the token, the parameter reflects raw markup into
the page — the precondition for reflected XSS. The probe does not execute.
"""

from __future__ import annotations

import secrets

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import xss_probe, xss_reflected_raw


class ReflectedXssCheck(ActiveCheck):
    name = "xss"
    description = "Detects reflected XSS (un-encoded HTML reflection of input)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        token = secrets.token_hex(3)
        resp = self.send(client, point, xss_probe(token))
        if resp is None or not resp.text:
            return []
        if not xss_reflected_raw(resp.text, token):
            return []
        return [
            self.finding(
                title="Reflected cross-site scripting (XSS)",
                severity=Severity.HIGH,
                confidence="firm",
                description=(
                    "User input is reflected into the HTML response without encoding, "
                    "so injected markup/script would run in the victim's browser."
                ),
                evidence=f"Probe reflected un-encoded in parameter '{point.param}'",
                remediation="Context-aware output encoding; add a strict Content-Security-Policy.",
                url=point.url,
                param=point.param,
            )
        ]
