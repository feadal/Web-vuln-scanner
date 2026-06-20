"""Context-aware reflected XSS detection.

Step 1: inject a plain marker and find where it is reflected, classifying the
context (HTML text, attribute, JS string, comment). Step 2: send a payload that
breaks out of exactly that context and confirm the breakout characters survive
un-encoded. This mirrors dalfox's context-based approach and cuts false
positives versus blind substring matching.
"""

from __future__ import annotations

import secrets

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import classify_xss_context, xss_context_payload, xss_reflected_raw


class ReflectedXssCheck(ActiveCheck):
    name = "xss"
    description = "Detects reflected XSS with context-aware payloads"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        marker = "wvs" + secrets.token_hex(3)
        probe = self.send(client, point, marker)
        if probe is None or marker not in (probe.text or ""):
            return []

        context = classify_xss_context(probe.text, marker)
        token = secrets.token_hex(3)
        payload, breakout = xss_context_payload(context, token)
        resp = self.send(client, point, payload)
        if resp is None:
            return []
        body = resp.text or ""

        if breakout and breakout in body:
            return [self._finding(point, context, confidence="firm")]
        if xss_reflected_raw(body, token):
            return [self._finding(point, context or "html", confidence="firm")]
        return []

    def _finding(self, point, context, confidence):
        return self.finding(
            title=f"Reflected cross-site scripting (XSS) — {context} context",
            severity=Severity.HIGH,
            confidence=confidence,
            description="User input is reflected without context-correct encoding, allowing script injection.",
            evidence=f"Breakout survived un-encoded in parameter '{point.param}' ({context})",
            remediation="Context-aware output encoding; add a strict Content-Security-Policy.",
            url=point.url,
            param=point.param,
        )
