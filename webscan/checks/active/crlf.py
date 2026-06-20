"""CRLF / HTTP response header injection detection."""

from __future__ import annotations

import secrets

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import crlf_payloads


class CrlfCheck(ActiveCheck):
    name = "crlf"
    description = "Detects CRLF / HTTP response header injection"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        token = secrets.token_hex(3)
        for payload, header_name, header_value in crlf_payloads(token):
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            if resp.headers.get(header_name) == header_value:
                return [
                    self.finding(
                        title="CRLF injection (HTTP response header injection)",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="Newlines in the parameter inject arbitrary response headers.",
                        evidence=f"Injected header {header_name}:{header_value} via '{point.param}'",
                        remediation="Strip CR/LF from values placed into response headers.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []
