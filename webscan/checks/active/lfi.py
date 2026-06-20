"""Local file inclusion detection via the PHP base64 filter wrapper."""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import LFI_PAYLOADS, LFI_PHP_MARKER


class LfiCheck(ActiveCheck):
    name = "lfi"
    description = "Detects local file inclusion (PHP source disclosure via php://filter)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        for payload in LFI_PAYLOADS:
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            if LFI_PHP_MARKER in (resp.text or ""):
                return [
                    self.finding(
                        title="Local file inclusion (PHP source disclosure)",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="php://filter returned base64-encoded PHP source, confirming file inclusion.",
                        evidence=f"PHP source disclosed via '{point.param}' ({payload})",
                        remediation="Reject wrappers and path separators; use an allow-list of includable files.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []
