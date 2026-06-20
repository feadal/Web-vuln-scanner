"""Server-side request forgery detection (cloud metadata + canary reflection)."""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import (
    SSRF_CANARY_PAYLOAD,
    SSRF_METADATA_PAYLOADS,
    SSRF_PARAM_NAMES,
    match_ssrf_canary,
    match_ssrf_metadata,
)


class SsrfCheck(ActiveCheck):
    name = "ssrf"
    description = "Detects server-side request forgery (cloud metadata + canary reflection)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        if not self._is_candidate(point):
            return []

        for payload in SSRF_METADATA_PAYLOADS:
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            hit = match_ssrf_metadata(resp.text or "")
            if hit:
                return [
                    self.finding(
                        title="SSRF to cloud metadata endpoint",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="The server fetched the instance metadata service, exposing cloud credentials.",
                        evidence=f"Metadata signature '{hit}' via '{point.param}'",
                        remediation="Block requests to link-local/internal addresses; allow-list outbound hosts.",
                        url=point.url,
                        param=point.param,
                    )
                ]

        resp = self.send(client, point, SSRF_CANARY_PAYLOAD)
        if resp is not None and match_ssrf_canary(resp.text or ""):
            return [
                self.finding(
                    title="Server-side request forgery (external fetch reflected)",
                    severity=Severity.HIGH,
                    confidence="firm",
                    description="The parameter made the server fetch an external URL and reflect its content.",
                    evidence=f"Fetched http://example.com/ content via '{point.param}'",
                    remediation="Allow-list outbound destinations; never fetch user-supplied URLs directly.",
                    url=point.url,
                    param=point.param,
                )
            ]
        return []

    def _is_candidate(self, point: InjectionPoint) -> bool:
        if point.param.lower() in SSRF_PARAM_NAMES:
            return True
        value = point.params.get(point.param, "")
        return value.startswith(("http://", "https://", "//"))
