"""XML external entity (XXE) detection for XML-bearing parameters."""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import match_passwd, xxe_payload


class XxeCheck(ActiveCheck):
    name = "xxe"
    description = "Detects XML external entity injection (XML parameters)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        value = point.params.get(point.param, "")
        if "<" not in value and "xml" not in point.param.lower():
            return []
        resp = self.send(client, point, xxe_payload())
        if resp is None:
            return []
        hit = match_passwd(resp.text or "")
        if hit:
            return [
                self.finding(
                    title="XML external entity injection (XXE)",
                    severity=Severity.HIGH,
                    confidence="firm",
                    description="An external entity was resolved, reading a local file off the server.",
                    evidence=f"/etc/passwd disclosed via '{point.param}': {hit}",
                    remediation="Disable external entities and DOCTYPE in the XML parser.",
                    url=point.url,
                    param=point.param,
                )
            ]
        return []
