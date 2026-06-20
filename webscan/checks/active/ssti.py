"""Server-side template injection detection via arithmetic evaluation."""

from __future__ import annotations

import secrets

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import SSTI_FP_PROBE, ssti_engine, ssti_expected, ssti_payloads


class SstiCheck(ActiveCheck):
    name = "ssti"
    description = "Detects server-side template injection (template math evaluation)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        a = secrets.randbelow(900) + 100
        b = secrets.randbelow(900) + 100
        left, right = "ssti", "end"
        expected = ssti_expected(a, b, left, right)
        for payload in ssti_payloads(a, b, left, right):
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            if expected in (resp.text or ""):
                engine = ""
                fp = self.send(client, point, SSTI_FP_PROBE)
                if fp is not None:
                    engine = ssti_engine(fp.text or "")
                title = "Server-side template injection (SSTI)" + (f" — {engine}" if engine else "")
                evidence = f"Template math evaluated on '{point.param}' -> {expected}"
                if engine:
                    evidence += f"; engine: {engine}"
                return [
                    self.finding(
                        title=title,
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="A template expression was evaluated by the server, often a path to RCE.",
                        evidence=evidence,
                        remediation="Never render user input as a template; sandbox or escape it.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []
