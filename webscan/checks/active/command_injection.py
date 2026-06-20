"""OS command injection detection (arithmetic-echo, non-destructive).

Each probe asks the shell to print ``wvs<A*B>end`` where the product is computed
by the shell, not present literally in the payload. If that exact string appears
in the response, our input reached a shell. The command only echoes a number —
it does not read, write or damage anything.
"""

from __future__ import annotations

import secrets

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import cmdi_expected, cmdi_payloads


class CommandInjectionCheck(ActiveCheck):
    name = "cmd-injection"
    description = "Detects OS command injection via arithmetic-echo probes"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        a = secrets.randbelow(900) + 100
        b = secrets.randbelow(900) + 100
        left, right = "wvs", "end"
        expected = cmdi_expected(a, b, left, right)

        for payload in cmdi_payloads(a, b, left, right):
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            if expected in (resp.text or ""):
                return [
                    self.finding(
                        title="OS command injection",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="Injected shell syntax was executed (an arithmetic echo returned the product).",
                        evidence=f"Shell evaluated probe on '{point.param}' -> {expected}",
                        remediation="Never pass user input to a shell; use argument arrays / safe APIs.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []
