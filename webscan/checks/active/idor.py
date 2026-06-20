"""Heuristic IDOR / object-enumeration hint for numeric reference parameters.

Derived from the cybersecurity skills 'exploiting-idor-vulnerabilities' and
'testing-api-for-broken-object-level-authorization'. This is a tentative hint —
true IDOR needs manual confirmation with a second account.
"""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity

_ID_NAMES = ("id", "uid", "user", "account", "order", "doc", "file", "object", "num", "pid")


class IdorCheck(ActiveCheck):
    name = "idor"
    description = "Flags numeric reference params whose neighbours return distinct data"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        value = point.params.get(point.param, "")
        if not value.isdigit():
            return []
        name = point.param.lower()
        if not any(tok in name for tok in _ID_NAMES):
            return []
        n = int(value)

        responses = []
        for candidate in (n, n - 1, n + 1):
            if candidate < 0:
                continue
            resp = self.send(client, point, str(candidate))
            if resp is not None and resp.status_code == 200:
                responses.append(resp.text or "")
        if len(responses) < 2:
            return []
        if len({r for r in responses}) >= 2 and all(len(r) > 80 for r in responses):
            return [
                self.finding(
                    title="Possible IDOR / object enumeration",
                    severity=Severity.LOW,
                    confidence="tentative",
                    description="Neighbouring values of this reference return distinct content without an authorization barrier.",
                    evidence=f"varying '{point.param}' returns distinct 200 responses",
                    remediation="Enforce per-object authorization; verify manually with a second account.",
                    url=point.url,
                    param=point.param,
                )
            ]
        return []
