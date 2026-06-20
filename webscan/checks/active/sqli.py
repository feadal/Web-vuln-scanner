"""SQL injection detection (error-based, plus a boolean differential).

Error-based: a single quote often breaks an unparameterised query and leaks a
database error message — a firm signal. Boolean-based: a TRUE vs FALSE payload
pair that changes the response in opposite directions is a tentative signal a
human should confirm. Neither payload reads, writes or destroys data.
"""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import (
    SQLI_ERROR_PAYLOADS,
    SQLI_FALSE_PAYLOAD,
    SQLI_TRUE_PAYLOAD,
    match_sql_error,
)


class SqlInjectionCheck(ActiveCheck):
    name = "sqli"
    description = "Detects SQL injection (database errors + boolean differential)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        error = self._error_based(point, client)
        if error:
            return [error]
        boolean = self._boolean_based(point, client)
        return [boolean] if boolean else []

    def _error_based(self, point, client) -> Finding | None:
        for payload in SQLI_ERROR_PAYLOADS:
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            fragment = match_sql_error(resp.text or "")
            if fragment:
                return self.finding(
                    title="Error-based SQL injection",
                    severity=Severity.HIGH,
                    confidence="firm",
                    description="A crafted quote produced a database error, indicating unsanitised input.",
                    evidence=f"DB error on '{point.param}': {fragment}",
                    remediation="Use parameterised queries / prepared statements.",
                    url=point.url,
                    param=point.param,
                )
        return None

    def _boolean_based(self, point, client) -> Finding | None:
        base = self.send(client, point, point.params.get(point.param, "1"))
        truthy = self.send(client, point, SQLI_TRUE_PAYLOAD)
        falsy = self.send(client, point, SQLI_FALSE_PAYLOAD)
        if not all((base, truthy, falsy)):
            return None

        base_len, true_len, false_len = (len(r.text or "") for r in (base, truthy, falsy))
        # TRUE resembles the baseline while FALSE diverges clearly.
        true_like_base = abs(true_len - base_len) <= max(40, base_len * 0.02)
        false_diverges = abs(false_len - true_len) > max(80, true_len * 0.05)
        if true_like_base and false_diverges:
            return self.finding(
                title="Possible boolean-based SQL injection",
                severity=Severity.MEDIUM,
                confidence="tentative",
                description="TRUE/FALSE payloads changed the response length in a SQL-like pattern.",
                evidence=f"len base={base_len} true={true_len} false={false_len} on '{point.param}'",
                remediation="Use parameterised queries; verify manually before acting.",
                url=point.url,
                param=point.param,
            )
        return None
