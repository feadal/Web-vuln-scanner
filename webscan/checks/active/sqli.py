"""SQL injection detection: error-based, boolean differential, and time-based blind."""

from __future__ import annotations

from webscan import tamper as tamper_mod
from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import (
    SQLI_ERROR_PAYLOADS,
    SQLI_FALSE_PAYLOAD,
    SQLI_TRUE_PAYLOAD,
    match_sql_error,
    sql_db_fingerprint,
    sqli_time_payloads,
    time_based_triggered,
)

_SLEEP = 3


class SqlInjectionCheck(ActiveCheck):
    name = "sqli"
    description = "Detects SQL injection (errors, boolean differential, time-based blind)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        error = self._error_based(point, client)
        if error:
            return [error]
        timed = self._time_based(point, client)
        if timed:
            return [timed]
        boolean = self._boolean_based(point, client)
        return [boolean] if boolean else []

    def _error_based(self, point, client) -> Finding | None:
        payloads = list(SQLI_ERROR_PAYLOADS)
        if self.tamper:
            payloads += [tamper_mod.chain(self.tamper, p) for p in SQLI_ERROR_PAYLOADS]
        for payload in payloads:
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            fragment = match_sql_error(resp.text or "")
            if fragment:
                db = sql_db_fingerprint(resp.text or "")
                title = f"Error-based SQL injection ({db})" if db else "Error-based SQL injection"
                return self.finding(
                    title=title,
                    severity=Severity.HIGH,
                    confidence="firm",
                    description="A crafted quote produced a database error, indicating unsanitised input.",
                    evidence=f"DB error on '{point.param}': {fragment}",
                    remediation="Use parameterised queries / prepared statements.",
                    url=point.url,
                    param=point.param,
                )
        return None

    def _time_based(self, point, client) -> Finding | None:
        baseline = self.send(client, point, point.params.get(point.param, "1"))
        if baseline is None:
            return None
        base_t = baseline.elapsed.total_seconds()
        for payload in sqli_time_payloads(_SLEEP):
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            if time_based_triggered(base_t, resp.elapsed.total_seconds(), _SLEEP):
                confirm = self.send(client, point, payload)
                if confirm is not None and time_based_triggered(
                    base_t, confirm.elapsed.total_seconds(), _SLEEP
                ):
                    return self.finding(
                        title="Time-based blind SQL injection",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="A sleep payload reproducibly delayed the response.",
                        evidence=f"~{_SLEEP}s delay on '{point.param}' with {payload}",
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
