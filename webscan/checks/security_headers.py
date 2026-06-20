"""Detect missing or weak HTTP security response headers."""

from __future__ import annotations

from webscan.checks.base import Check
from webscan.models import Finding, ScanContext, Severity

# header -> (severity, human title, remediation)
_EXPECTED_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Отсутствует Content-Security-Policy (CSP)",
        "Задайте политику CSP, ограничивающую источники скриптов/стилей, "
        "чтобы снизить риск XSS и инъекций.",
    ),
    "strict-transport-security": (
        Severity.HIGH,
        "Отсутствует Strict-Transport-Security (HSTS)",
        "Добавьте заголовок HSTS на HTTPS-ответы, например "
        "'max-age=31536000; includeSubDomains'.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Отсутствует X-Content-Type-Options",
        "Установите 'X-Content-Type-Options: nosniff', чтобы запретить браузеру "
        "угадывать MIME-тип.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Отсутствует защита от clickjacking (X-Frame-Options / CSP frame-ancestors)",
        "Задайте 'X-Frame-Options: DENY' или директиву CSP 'frame-ancestors'.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Отсутствует Referrer-Policy",
        "Установите 'Referrer-Policy: strict-origin-when-cross-origin' или строже.",
    ),
}


class SecurityHeadersCheck(Check):
    name = "security-headers"
    description = "Проверяет наличие HTTP-заголовков безопасности (CSP, HSTS, ...)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []

        findings: list[Finding] = []
        # requests' header mapping is case-insensitive.
        headers = resp.headers
        is_https = resp.url.lower().startswith("https://")

        for header, (severity, title, remediation) in _EXPECTED_HEADERS.items():
            if header in headers:
                continue
            # HSTS is only meaningful over HTTPS — skip it on plain HTTP targets,
            # the tls check already flags the lack of HTTPS.
            if header == "strict-transport-security" and not is_https:
                continue
            # clickjacking protection can also be provided via CSP frame-ancestors.
            if header == "x-frame-options" and _has_frame_ancestors(headers):
                continue
            findings.append(
                self.finding(
                    title=title,
                    severity=severity,
                    description=f"Ответ не содержит заголовок '{header}'.",
                    remediation=remediation,
                    url=resp.url,
                )
            )

        findings.extend(self._weak_values(headers, resp.url))
        return findings

    def _weak_values(self, headers, url: str) -> list[Finding]:
        out: list[Finding] = []
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            max_age = _parse_max_age(hsts)
            if max_age is not None and max_age < 15552000:  # < 180 days
                out.append(
                    self.finding(
                        title="Слишком короткий max-age у HSTS",
                        severity=Severity.LOW,
                        description=f"HSTS max-age={max_age} меньше рекомендуемых 6 месяцев.",
                        evidence=hsts,
                        remediation="Увеличьте max-age минимум до 15552000 (180 дней).",
                        url=url,
                    )
                )
        return out


def _has_frame_ancestors(headers) -> bool:
    csp = headers.get("content-security-policy", "").lower()
    return "frame-ancestors" in csp


def _parse_max_age(value: str):
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None
