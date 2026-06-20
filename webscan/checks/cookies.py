"""Flag cookies set without the Secure / HttpOnly / SameSite hardening flags."""

from __future__ import annotations

from webscan.checks.base import Check
from webscan.models import Finding, ScanContext, Severity


class CookieFlagsCheck(Check):
    name = "cookies"
    description = "Проверяет флаги Secure / HttpOnly / SameSite у Set-Cookie"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []

        # A single response may carry several Set-Cookie headers.
        raw_cookies = _raw_set_cookie_headers(resp)
        if not raw_cookies:
            return []

        is_https = resp.url.lower().startswith("https://")
        findings: list[Finding] = []

        for raw in raw_cookies:
            name = _cookie_name(raw)
            attrs = _cookie_attrs(raw)

            if "httponly" not in attrs:
                findings.append(
                    self.finding(
                        title=f"Cookie '{name}' без флага HttpOnly",
                        severity=Severity.MEDIUM,
                        description="Cookie доступна из JavaScript и может быть украдена при XSS.",
                        evidence=raw,
                        remediation="Добавьте атрибут HttpOnly, если cookie не нужна на клиенте.",
                        url=resp.url,
                    )
                )
            if is_https and "secure" not in attrs:
                findings.append(
                    self.finding(
                        title=f"Cookie '{name}' без флага Secure",
                        severity=Severity.MEDIUM,
                        description="Cookie может уйти по незашифрованному HTTP-соединению.",
                        evidence=raw,
                        remediation="Добавьте атрибут Secure, чтобы cookie слалась только по HTTPS.",
                        url=resp.url,
                    )
                )
            if "samesite" not in attrs:
                findings.append(
                    self.finding(
                        title=f"Cookie '{name}' без атрибута SameSite",
                        severity=Severity.LOW,
                        description="Без SameSite cookie участвует в межсайтовых запросах (риск CSRF).",
                        evidence=raw,
                        remediation="Задайте 'SameSite=Lax' или 'SameSite=Strict'.",
                        url=resp.url,
                    )
                )

        return findings


def _raw_set_cookie_headers(resp) -> list[str]:
    """Return every Set-Cookie header line, handling multiple cookies."""
    # urllib3's HTTPHeaderDict (used by requests) joins repeated headers with
    # ", " which is ambiguous for cookies. Prefer the raw header list if present.
    raw = getattr(resp, "raw", None)
    if raw is not None and getattr(raw, "headers", None) is not None:
        getlist = getattr(raw.headers, "getlist", None) or getattr(
            raw.headers, "get_all", None
        )
        if getlist:
            values = getlist("Set-Cookie")
            if values:
                return list(values)
    single = resp.headers.get("Set-Cookie")
    return [single] if single else []


def _cookie_name(raw: str) -> str:
    return raw.split("=", 1)[0].strip()


def _cookie_attrs(raw: str) -> set[str]:
    parts = raw.split(";")[1:]  # skip the name=value pair
    return {p.strip().split("=", 1)[0].lower() for p in parts if p.strip()}
