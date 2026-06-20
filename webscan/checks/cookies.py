"""Flag cookies set without the Secure / HttpOnly / SameSite hardening flags."""

from __future__ import annotations

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity


class CookieFlagsCheck(PassiveCheck):
    name = "cookies"
    description = "Checks Secure / HttpOnly / SameSite flags on Set-Cookie"

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
                        title=f"Cookie '{name}' is missing the HttpOnly flag",
                        severity=Severity.MEDIUM,
                        description="The cookie is readable from JavaScript and can be stolen via XSS.",
                        evidence=raw,
                        remediation="Add the HttpOnly attribute if the cookie is not needed client-side.",
                        url=resp.url,
                    )
                )
            if is_https and "secure" not in attrs:
                findings.append(
                    self.finding(
                        title=f"Cookie '{name}' is missing the Secure flag",
                        severity=Severity.MEDIUM,
                        description="The cookie may be sent over an unencrypted HTTP connection.",
                        evidence=raw,
                        remediation="Add the Secure attribute so the cookie is sent over HTTPS only.",
                        url=resp.url,
                    )
                )
            if "samesite" not in attrs:
                findings.append(
                    self.finding(
                        title=f"Cookie '{name}' is missing the SameSite attribute",
                        severity=Severity.LOW,
                        description="Without SameSite the cookie rides along on cross-site requests (CSRF risk).",
                        evidence=raw,
                        remediation="Set 'SameSite=Lax' or 'SameSite=Strict'.",
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
