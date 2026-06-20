"""Detect missing or weak HTTP security response headers."""

from __future__ import annotations

from webscan.checks.base import Check
from webscan.models import Finding, ScanContext, Severity

# header -> (severity, human title, remediation)
_EXPECTED_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Missing Content-Security-Policy (CSP) header",
        "Define a CSP that restricts script/style sources to reduce the risk of "
        "XSS and injection.",
    ),
    "strict-transport-security": (
        Severity.HIGH,
        "Missing Strict-Transport-Security (HSTS) header",
        "Add an HSTS header to HTTPS responses, e.g. "
        "'max-age=31536000; includeSubDomains'.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing X-Content-Type-Options header",
        "Set 'X-Content-Type-Options: nosniff' to stop the browser from MIME-sniffing.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
        "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Missing Referrer-Policy header",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
}


class SecurityHeadersCheck(Check):
    name = "security-headers"
    description = "Checks for HTTP security headers (CSP, HSTS, ...)"

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
                    description=f"The response does not set the '{header}' header.",
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
                        title="HSTS max-age is too short",
                        severity=Severity.LOW,
                        description=f"HSTS max-age={max_age} is below the recommended 6 months.",
                        evidence=hsts,
                        remediation="Increase max-age to at least 15552000 (180 days).",
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
