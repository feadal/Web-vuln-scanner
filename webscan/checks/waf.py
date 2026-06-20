"""Fingerprint a WAF / CDN in front of the target.

Derived from the cybersecurity skill 'performing-web-application-firewall-bypass'.
Informational: knowing the WAF tells you which evasions and rate limits apply.
"""

from __future__ import annotations

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "cf_clearance", "server: cloudflare"]),
    ("Akamai", ["akamaighost", "x-akamai-transformed", "akamai"]),
    ("AWS CloudFront / WAF", ["x-amz-cf-id", "via: cloudfront", "server: cloudfront", "x-amzn-requestid"]),
    ("Imperva Incapsula", ["x-iinfo", "incap_ses", "visid_incap", "x-cdn: incapsula"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"]),
    ("F5 BIG-IP", ["bigipserver", "server: bigip", "x-waf-event"]),
    ("Fastly", ["x-served-by: cache", "x-fastly", "fastly-debug"]),
    ("Barracuda", ["barra_counter_session", "barracuda"]),
    ("Fortinet FortiWeb", ["fortiwafsid", "fortigate"]),
    ("Wordfence", ["wordfence", "x-wf-"]),
    ("ModSecurity", ["mod_security", "modsecurity"]),
]


class WafCheck(PassiveCheck):
    name = "waf"
    description = "Fingerprints a WAF / CDN from response headers and cookies"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []
        haystack = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        for cookie in resp.cookies:
            haystack += f"\nset-cookie: {cookie.name}".lower()

        for name, markers in _SIGNATURES:
            if any(m in haystack for m in markers):
                return [
                    self.finding(
                        title=f"WAF / CDN detected: {name}",
                        severity=Severity.INFO,
                        confidence="firm",
                        description="A WAF/CDN is in front of the target; expect filtering and rate limiting.",
                        evidence=name,
                        remediation="Informational — tune payload encoding and request rate accordingly.",
                        url=resp.url,
                    )
                ]
        return []
