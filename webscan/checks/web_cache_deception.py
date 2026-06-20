"""Detect web cache deception.

Derived from the cybersecurity skill 'performing-web-cache-deception-attack'.
Appends a static-looking suffix to the page URL; if the server still returns the
dynamic page and the response looks cacheable, the page may be cached publicly.
"""

from __future__ import annotations

import secrets

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_CACHEABLE_HINTS = ("public", "max-age", "s-maxage")


class WebCacheDeceptionCheck(PassiveCheck):
    name = "web-cache-deception"
    description = "Detects web cache deception (dynamic page served as cacheable static)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        original = ctx.base_response
        if original is None or not (original.text or ""):
            return []
        base = original.url.rstrip("/")
        probe_url = f"{base}/wvs{secrets.token_hex(4)}.css"
        resp = ctx.client.try_get(probe_url, allow_redirects=False)
        if resp is None or resp.status_code != 200:
            return []

        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return []

        if not _similar(resp.text or "", original.text or ""):
            return []

        cache_control = resp.headers.get("Cache-Control", "").lower()
        x_cache = resp.headers.get("X-Cache", "")
        cacheable = any(h in cache_control for h in _CACHEABLE_HINTS) or bool(x_cache)
        severity = Severity.HIGH if cacheable else Severity.MEDIUM
        evidence = f"{probe_url} returned the page as text/html"
        if cache_control:
            evidence += f"; Cache-Control: {cache_control}"
        return [
            self.finding(
                title="Web cache deception (dynamic page served under a static path)",
                severity=severity,
                confidence="firm" if cacheable else "tentative",
                description="A static-looking URL returns the dynamic page; a cache may store and serve it to others.",
                evidence=evidence,
                remediation="Cache by content type from origin headers; don't cache by URL extension alone.",
                url=probe_url,
            )
        ]


def _similar(a: str, b: str) -> bool:
    if not a or not b:
        return False
    longer = max(len(a), len(b))
    return abs(len(a) - len(b)) <= longer * 0.25
