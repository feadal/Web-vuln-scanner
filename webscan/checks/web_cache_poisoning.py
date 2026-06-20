"""Detect web cache poisoning via reflected unkeyed headers.

Derived from the cybersecurity skill 'performing-web-cache-poisoning-attack'.
A finding requires both: an unkeyed header is reflected, and the response looks
cacheable — otherwise the plain reflection is covered by the host-header check.
"""

from __future__ import annotations

import secrets

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme", "X-Forwarded-Server"]
_CACHEABLE_HINTS = ("public", "max-age", "s-maxage")


class WebCachePoisoningCheck(PassiveCheck):
    name = "web-cache-poisoning"
    description = "Detects cache poisoning via reflected unkeyed request headers"

    def run(self, ctx: ScanContext) -> list[Finding]:
        canary = f"wvs{secrets.token_hex(4)}.example.com"
        for header in _HEADERS:
            resp = ctx.client.try_get(ctx.target, headers={header: canary}, allow_redirects=False)
            if resp is None:
                continue
            reflected = canary in (resp.text or "")[:20000] or canary in resp.headers.get("Location", "")
            if not reflected:
                continue
            cache_control = resp.headers.get("Cache-Control", "").lower()
            cacheable = any(h in cache_control for h in _CACHEABLE_HINTS) or bool(
                resp.headers.get("X-Cache")
            )
            if not cacheable:
                continue
            return [
                self.finding(
                    title=f"Web cache poisoning via {header}",
                    severity=Severity.HIGH,
                    confidence="firm",
                    description="An unkeyed header is reflected into a cacheable response, so a poisoned entry can be served to others.",
                    evidence=f"{header}: {canary} reflected; Cache-Control: {cache_control or '(none)'}",
                    remediation="Add the header to the cache key or stop reflecting it into responses.",
                    url=ctx.target,
                )
            ]
        return []
