"""Find hardcoded secrets exposed in HTML responses and linked JavaScript.

Derived from the cybersecurity skills 'implementing-secret-scanning-with-gitleaks'
and 'implementing-secrets-scanning-in-ci-cd'.
"""

from __future__ import annotations

import re

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_PATTERNS = [
    (Severity.HIGH, "aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (Severity.HIGH, "google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    (Severity.HIGH, "private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    (Severity.HIGH, "stripe_secret_key", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    (Severity.HIGH, "github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    (Severity.MEDIUM, "slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    (Severity.MEDIUM, "google_oauth_client", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    (Severity.MEDIUM, "firebase_url", re.compile(r"https://[a-z0-9.\-]+\.firebaseio\.com")),
    (Severity.MEDIUM, "jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    (Severity.LOW, "credential_assignment",
     re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|token)['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
]

_SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
_MAX_SCRIPTS = 5


def _trim(value: str) -> str:
    return value if len(value) <= 80 else value[:77] + "..."


class SecretsCheck(PassiveCheck):
    name = "secrets"
    description = "Finds hardcoded secrets/keys in responses and linked JavaScript"

    def run(self, ctx: ScanContext) -> list[Finding]:
        sources = []
        if ctx.base_response is not None:
            sources.append((ctx.base_response.url, ctx.base_response.text or ""))
        sources.extend(self._linked_scripts(ctx))

        seen: set[tuple] = set()
        findings: list[Finding] = []
        for url, body in sources:
            for severity, kind, rx in _PATTERNS:
                for match in rx.finditer(body):
                    value = match.group(0)
                    key = (kind, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            title=f"Exposed secret: {kind}",
                            severity=severity,
                            confidence="firm",
                            description="A credential/secret is exposed in client-visible content.",
                            evidence=f"{_trim(value)} in {url}",
                            remediation="Rotate the secret and move it server-side; never ship secrets to clients.",
                            url=url,
                        )
                    )
        return findings

    def _linked_scripts(self, ctx: ScanContext):
        out = []
        if not ctx.base_html:
            return out
        host = ctx.base_response.url if ctx.base_response is not None else ctx.target
        for src in _SCRIPT_SRC.findall(ctx.base_html)[:_MAX_SCRIPTS]:
            url = ctx.client.join(host, src)
            if not url.startswith(("http://", "https://")):
                continue
            resp = ctx.client.try_get(url)
            if resp is not None and "javascript" in resp.headers.get("Content-Type", "").lower():
                out.append((url, resp.text or ""))
        return out
