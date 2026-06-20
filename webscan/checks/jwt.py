"""JWT weakness detection (alg:none, weak HS256 secret, missing expiry).

Derived from the cybersecurity skill 'exploiting-jwt-algorithm-confusion-attack'.
Tokens are only observed and analysed offline — no forged token is sent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")

_WEAK_SECRETS = [
    "secret", "secretkey", "password", "123456", "jwt", "key", "admin",
    "changeme", "your-256-bit-secret", "supersecret", "test", "qwerty",
    "s3cr3t", "private", "token", "jwtsecret", "default", "hmac",
]

_SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope", "scopes", "groups")


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


class JwtCheck(PassiveCheck):
    name = "jwt"
    description = "Finds JWTs and flags alg:none, weak HS256 secrets, missing expiry"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for token in self._collect(ctx):
            if token in seen:
                continue
            seen.add(token)
            findings.extend(self._analyse(token, ctx.target))
        return findings

    def _collect(self, ctx: ScanContext) -> list[str]:
        resp = ctx.base_response
        if resp is None:
            return []
        chunks = [resp.text or ""]
        chunks.extend(resp.headers.values())
        chunks.extend(c.value for c in resp.cookies if c.value)
        return _JWT_RE.findall("\n".join(c for c in chunks if c))

    def _analyse(self, token: str, url: str) -> list[Finding]:
        parts = token.split(".")
        if len(parts) != 3:
            return []
        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except (ValueError, binascii.Error):
            return []
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return []

        findings: list[Finding] = []
        alg = str(header.get("alg", "")).lower()

        if alg == "none":
            findings.append(
                self.finding(
                    title="JWT uses 'alg: none' (unsigned token)",
                    severity=Severity.HIGH,
                    confidence="firm",
                    description="The token is unsigned, so its claims can be modified freely.",
                    evidence="header alg=none",
                    remediation="Enforce a fixed signing algorithm server-side.",
                    url=url,
                )
            )
        elif alg == "hs256":
            secret = self._crack(token)
            if secret:
                findings.append(
                    self.finding(
                        title="JWT signed with a weak HS256 secret",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="The signing secret is guessable, so valid tokens can be forged.",
                        evidence=f"recovered secret: '{secret}'",
                        remediation="Use a long random secret or an asymmetric algorithm.",
                        url=url,
                    )
                )

        if "exp" not in payload:
            findings.append(
                self.finding(
                    title="JWT has no expiry (exp claim)",
                    severity=Severity.LOW,
                    confidence="firm",
                    description="Tokens without exp stay valid indefinitely if leaked.",
                    remediation="Issue short-lived tokens with an exp claim.",
                    url=url,
                )
            )

        exposed = sorted(k for k in payload if k.lower() in _SENSITIVE_CLAIMS)
        if exposed:
            findings.append(
                self.finding(
                    title="JWT exposes privilege claims",
                    severity=Severity.INFO,
                    confidence="firm",
                    description="Role/scope claims are readable and forgeable if signing is weak.",
                    evidence=", ".join(exposed),
                    url=url,
                )
            )
        return findings

    def _crack(self, token: str) -> str:
        try:
            signing_input, sig = token.rsplit(".", 1)
            expected = _b64url_decode(sig)
        except (ValueError, binascii.Error):
            return ""
        if not expected:
            return ""
        for secret in _WEAK_SECRETS:
            mac = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
            if hmac.compare_digest(mac, expected):
                return secret
        return ""
