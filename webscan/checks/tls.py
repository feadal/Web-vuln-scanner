"""Check transport security: HTTPS usage, HTTP->HTTPS redirect, cert validity."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import requests

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity


class TlsCheck(PassiveCheck):
    name = "tls"
    description = "Checks HTTPS usage, HTTP redirect and certificate validity"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []

        findings: list[Finding] = []
        final_is_https = resp.url.lower().startswith("https://")

        if not final_is_https:
            findings.append(
                self.finding(
                    title="Site is served over unencrypted HTTP",
                    severity=Severity.HIGH,
                    description="Traffic is sent in clear text and can be intercepted or modified.",
                    evidence=resp.url,
                    remediation="Enable HTTPS and force a redirect of all traffic to it.",
                    url=resp.url,
                )
            )
            findings.extend(self._check_http_redirect(ctx))
            return findings

        if not ctx.client.verify_tls:
            findings.append(
                self.finding(
                    title="TLS certificate verification was disabled (--insecure)",
                    severity=Severity.INFO,
                    description="The scan ran without validating the certificate.",
                    url=resp.url,
                )
            )
        else:
            findings.extend(self._verify_certificate(ctx, resp.url))

        return findings

    def _check_http_redirect(self, ctx: ScanContext) -> list[Finding]:
        """If we landed on HTTP, see whether an HTTPS endpoint even exists."""
        https_url = _force_scheme(ctx.target, "https")
        probe = ctx.client.try_get(https_url, allow_redirects=False)
        if probe is None:
            return [
                self.finding(
                    title="No HTTPS endpoint available",
                    severity=Severity.MEDIUM,
                    description="Connecting over HTTPS failed — encryption is likely not configured.",
                    evidence=https_url,
                    remediation="Deploy a valid TLS certificate and listen on port 443.",
                    url=https_url,
                )
            ]
        return []

    def _verify_certificate(self, ctx: ScanContext, url: str) -> list[Finding]:
        """Re-request with verification forced on to surface cert errors explicitly."""
        try:
            ctx.client.get(url, verify=True)
        except requests.exceptions.SSLError as exc:
            return [
                self.finding(
                    title="Invalid TLS certificate",
                    severity=Severity.HIGH,
                    description="The certificate failed validation (expired, self-signed or wrong host).",
                    evidence=str(exc)[:200],
                    remediation="Install a valid certificate from a trusted CA.",
                    url=url,
                )
            ]
        except requests.RequestException:
            return []
        return []


def _force_scheme(url: str, scheme: str) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(scheme=scheme))
