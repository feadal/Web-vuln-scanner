"""Check transport security: HTTPS usage, HTTP->HTTPS redirect, cert validity."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import requests

from webscan.checks.base import Check
from webscan.models import Finding, ScanContext, Severity


class TlsCheck(Check):
    name = "tls"
    description = "Проверяет HTTPS, редирект с HTTP и валидность сертификата"

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []

        findings: list[Finding] = []
        final_is_https = resp.url.lower().startswith("https://")

        if not final_is_https:
            findings.append(
                self.finding(
                    title="Сайт обслуживается по незашифрованному HTTP",
                    severity=Severity.HIGH,
                    description="Трафик передаётся открытым текстом и может быть перехвачен/изменён.",
                    evidence=resp.url,
                    remediation="Включите HTTPS и принудительный редирект всего трафика на него.",
                    url=resp.url,
                )
            )
            findings.extend(self._check_http_redirect(ctx))
            return findings

        # We are on HTTPS — verify the certificate is actually trusted.
        if not ctx.client.verify_tls:
            findings.append(
                self.finding(
                    title="Проверка TLS-сертификата отключена (--insecure)",
                    severity=Severity.INFO,
                    description="Сканирование выполнено без валидации сертификата.",
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
                    title="HTTPS-эндпоинт недоступен",
                    severity=Severity.MEDIUM,
                    description="Подключение по HTTPS не удалось — шифрование, вероятно, не настроено.",
                    evidence=https_url,
                    remediation="Разверните валидный TLS-сертификат и слушайте порт 443.",
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
                    title="Невалидный TLS-сертификат",
                    severity=Severity.HIGH,
                    description="Сертификат не прошёл проверку доверия (истёк, самоподписан или не тот хост).",
                    evidence=str(exc)[:200],
                    remediation="Установите валидный сертификат от доверенного УЦ.",
                    url=url,
                )
            ]
        except requests.RequestException:
            # Transient/transport issues are not a TLS finding.
            return []
        return []


def _force_scheme(url: str, scheme: str) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(scheme=scheme))
