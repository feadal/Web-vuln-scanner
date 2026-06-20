"""Probe for a small, well-known set of accidentally exposed files.

This is the only check that makes extra requests, and it stays low-intensity:
a short, fixed list of common paths fetched once each. It never brute-forces.
"""

from __future__ import annotations

import requests

from webscan.checks.base import Check
from webscan.models import Finding, ScanContext, Severity

# path -> (severity, why it matters)
_PATHS = {
    "/.git/config": (Severity.HIGH, "Экспонирован репозиторий .git — можно выкачать исходники."),
    "/.env": (Severity.HIGH, "Файл окружения часто содержит секреты и пароли БД."),
    "/.svn/entries": (Severity.MEDIUM, "Метаданные SVN раскрывают структуру и историю кода."),
    "/.DS_Store": (Severity.LOW, "Файл macOS раскрывает имена файлов в директории."),
    "/backup.zip": (Severity.MEDIUM, "Доступный бэкап может содержать исходники/данные."),
    "/wp-config.php.bak": (Severity.HIGH, "Бэкап конфигурации WordPress с учётными данными."),
    "/.htaccess": (Severity.LOW, "Файл конфигурации Apache не должен отдаваться напрямую."),
    "/server-status": (Severity.MEDIUM, "Apache mod_status раскрывает запросы и внутренние адреса."),
}

# A body that looks like real content rather than a custom 200-styled 404.
_GIT_MARKER = "[core]"
_ENV_MARKERS = ("=", "\n")


class SensitiveFilesCheck(Check):
    name = "sensitive-files"
    description = "Проверяет доступность типичных чувствительных файлов (.git, .env, бэкапы)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, (severity, why) in _PATHS.items():
            url = ctx.client.join(ctx.target, path)
            resp = ctx.client.try_get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            if not _looks_real(path, resp):
                continue
            findings.append(
                self.finding(
                    title=f"Доступен чувствительный путь: {path}",
                    severity=severity,
                    description=why,
                    evidence=f"HTTP 200 на {url} ({len(resp.content)} байт)",
                    remediation="Закройте доступ к файлу/директории на уровне веб-сервера или удалите его.",
                    url=url,
                )
            )

        findings.extend(self._directory_listing(ctx))
        return findings

    def _directory_listing(self, ctx: ScanContext) -> list[Finding]:
        url = ctx.client.join(ctx.target, "/")
        resp = ctx.base_response if ctx.base_response is not None else ctx.client.try_get(url)
        if resp is None:
            return []
        body = (resp.text or "")[:4000].lower()
        if "index of /" in body and "<title>index of" in body:
            return [
                self.finding(
                    title="Включён листинг директорий",
                    severity=Severity.MEDIUM,
                    description="Сервер показывает содержимое директории вместо страницы.",
                    evidence="Найден маркер 'Index of /'",
                    remediation="Отключите автоиндекс (Options -Indexes в Apache, autoindex off в nginx).",
                    url=resp.url,
                )
            ]
        return []


def _looks_real(path: str, resp: "requests.Response") -> bool:
    """Reduce false positives from sites that return 200 for everything."""
    body = resp.text or ""
    if path.endswith("/.git/config"):
        return _GIT_MARKER in body
    if path.endswith("/.env"):
        return all(m in body for m in _ENV_MARKERS) and "<html" not in body.lower()
    # For the rest, a non-empty, non-HTML-error body is a reasonable signal.
    return len(resp.content) > 0
