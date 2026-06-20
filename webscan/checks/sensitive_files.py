"""Probe for a small, well-known set of accidentally exposed files.

A short, fixed list of common paths fetched once each. It never brute-forces.
"""

from __future__ import annotations

import requests

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_PATHS = {
    "/.git/config": (Severity.HIGH, "Exposed .git repository — the source can be downloaded."),
    "/.env": (Severity.HIGH, "Environment files often hold secrets and DB credentials."),
    "/.svn/entries": (Severity.MEDIUM, "SVN metadata leaks the code structure and history."),
    "/.DS_Store": (Severity.LOW, "macOS file leaks the names of files in the directory."),
    "/backup.zip": (Severity.MEDIUM, "A reachable backup may contain source code or data."),
    "/wp-config.php.bak": (Severity.HIGH, "WordPress config backup with credentials."),
    "/.htaccess": (Severity.LOW, "Apache config file should not be served directly."),
    "/server-status": (Severity.MEDIUM, "Apache mod_status leaks requests and internal addresses."),
}

_GIT_MARKER = "[core]"
_ENV_MARKERS = ("=", "\n")


class SensitiveFilesCheck(PassiveCheck):
    name = "sensitive-files"
    description = "Checks for exposed sensitive files (.git, .env, backups)"

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
                    title=f"Sensitive path is reachable: {path}",
                    severity=severity,
                    description=why,
                    evidence=f"HTTP 200 at {url} ({len(resp.content)} bytes)",
                    remediation="Block access to the file/directory at the web server, or remove it.",
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
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM,
                    description="The server shows directory contents instead of a page.",
                    evidence="Found an 'Index of /' marker",
                    remediation="Disable auto-indexing (Options -Indexes in Apache, autoindex off in nginx).",
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
    return len(resp.content) > 0
