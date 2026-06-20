"""Probe for a small, well-known set of accidentally exposed files."""

from __future__ import annotations

import secrets

import requests

from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

_PATHS = {
    "/.git/config": (Severity.HIGH, "Exposed .git repository — the source can be downloaded."),
    "/.git/HEAD": (Severity.HIGH, "Exposed .git metadata — the repository may be dumpable."),
    "/.env": (Severity.HIGH, "Environment files often hold secrets and DB credentials."),
    "/.env.local": (Severity.HIGH, "Local environment file may hold secrets."),
    "/.env.bak": (Severity.HIGH, "Backup of the environment file may hold secrets."),
    "/.svn/entries": (Severity.MEDIUM, "SVN metadata leaks the code structure and history."),
    "/.aws/credentials": (Severity.HIGH, "AWS credentials file exposed."),
    "/id_rsa": (Severity.HIGH, "Private SSH key exposed."),
    "/.DS_Store": (Severity.LOW, "macOS file leaks the names of files in the directory."),
    "/backup.zip": (Severity.MEDIUM, "A reachable backup may contain source code or data."),
    "/backup.sql": (Severity.HIGH, "A reachable database dump may contain all data."),
    "/database.sql": (Severity.HIGH, "A reachable database dump may contain all data."),
    "/dump.sql": (Severity.HIGH, "A reachable database dump may contain all data."),
    "/wp-config.php.bak": (Severity.HIGH, "WordPress config backup with credentials."),
    "/config.php.bak": (Severity.HIGH, "Config backup may expose credentials."),
    "/web.config": (Severity.MEDIUM, "IIS config file should not be served directly."),
    "/.htaccess": (Severity.LOW, "Apache config file should not be served directly."),
    "/.npmrc": (Severity.MEDIUM, ".npmrc may contain registry auth tokens."),
    "/.bash_history": (Severity.MEDIUM, "Shell history may leak commands and secrets."),
    "/docker-compose.yml": (Severity.LOW, "Compose file may reveal services and credentials."),
    "/phpinfo.php": (Severity.MEDIUM, "phpinfo() leaks configuration and paths."),
    "/info.php": (Severity.MEDIUM, "phpinfo() leaks configuration and paths."),
    "/server-status": (Severity.MEDIUM, "Apache mod_status leaks requests and internal addresses."),
}

_GIT_MARKER = "[core]"
_ENV_MARKERS = ("=", "\n")


class SensitiveFilesCheck(PassiveCheck):
    name = "sensitive-files"
    description = "Checks for exposed sensitive files (.git, .env, backups, dumps)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        catch_all = self._catch_all_200(ctx)
        findings: list[Finding] = []
        for path, (severity, why) in _PATHS.items():
            url = ctx.client.join(ctx.target, path)
            resp = ctx.client.try_get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            if not _looks_real(path, resp, catch_all):
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

    def _catch_all_200(self, ctx: ScanContext) -> bool:
        probe = ctx.client.join(ctx.target, "/wvs-" + secrets.token_hex(6) + ".txt")
        resp = ctx.client.try_get(probe, allow_redirects=False)
        return resp is not None and resp.status_code == 200

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


def _looks_real(path: str, resp: "requests.Response", catch_all: bool = False) -> bool:
    body = resp.text or ""
    if path.endswith("/.git/config"):
        return _GIT_MARKER in body
    if path.endswith("/.env"):
        return all(m in body for m in _ENV_MARKERS) and "<html" not in body.lower()
    return len(resp.content) > 0 and not catch_all
