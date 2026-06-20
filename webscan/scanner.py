"""Orchestrates a scan: fetch the target once, run each check, collect findings."""

from __future__ import annotations

import logging
from typing import Optional, Sequence

import requests

from webscan.checks import Check, all_checks
from webscan.http_client import HttpClient
from webscan.models import ScanContext, ScanResult

log = logging.getLogger("webscan")


class Scanner:
    def __init__(
        self,
        client: Optional[HttpClient] = None,
        checks: Optional[Sequence[Check]] = None,
    ) -> None:
        self.client = client or HttpClient()
        self.checks = list(checks) if checks is not None else all_checks()

    def scan(self, target: str) -> ScanResult:
        target = _normalize_target(target)
        result = ScanResult(target=target)

        base_response, base_html = self._fetch_base(target, result)
        ctx = ScanContext(
            target=target,
            client=self.client,
            base_response=base_response,
            base_html=base_html,
        )

        for check in self.checks:
            try:
                findings = check.run(ctx)
            except Exception as exc:  # one broken check shouldn't sink the scan
                log.warning("check %s raised: %s", check.name, exc)
                result.errors.append(f"{check.name}: {exc}")
                continue
            result.findings.extend(findings)

        return result

    def _fetch_base(self, target: str, result: ScanResult):
        try:
            resp = self.client.get(target)
        except requests.RequestException as exc:
            result.errors.append(f"Не удалось загрузить {target}: {exc}")
            return None, ""
        # Only parse HTML bodies; skip binary/large non-HTML responses.
        content_type = resp.headers.get("Content-Type", "")
        html = resp.text if "html" in content_type.lower() else ""
        return resp, html


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        # Default to https; the tls check will report if only http works.
        target = "https://" + target
    return target
