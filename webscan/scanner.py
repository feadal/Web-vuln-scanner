"""Orchestrates a scan: passive pass then optional active pass."""

from __future__ import annotations

import logging
from typing import Optional, Sequence

import requests

from webscan import crawler
from webscan.checks import ActiveCheck, PassiveCheck, all_active, all_passive
from webscan.http_client import BudgetExceeded, HttpClient
from webscan.models import ScanContext, ScanResult

log = logging.getLogger("webscan")


class Scanner:
    def __init__(
        self,
        client: Optional[HttpClient] = None,
        passive_checks: Optional[Sequence[PassiveCheck]] = None,
        active_checks: Optional[Sequence[ActiveCheck]] = None,
        *,
        active: bool = True,
        max_pages: int = 10,
        guess_params: bool = False,
    ) -> None:
        self.client = client or HttpClient()
        self.passive_checks = (
            list(passive_checks) if passive_checks is not None else all_passive()
        )
        self.active_checks = (
            list(active_checks) if active_checks is not None else all_active()
        )
        self.active = active
        self.max_pages = max_pages
        self.guess_params = guess_params

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

        self._run_passive(ctx, result)

        if self.active and self.active_checks and base_response is not None:
            self._run_active(base_response.url, base_html, result)

        result.requests_made = self.client.requests_made
        return result

    def _run_passive(self, ctx: ScanContext, result: ScanResult) -> None:
        for check in self.passive_checks:
            try:
                findings = check.run(ctx)
            except BudgetExceeded as exc:
                result.errors.append(f"Stopped early: {exc}")
                return
            except Exception as exc:
                log.warning("passive check %s raised: %s", check.name, exc)
                result.errors.append(f"{check.name}: {exc}")
                continue
            for f in findings:
                result.add(f)

    def _run_active(self, base_url: str, base_html: str, result: ScanResult) -> None:
        try:
            points = crawler.discover(
                self.client, base_url, base_html, max_pages=self.max_pages
            )
        except BudgetExceeded as exc:
            result.errors.append(f"Stopped early during crawl: {exc}")
            return

        if self.guess_params:
            points = _merge_points(points, crawler.guessed_points(base_url))

        result.injection_points = len(points)
        if not points:
            return

        try:
            for point in points:
                for check in self.active_checks:
                    try:
                        findings = check.test(point, self.client)
                    except Exception as exc:
                        log.warning("active check %s raised: %s", check.name, exc)
                        result.errors.append(f"{check.name} ({point.label()}): {exc}")
                        continue
                    for f in findings:
                        result.add(f)
        except BudgetExceeded as exc:
            result.errors.append(f"Stopped early: {exc}")

    def _fetch_base(self, target: str, result: ScanResult):
        try:
            resp = self.client.get(target)
        except BudgetExceeded as exc:
            result.errors.append(str(exc))
            return None, ""
        except requests.RequestException as exc:
            result.errors.append(f"Could not load {target}: {exc}")
            return None, ""
        content_type = resp.headers.get("Content-Type", "")
        html = resp.text if "html" in content_type.lower() else ""
        return resp, html


def _merge_points(points, extra):
    seen = {(p.method, p.url, p.param) for p in points}
    merged = list(points)
    for p in extra:
        key = (p.method, p.url, p.param)
        if key not in seen:
            seen.add(key)
            merged.append(p)
    return merged


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target
