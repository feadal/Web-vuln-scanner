"""Orchestrates a scan: passive pass, then a concurrent active pass."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Sequence

import requests

from webscan import browser_crawler, crawler, owasp
from webscan.checks import ActiveCheck, PassiveCheck, all_active, all_passive
from webscan.collaborator import OOB_TEMPLATES, correlate
from webscan.http_client import BudgetExceeded, HttpClient
from webscan.models import ScanContext, ScanResult
from webscan.progress import NullReporter
from webscan.templates_engine import run_template

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
        threads: int = 10,
        browser: bool = False,
        oob: bool = False,
        collaborator=None,
        oob_wait: float = 5.0,
        templates=None,
        tamper=None,
        reporter=None,
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
        self.threads = max(1, threads)
        self.browser = browser
        self.oob = oob
        self.collaborator = collaborator
        self.oob_wait = oob_wait
        self.templates = templates or []
        self.reporter = reporter or NullReporter()
        for check in self.active_checks:
            check.tamper = tamper or []

    def scan(self, target: str) -> ScanResult:
        target = _normalize_target(target)
        result = ScanResult(target=target)

        self.reporter.phase(f"Fetching {target}")
        base_response, base_html = self._fetch_base(target, result)
        ctx = ScanContext(
            target=target,
            client=self.client,
            base_response=base_response,
            base_html=base_html,
        )

        self.reporter.phase(f"Passive checks ({len(self.passive_checks)})")
        self._run_passive(ctx, result)

        if self.templates:
            self.reporter.phase(f"Detection templates ({len(self.templates)})")
            self._run_templates(target, result)

        if self.active and self.active_checks and base_response is not None:
            self._run_active(base_response.url, base_html, result)

        for finding in result.findings:
            owasp.tag(finding)

        result.requests_made = self.client.requests_made
        self.reporter.close()
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
                if result.add(f):
                    self.reporter.finding(f)

    def _run_templates(self, target: str, result: ScanResult) -> None:
        for template in self.templates:
            try:
                for finding in run_template(template, target, self.client):
                    if result.add(finding):
                        self.reporter.finding(finding)
            except BudgetExceeded as exc:
                result.errors.append(f"Stopped early (templates): {exc}")
                return

    def _run_active(self, base_url: str, base_html: str, result: ScanResult) -> None:
        try:
            points = crawler.discover(
                self.client, base_url, base_html, max_pages=self.max_pages
            )
        except BudgetExceeded as exc:
            result.errors.append(f"Stopped early during crawl: {exc}")
            return

        if self.browser:
            try:
                bpoints = browser_crawler.discover(base_url)
                points = _merge_points(points, bpoints)
            except browser_crawler.BrowserUnavailable as exc:
                result.errors.append(str(exc))
            except Exception as exc:
                result.errors.append(f"browser crawl failed: {exc}")

        if self.guess_params:
            points = _merge_points(points, crawler.guessed_points(base_url))

        result.injection_points = len(points)
        if not points:
            self.reporter.info("no injection points found")
            return

        total = len(points)
        self.reporter.phase(f"Active scan — {total} points x {len(self.active_checks)} checks")
        done = 0
        self.reporter.active(done, total, self.client.requests_made)
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._scan_point, p): p for p in points}
            for future in as_completed(futures):
                findings, errors = future.result()
                for f in findings:
                    if result.add(f):
                        self.reporter.finding(f)
                result.errors.extend(errors)
                done += 1
                self.reporter.active(done, total, self.client.requests_made)

        if self.oob and self.collaborator is not None:
            self.reporter.phase(f"Out-of-band wait ({self.oob_wait}s)")
            self._run_oob(points, result)

    def _run_oob(self, points, result):
        registry = {}
        try:
            for point in points:
                for kind, make in OOB_TEMPLATES:
                    token = self.collaborator.new_token()
                    self._inject(point, make(self.collaborator.payload_url(token)))
                    registry[token] = (point, kind)
        except BudgetExceeded as exc:
            result.errors.append(f"Stopped early (OOB): {exc}")
        time.sleep(self.oob_wait)
        for finding in correlate(self.collaborator.poll(), registry):
            if result.add(finding):
                self.reporter.finding(finding)

    def _inject(self, point, payload):
        values = dict(point.params)
        values[point.param] = payload
        try:
            if point.method == "POST":
                self.client.request("POST", point.url, data=values, allow_redirects=False)
            else:
                self.client.request("GET", point.url, params=values, allow_redirects=False)
        except requests.RequestException:
            pass

    def _scan_point(self, point):
        findings = []
        errors = []
        for check in self.active_checks:
            try:
                findings.extend(check.test(point, self.client))
            except BudgetExceeded:
                break
            except Exception as exc:
                log.warning("active check %s raised: %s", check.name, exc)
                errors.append(f"{check.name} ({point.label()}): {exc}")
        return findings, errors

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
