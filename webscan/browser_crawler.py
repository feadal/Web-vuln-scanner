"""Optional headless-browser crawler (Playwright) for SPA / JS-rendered apps.

Renders the page, captures XHR/fetch network traffic and DOM forms, and turns
them into injection points the static crawler cannot see. Playwright is an
optional dependency: install with `pip install -e ".[browser]"` then
`playwright install chromium`.
"""

from __future__ import annotations

import importlib.util
from urllib.parse import parse_qsl, urlparse, urlunparse

from webscan.models import InjectionPoint

_CAPTURE_TYPES = {"xhr", "fetch", "document"}
_FORM_ENCODED = "application/x-www-form-urlencoded"


class BrowserUnavailable(RuntimeError):
    """Raised when Playwright (or its browser) is not installed."""


def available() -> bool:
    return importlib.util.find_spec("playwright") is not None


def _strip_query(url: str) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(query="", fragment=""))


def records_to_points(records, forms, host) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()

    def add(p: InjectionPoint) -> None:
        key = (p.method, p.url, p.param)
        if key not in seen:
            seen.add(key)
            points.append(p)

    for rec in records:
        if rec.get("resource_type") not in _CAPTURE_TYPES:
            continue
        url = rec.get("url", "")
        if not url.startswith(("http://", "https://")) or urlparse(url).hostname != host:
            continue
        query = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        if query:
            base = _strip_query(url)
            for name in query:
                add(InjectionPoint(method="GET", url=base, param=name, params=dict(query), source="xhr"))
        if rec.get("method", "GET").upper() == "POST" and _FORM_ENCODED in rec.get("content_type", ""):
            body = dict(parse_qsl(rec.get("post_data", ""), keep_blank_values=True))
            for name in body:
                add(InjectionPoint(method="POST", url=_strip_query(url), param=name, params=dict(body), source="xhr"))

    for form in forms:
        action = form.get("action") or ""
        if not action.startswith(("http://", "https://")) or urlparse(action).hostname != host:
            continue
        method = "POST" if str(form.get("method", "get")).lower() == "post" else "GET"
        fields = {name: "test" for name in form.get("fields", []) if name}
        target_url = action if method == "POST" else _strip_query(action)
        for name in fields:
            add(InjectionPoint(method=method, url=target_url, param=name, params=dict(fields), source="form"))

    return points


def discover(target, *, scope_host=None, timeout=15, settle_ms=2500):
    if not available():
        raise BrowserUnavailable(
            "Playwright not installed. Run: pip install -e \".[browser]\" && playwright install chromium"
        )
    from playwright.sync_api import sync_playwright

    records: list[dict] = []
    forms: list[dict] = []
    host = scope_host or urlparse(target).hostname

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.on(
            "request",
            lambda req: records.append(
                {
                    "method": req.method,
                    "url": req.url,
                    "post_data": req.post_data or "",
                    "content_type": (req.headers or {}).get("content-type", ""),
                    "resource_type": req.resource_type,
                }
            ),
        )
        try:
            page.goto(target, wait_until="networkidle", timeout=timeout * 1000)
        except Exception:
            try:
                page.goto(target, timeout=timeout * 1000)
            except Exception:
                pass
        page.wait_for_timeout(settle_ms)
        try:
            forms = page.eval_on_selector_all(
                "form",
                "els => els.map(f => ({action: f.action, method: (f.getAttribute('method')||'get'),"
                " fields: Array.from(f.querySelectorAll('input,textarea,select'))"
                ".filter(i => i.name && !['submit','button','image','file','reset']"
                ".includes((i.getAttribute('type')||'').toLowerCase())).map(i => i.name)}))",
            )
        except Exception:
            forms = []
        browser.close()

    return records_to_points(records, forms, host)
