"""Discover injection points (URL parameters and form fields) on the target.

The crawl is deliberately small and same-host only: it exists to find inputs to
test, not to mirror the site. Bounded by ``max_pages`` and the client's request
budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from webscan.http_client import HttpClient
from webscan.models import InjectionPoint

# Input types we never fuzz (no useful value to mutate).
_SKIP_INPUT_TYPES = {"submit", "button", "image", "file", "reset"}


@dataclass
class _Form:
    action: str = ""
    method: str = "get"
    fields: dict[str, str] = field(default_factory=dict)


class _LinkFormParser(HTMLParser):
    """Collect anchor hrefs and forms (with their named fields)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[_Form] = []
        self._current: _Form | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and "href" in a:
            self.links.append(a["href"])
        elif tag == "form":
            self._current = _Form(
                action=a.get("action", ""), method=(a.get("method") or "get").lower()
            )
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = a.get("name")
            if not name or a.get("type", "").lower() in _SKIP_INPUT_TYPES:
                return
            self._current.fields[name] = a.get("value", "test")

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def _strip_query(url: str) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(query="", fragment=""))


def _same_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).hostname == host
    except ValueError:
        return False


def _points_from_query(url: str) -> list[InjectionPoint]:
    qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    if not qs:
        return []
    params = {k: v for k, v in qs}
    base = _strip_query(url)
    return [
        InjectionPoint(method="GET", url=base, param=name, params=dict(params), source="query")
        for name in params
    ]


def _points_from_form(form: _Form, page_url: str) -> list[InjectionPoint]:
    if not form.fields:
        return []
    action_url = urljoin(page_url, form.action) if form.action else page_url
    method = "POST" if form.method == "post" else "GET"
    if method == "GET":
        action_url = _strip_query(action_url)
    return [
        InjectionPoint(
            method=method,
            url=action_url,
            param=name,
            params=dict(form.fields),
            source="form",
        )
        for name in form.fields
    ]


def discover(
    client: HttpClient,
    base_url: str,
    base_html: str,
    *,
    max_pages: int = 10,
) -> list[InjectionPoint]:
    """Crawl ``base_url`` (same host) and return a de-duplicated list of points."""
    host = urlparse(base_url).hostname
    queue: list[str] = [base_url]
    htmls: dict[str, str] = {base_url: base_html}
    visited: set[str] = set()
    points: list[InjectionPoint] = []
    seen_keys: set[tuple] = set()

    def add(new_points: list[InjectionPoint]) -> None:
        for p in new_points:
            key = (p.method, p.url, p.param, tuple(sorted(p.params)))
            if key not in seen_keys:
                seen_keys.add(key)
                points.append(p)

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        html = htmls.pop(url, None)
        if html is None:
            resp = client.try_get(url)
            if resp is None:
                continue
            if "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            html = resp.text

        add(_points_from_query(url))

        parser = _LinkFormParser()
        try:
            parser.feed(html or "")
        except Exception:
            continue

        for form in parser.forms:
            add(_points_from_form(form, url))

        for href in parser.links:
            target = urljoin(url, href)
            target = urlunparse(urlparse(target)._replace(fragment=""))
            if not target.startswith(("http://", "https://")):
                continue
            if not _same_host(target, host):
                continue
            if target not in visited:
                queue.append(target)

    return points
