"""Tests for web cache poisoning, mass assignment and the IDOR hint."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import responses

from webscan.checks.active.idor import IdorCheck
from webscan.checks.active.mass_assignment import MassAssignmentCheck
from webscan.checks.web_cache_poisoning import WebCachePoisoningCheck
from webscan.http_client import HttpClient
from webscan.models import InjectionPoint, ScanContext, Severity


def _ctx():
    return ScanContext(target="https://t.test/", client=HttpClient(), base_response=None, base_html="")


@responses.activate
def test_web_cache_poisoning_detected():
    def cb(request):
        xfh = request.headers.get("X-Forwarded-Host", "")
        return (200, {"Cache-Control": "public, max-age=30"}, f"<link href='https://{xfh}/a.css'>")

    responses.add_callback(responses.GET, "https://t.test/", callback=cb)
    findings = WebCachePoisoningCheck().run(_ctx())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_web_cache_poisoning_needs_cacheable():
    def cb(request):
        xfh = request.headers.get("X-Forwarded-Host", "")
        return (200, {"Cache-Control": "no-store"}, f"<link href='https://{xfh}/a.css'>")

    responses.add_callback(responses.GET, "https://t.test/", callback=cb)
    assert WebCachePoisoningCheck().run(_ctx()) == []


@responses.activate
def test_mass_assignment_detected():
    def cb(request):
        role = parse_qs(request.body or "").get("role", [""])[0]
        return (200, {}, f"created with role={role}")

    responses.add_callback(responses.POST, "https://t.test/api/users", callback=cb)
    point = InjectionPoint(method="POST", url="https://t.test/api/users", param="name", params={"name": "x"})
    findings = MassAssignmentCheck().test(point, HttpClient())
    assert findings and findings[0].confidence == "tentative"


@responses.activate
def test_idor_hint_on_numeric_id():
    def cb(request):
        idv = parse_qs(urlparse(request.url).query).get("id", [""])[0]
        return (200, {}, "profile number " + idv + " " + "x" * 100)

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    point = InjectionPoint(method="GET", url="https://t.test/p", param="id", params={"id": "5"})
    findings = IdorCheck().test(point, HttpClient())
    assert findings and findings[0].confidence == "tentative"


def test_idor_skips_non_numeric():
    point = InjectionPoint(method="GET", url="https://t.test/p", param="q", params={"q": "hello"})
    assert IdorCheck().test(point, HttpClient()) == []
