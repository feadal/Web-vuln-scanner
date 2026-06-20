"""Tests for the new checks: secrets, web cache deception, HTTP parameter pollution."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import requests
import responses

from webscan.checks.active.hpp import HppCheck
from webscan.checks.secrets import SecretsCheck
from webscan.checks.web_cache_deception import WebCacheDeceptionCheck
from webscan.http_client import HttpClient
from webscan.models import InjectionPoint, ScanContext, Severity

_AWS = "AKIAABCDEFGHIJKLMNOP"
_GOOGLE = "AIza" + "a" * 35


def _resp(body, url="https://t.test/", headers=None):
    r = requests.Response()
    r.status_code = 200
    r.url = url
    r._content = body.encode()
    r.headers.update(headers or {})
    return r


def _ctx(base_response, html=""):
    return ScanContext(target="https://t.test/", client=HttpClient(), base_response=base_response, base_html=html)


def test_secrets_detected_in_body():
    body = f'config = {{"aws": "{_AWS}", "g": "{_GOOGLE}", "tok": "password=\\"s3cr3tValue\\""}}'
    findings = SecretsCheck().run(_ctx(_resp(body)))
    titles = " ".join(f.title for f in findings)
    assert "aws_access_key" in titles
    assert "google_api_key" in titles
    assert any(f.severity == Severity.HIGH for f in findings)


def test_secrets_clean_body():
    findings = SecretsCheck().run(_ctx(_resp("nothing sensitive here at all")))
    assert findings == []


@responses.activate
def test_web_cache_deception_detected():
    def cb(request):
        return (200, {"Content-Type": "text/html", "Cache-Control": "public, max-age=60"},
                "<html>" + "x" * 200 + "</html>")

    responses.add_callback(responses.GET, re.compile(r"https://t\.test/.*\.css"), callback=cb)
    original = _resp("<html>" + "x" * 210 + "</html>", url="https://t.test/account")
    findings = WebCacheDeceptionCheck().run(_ctx(original))
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_hpp_detected_when_both_values_reflected():
    def cb(request):
        vals = parse_qs(urlparse(request.url).query).get("q", [])
        return (200, {}, "got: " + " ".join(vals))

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    point = InjectionPoint(method="GET", url="https://t.test/p", param="q", params={"q": "1"})
    findings = HppCheck().test(point, HttpClient())
    assert findings and findings[0].confidence == "tentative"


@responses.activate
def test_hpp_not_detected_when_last_wins():
    def cb(request):
        vals = parse_qs(urlparse(request.url).query).get("q", [])
        return (200, {}, "got: " + (vals[-1] if vals else ""))

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    point = InjectionPoint(method="GET", url="https://t.test/p", param="q", params={"q": "1"})
    assert HppCheck().test(point, HttpClient()) == []
