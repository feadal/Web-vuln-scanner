"""Tests for the SSRF active check."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import responses

from webscan.checks.active.ssrf import SsrfCheck
from webscan.http_client import HttpClient
from webscan.models import InjectionPoint, Severity


def _param(request, name):
    return parse_qs(urlparse(request.url).query).get(name, [""])[0]


def point(param="url", value="http://a"):
    return InjectionPoint(method="GET", url="https://t.test/p", param=param, params={param: value})


@responses.activate
def test_ssrf_metadata_detected():
    def cb(request):
        if "169.254.169.254" in _param(request, "url"):
            return (200, {}, "ami-id\nhostname\niam/\ninstance-id\n")
        return (200, {}, "ok")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = SsrfCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH
    assert "metadata" in findings[0].title.lower()


@responses.activate
def test_ssrf_canary_reflection_detected():
    def cb(request):
        if "example.com" in _param(request, "url"):
            return (200, {}, "<title>Example Domain</title> illustrative examples")
        return (200, {}, "ok")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = SsrfCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_ssrf_ignored_for_non_url_param():
    findings = SsrfCheck().test(point(param="q", value="hello"), HttpClient())
    assert findings == []
