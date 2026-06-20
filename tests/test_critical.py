"""Tests for the critical active checks: SSTI, LFI, and time-based SQLi logic."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import responses

from webscan.checks.active.lfi import LfiCheck
from webscan.checks.active.ssti import SstiCheck
from webscan.http_client import HttpClient
from webscan.models import InjectionPoint, Severity
from webscan.payloads import time_based_triggered


def _param(request, name):
    return parse_qs(urlparse(request.url).query).get(name, [""])[0]


def point(param="q", value="1"):
    return InjectionPoint(method="GET", url="https://t.test/p", param=param, params={param: value})


@responses.activate
def test_ssti_detected_when_evaluated():
    def cb(request):
        v = _param(request, "q")
        m = re.search(r"(\d+)\*(\d+)", v)
        if m and "{{" in v:
            return (200, {}, f"<p>ssti{int(m.group(1)) * int(m.group(2))}end</p>")
        return (200, {}, "<p>" + v + "</p>")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = SstiCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH
    assert findings[0].title.startswith("Server-side template injection")


@responses.activate
def test_ssti_not_detected_when_literal():
    def cb(request):
        return (200, {}, "<p>" + _param(request, "q") + "</p>")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    assert SstiCheck().test(point(), HttpClient()) == []


@responses.activate
def test_lfi_php_filter_detected():
    def cb(request):
        v = _param(request, "page")
        if "php://filter" in v:
            return (200, {}, "PD9waHAgZWNobyAxOyA/Pg==")
        return (200, {}, "home page")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = LfiCheck().test(point(param="page", value="home"), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_lfi_not_detected_without_disclosure():
    def cb(request):
        return (200, {}, "nothing here")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    assert LfiCheck().test(point(param="page", value="home"), HttpClient()) == []


def test_time_based_decision():
    assert time_based_triggered(0.3, 3.4, 3) is True
    assert time_based_triggered(0.3, 0.6, 3) is False
    assert time_based_triggered(3.1, 3.5, 3) is False
