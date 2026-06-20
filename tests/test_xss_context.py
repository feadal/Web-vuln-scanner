"""Tests for context-aware XSS classification and detection."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import responses

from webscan.checks.active.xss import ReflectedXssCheck
from webscan.http_client import HttpClient
from webscan.models import InjectionPoint, Severity
from webscan.payloads import classify_xss_context


def _q(request, name):
    return parse_qs(urlparse(request.url).query).get(name, [""])[0]


def point(param="q", value="1"):
    return InjectionPoint(method="GET", url="https://t.test/p", param=param, params={param: value})


def test_classify_contexts():
    assert classify_xss_context("<p>MARK</p>", "MARK") == "html-text"
    assert classify_xss_context('<input value="MARK">', "MARK") == "attr-double"
    assert classify_xss_context("<input value='MARK'>", "MARK") == "attr-single"
    assert classify_xss_context('<script>var x="MARK";</script>', "MARK") == "js-string-double"
    assert classify_xss_context("<!-- MARK -->", "MARK") == "html-comment"


@responses.activate
def test_xss_attribute_context_detected():
    def cb(request):
        return (200, {}, f'<input type="text" value="{_q(request, "q")}">')

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = ReflectedXssCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH
    assert "attr" in findings[0].title


@responses.activate
def test_xss_attribute_context_encoded_is_safe():
    import html as html_lib

    def cb(request):
        return (200, {}, f'<input value="{html_lib.escape(_q(request, "q"), quote=True)}">')

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    assert ReflectedXssCheck().test(point(), HttpClient()) == []


@responses.activate
def test_xss_html_text_context_detected():
    def cb(request):
        return (200, {}, f"<div>Results: {_q(request, 'q')}</div>")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = ReflectedXssCheck().test(point(), HttpClient())
    assert findings and "html-text" in findings[0].title
