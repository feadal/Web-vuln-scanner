"""Tests for the extended checks (CRLF, NoSQLi, XXE, CORS, host header, methods)
and infrastructure (param guessing, HTML report)."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import responses

from webscan import crawler
from webscan.checks.active.crlf import CrlfCheck
from webscan.checks.active.nosqli import NoSqlInjectionCheck
from webscan.checks.active.xxe import XxeCheck
from webscan.checks.cors import CorsCheck
from webscan.checks.host_header import HostHeaderCheck
from webscan.checks.http_methods import HttpMethodsCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, ScanContext, ScanResult, Severity
from webscan.report import render_html


def _q(request, name):
    return parse_qs(urlparse(request.url).query).get(name, [""])[0]


def point(param="q", value="1"):
    return InjectionPoint(method="GET", url="https://t.test/p", param=param, params={param: value})


def ctx():
    return ScanContext(target="https://t.test/", client=HttpClient(), base_response=None, base_html="")


@responses.activate
def test_crlf_detected():
    def cb(request):
        m = re.search(r"(X-Wvs-[0-9a-f]+):([0-9a-f]+)", _q(request, "q"))
        if m:
            return (200, {m.group(1): m.group(2)}, "ok")
        return (200, {}, "ok")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = CrlfCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_nosqli_detected():
    def cb(request):
        v = _q(request, "q")
        if "||" in v or "$ne" in v or "$gt" in v:
            return (200, {}, "MongoDBError: $where evaluation failed")
        return (200, {}, "ok")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = NoSqlInjectionCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_xxe_detected_for_xml_param():
    def cb(request):
        if "file:///etc/passwd" in _q(request, "data"):
            return (200, {}, "root:x:0:0:root:/root:/bin/bash")
        return (200, {}, "ok")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = XxeCheck().test(point(param="data", value="<a/>"), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH


def test_xxe_skips_non_xml_param():
    assert XxeCheck().test(point(param="q", value="hello"), HttpClient()) == []


@responses.activate
def test_cors_reflects_origin_with_credentials():
    def cb(request):
        origin = request.headers.get("Origin", "")
        headers = {}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return (200, headers, "ok")

    responses.add_callback(responses.GET, "https://t.test/", callback=cb)
    findings = CorsCheck().run(ctx())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_host_header_reflected():
    def cb(request):
        xfh = request.headers.get("X-Forwarded-Host", "")
        return (200, {}, f"<a href='http://{xfh}/reset'>reset</a>")

    responses.add_callback(responses.GET, "https://t.test/", callback=cb)
    findings = HostHeaderCheck().run(ctx())
    assert findings and findings[0].severity == Severity.MEDIUM


@responses.activate
def test_http_methods_flagged():
    responses.add(
        method="OPTIONS",
        url="https://t.test/",
        headers={"Allow": "GET, POST, PUT, DELETE, TRACE"},
    )
    findings = HttpMethodsCheck().run(ctx())
    assert findings and findings[0].severity == Severity.MEDIUM


def test_guessed_points():
    pts = crawler.guessed_points("https://t.test/index.php?x=1")
    names = {p.param for p in pts}
    assert {"page", "file", "id", "url"} <= names
    assert all(p.method == "GET" and p.url == "https://t.test/index.php" for p in pts)


def test_html_report_renders_findings():
    result = ScanResult(target="https://t.test/")
    result.findings = [
        Finding(check="sqli", title="Error-based SQL injection", severity=Severity.HIGH,
                param="id", evidence="boom")
    ]
    out = render_html(result)
    assert "<table" in out
    assert "Error-based SQL injection" in out
    assert "HIGH" in out
