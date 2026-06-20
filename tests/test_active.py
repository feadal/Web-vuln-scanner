"""Tests for the active checks and the crawler, fully offline via mocked HTTP.

Each test simulates a vulnerable endpoint with a ``responses`` callback so the
detection logic is exercised without touching a real server.
"""

from __future__ import annotations

import html as html_lib
import re
from urllib.parse import parse_qs, urlparse

import responses

from webscan import crawler
from webscan.checks.active.command_injection import CommandInjectionCheck
from webscan.checks.active.open_redirect import OpenRedirectCheck
from webscan.checks.active.path_traversal import PathTraversalCheck
from webscan.checks.active.sqli import SqlInjectionCheck
from webscan.checks.active.xss import ReflectedXssCheck
from webscan.http_client import HttpClient
from webscan.models import InjectionPoint, Severity


def _param(request, name):
    return parse_qs(urlparse(request.url).query).get(name, [""])[0]


def point(url="https://t.test/p", param="q", value="1", method="GET"):
    return InjectionPoint(method=method, url=url, param=param, params={param: value})


@responses.activate
def test_xss_detected_when_reflected_raw():
    def cb(request):
        return (200, {}, f"<html>You searched: {_param(request, 'q')}</html>")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = ReflectedXssCheck().test(point(), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH
    assert findings[0].confidence == "firm"


@responses.activate
def test_xss_not_detected_when_encoded():
    def cb(request):
        return (200, {}, f"<html>You searched: {html_lib.escape(_param(request, 'q'))}</html>")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = ReflectedXssCheck().test(point(), HttpClient())
    assert findings == []


@responses.activate
def test_sqli_error_based_detected():
    def cb(request):
        value = _param(request, "id")
        if "'" in value or '"' in value:
            body = "Warning: mysqli_query(): You have an error in your SQL syntax near '''"
        else:
            body = "ok"
        return (200, {}, body)

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = SqlInjectionCheck().test(point(param="id"), HttpClient())
    assert findings and findings[0].title.startswith("Error-based")
    assert findings[0].severity == Severity.HIGH


@responses.activate
def test_path_traversal_detected():
    def cb(request):
        value = _param(request, "file")
        if "etc/passwd" in value:
            return (200, {}, "root:x:0:0:root:/root:/bin/bash\n")
        return (200, {}, "not found")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = PathTraversalCheck().test(point(param="file"), HttpClient())
    assert findings and findings[0].severity == Severity.HIGH


@responses.activate
def test_open_redirect_detected():
    def cb(request):
        return (302, {"Location": _param(request, "next")}, "")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = OpenRedirectCheck().test(point(param="next", value="/home"), HttpClient())
    assert findings and findings[0].title == "Open redirect"


@responses.activate
def test_open_redirect_ignored_for_non_redirect_param():
    findings = OpenRedirectCheck().test(point(param="q", value="hello"), HttpClient())
    assert findings == []


@responses.activate
def test_command_injection_detected():
    def cb(request):
        cmd = _param(request, "host")
        m = re.search(r"\$\(\((\d+)\*(\d+)\)\)", cmd)
        if m:
            product = int(m.group(1)) * int(m.group(2))
            return (200, {}, f"PING output wvs{product}end ...")
        return (200, {}, "PING output ...")

    responses.add_callback(responses.GET, "https://t.test/p", callback=cb)
    findings = CommandInjectionCheck().test(point(param="host"), HttpClient())
    assert findings and findings[0].title == "OS command injection"


def test_crawler_discovers_query_and_form_inputs():
    base_url = "https://t.test/page?id=1"
    html = (
        '<form action="/login" method="post">'
        '<input name="user"><input name="pass" type="password">'
        '<input type="submit" value="go"></form>'
        '<a href="/other?x=2">link</a>'
    )
    points = crawler.discover(HttpClient(), base_url, html, max_pages=1)
    names = {p.param for p in points}
    assert "id" in names
    assert {"user", "pass"} <= names
    assert "go" not in names
    login = [p for p in points if p.param == "user"][0]
    assert login.method == "POST"
    assert login.url == "https://t.test/login"
