"""Unit tests for individual checks.

These tests drive checks with hand-built responses so they run fully offline
and never touch the network.
"""

from __future__ import annotations

import requests

from webscan.checks.cookies import CookieFlagsCheck, _cookie_attrs, _cookie_name
from webscan.checks.forms import FormSecurityCheck
from webscan.checks.security_headers import SecurityHeadersCheck, _parse_max_age
from webscan.checks.server_disclosure import ServerDisclosureCheck
from webscan.http_client import HttpClient
from webscan.models import ScanContext, Severity


def make_response(url="https://example.com/", headers=None, body="", status=200):
    resp = requests.Response()
    resp.status_code = status
    resp.url = url
    resp.headers.update(headers or {})
    resp._content = body.encode("utf-8")
    return resp


def make_ctx(resp, html=""):
    return ScanContext(target="https://example.com", client=HttpClient(), base_response=resp, base_html=html)


def test_missing_headers_are_reported():
    resp = make_response(headers={})
    findings = SecurityHeadersCheck().run(make_ctx(resp))
    titles = {f.title for f in findings}
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_present_headers_are_not_reported():
    resp = make_response(
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
    )
    findings = SecurityHeadersCheck().run(make_ctx(resp))
    assert findings == []


def test_short_hsts_max_age_flagged():
    resp = make_response(
        headers={
            "Strict-Transport-Security": "max-age=100",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
    )
    findings = SecurityHeadersCheck().run(make_ctx(resp))
    assert any("max-age" in f.title for f in findings)


def test_frame_ancestors_satisfies_clickjacking():
    resp = make_response(
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
    )
    findings = SecurityHeadersCheck().run(make_ctx(resp))
    assert not any("clickjacking" in f.title.lower() for f in findings)


def test_parse_max_age():
    assert _parse_max_age("max-age=31536000; includeSubDomains") == 31536000
    assert _parse_max_age("includeSubDomains") is None


def test_cookie_without_flags_is_flagged():
    resp = make_response(headers={"Set-Cookie": "session=abc123; Path=/"})
    findings = CookieFlagsCheck().run(make_ctx(resp))
    severities = {f.title.split("'")[1]: f for f in findings}
    assert "session" in severities
    assert any("HttpOnly" in f.title for f in findings)
    assert any("Secure" in f.title for f in findings)
    assert any("SameSite" in f.title for f in findings)


def test_fully_hardened_cookie_is_clean():
    resp = make_response(
        headers={"Set-Cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"}
    )
    findings = CookieFlagsCheck().run(make_ctx(resp))
    assert findings == []


def test_cookie_parsing_helpers():
    raw = "id=42; Path=/; Secure; HttpOnly"
    assert _cookie_name(raw) == "id"
    assert _cookie_attrs(raw) == {"path", "secure", "httponly"}


def test_server_version_disclosure():
    resp = make_response(headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"})
    findings = ServerDisclosureCheck().run(make_ctx(resp))
    assert len(findings) == 2
    assert all(f.severity == Severity.LOW for f in findings)


def test_server_without_version_is_info():
    resp = make_response(headers={"Server": "cloudflare"})
    findings = ServerDisclosureCheck().run(make_ctx(resp))
    assert findings[0].severity == Severity.INFO


def test_password_form_get_method_is_high():
    html = """
    <form action="/login" method="get">
      <input type="text" name="user">
      <input type="password" name="pass">
    </form>
    """
    resp = make_response(url="https://example.com/", body=html)
    findings = FormSecurityCheck().run(make_ctx(resp, html=html))
    assert any("GET" in f.title and f.severity == Severity.HIGH for f in findings)


def test_password_form_without_csrf_token():
    html = """
    <form action="/login" method="post">
      <input type="password" name="pass">
    </form>
    """
    resp = make_response(body=html)
    findings = FormSecurityCheck().run(make_ctx(resp, html=html))
    assert any("CSRF" in f.title for f in findings)


def test_password_form_with_csrf_token_is_clean():
    html = """
    <form action="/login" method="post">
      <input type="hidden" name="csrf_token" value="xyz">
      <input type="password" name="pass">
    </form>
    """
    resp = make_response(body=html)
    findings = FormSecurityCheck().run(make_ctx(resp, html=html))
    assert not any("CSRF" in f.title for f in findings)
