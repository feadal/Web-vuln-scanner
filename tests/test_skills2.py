"""Tests for skill-derived depth: DB fingerprint, traversal signatures, SSTI
engine fingerprint, WAF detection, tamper transforms and MITRE tagging."""

from __future__ import annotations

import requests

from webscan import owasp, tamper
from webscan.checks.waf import WafCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, ScanContext, Severity
from webscan.payloads import match_traversal, sql_db_fingerprint, ssti_engine


def test_sql_db_fingerprint():
    assert sql_db_fingerprint("You have an error in your SQL syntax; check the manual") == "MySQL"
    assert sql_db_fingerprint("ERROR: unterminated quoted string at or near") == "PostgreSQL"
    assert sql_db_fingerprint("ORA-00933: SQL command not properly ended") == "Oracle"
    assert sql_db_fingerprint("just plain text") == ""


def test_match_traversal_passwd_and_winini():
    assert match_traversal("root:x:0:0:root:/root:/bin/bash")
    assert match_traversal("[fonts]\r\nfor 16-bit app support")
    assert match_traversal("nothing here") == ""


def test_ssti_engine_fingerprint():
    assert ssti_engine("output: 7777777 done") == "Jinja2"
    assert ssti_engine("output: 49 done") == "Twig"
    assert ssti_engine("no evaluation") == ""


def test_tamper_transforms():
    assert tamper.url_encode("' OR 1=1") == "%27%20OR%201%3D1"
    assert tamper.double_url_encode("'") == "%2527"
    assert tamper.apply("space2comment", "a b") == "a/**/b"
    assert tamper.chain(["url"], "'") == "%27"
    rc = tamper.random_case("UnIoN")
    assert rc.lower() == "union" and len(rc) == 5
    assert "randomcase" in tamper.names()


def test_mitre_tagging():
    f = owasp.tag(Finding(check="sqli", title="x", severity=Severity.HIGH))
    assert "T1190" in f.mitre
    g = owasp.tag(Finding(check="secrets", title="y", severity=Severity.HIGH))
    assert g.mitre == "T1552.001"


def test_waf_detects_cloudflare():
    r = requests.Response()
    r.status_code = 200
    r.url = "https://t.test/"
    r._content = b""
    r.headers.update({"Server": "cloudflare", "CF-RAY": "abc123-LHR"})
    ctx = ScanContext(target="https://t.test/", client=HttpClient(), base_response=r, base_html="")
    findings = WafCheck().run(ctx)
    assert findings and "Cloudflare" in findings[0].title
    assert findings[0].severity == Severity.INFO
