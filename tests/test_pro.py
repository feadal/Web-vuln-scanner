"""Tests for the professional-tier features: OWASP/CWE tagging, SARIF,
nuclei parsing and the GraphQL introspection check."""

from __future__ import annotations

import json
import re

import responses

from webscan import owasp
from webscan.checks.graphql_introspection import GraphqlIntrospectionCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, ScanContext, ScanResult, Severity
from webscan.nuclei import parse_jsonl
from webscan.report import render_sarif


def test_owasp_cwe_tagging():
    f = owasp.tag(Finding(check="sqli", title="x", severity=Severity.HIGH))
    assert f.cwe == "CWE-89"
    assert "A03" in f.owasp
    g = owasp.tag(Finding(check="ssrf", title="y", severity=Severity.HIGH))
    assert g.cwe == "CWE-918"


def test_sarif_output_is_valid():
    result = ScanResult(target="https://t.test/")
    result.findings = [
        Finding(check="sqli", title="SQL injection", severity=Severity.HIGH,
                url="https://t.test/?id=1", cwe="CWE-89", owasp="A03:2021 Injection")
    ]
    doc = json.loads(render_sarif(result))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "webscan"
    res = run["results"][0]
    assert res["ruleId"] == "sqli"
    assert res["level"] == "error"
    assert "CWE-89" in res["properties"]["tags"]


def test_nuclei_jsonl_parsing():
    line = json.dumps({
        "template-id": "git-config",
        "info": {"name": "Git Config Exposure", "severity": "medium",
                 "classification": {"cwe-id": ["cwe-200"]}, "tags": ["exposure"]},
        "matched-at": "https://t.test/.git/config",
        "host": "https://t.test",
    })
    findings = parse_jsonl(line + "\n\n")
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "nuclei:git-config"
    assert f.severity == Severity.MEDIUM
    assert "CWE-200" in f.cwe


@responses.activate
def test_graphql_introspection_detected():
    responses.add(
        responses.GET,
        "https://t.test/graphql",
        json={"data": {"__schema": {"queryType": {"name": "Query"}}}},
    )
    responses.add(responses.GET, re.compile(r"https://t\.test/.*"), status=404)
    ctx = ScanContext(target="https://t.test/", client=HttpClient(), base_response=None, base_html="")
    findings = GraphqlIntrospectionCheck().run(ctx)
    assert findings and findings[0].severity == Severity.MEDIUM
