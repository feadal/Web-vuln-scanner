"""Tests for the YAML template engine (matchers, parsing, execution, loading)."""

from __future__ import annotations

import pytest
import responses

from webscan.http_client import HttpClient
from webscan.models import Severity
from webscan.templates_engine import (
    Template,
    evaluate_matchers,
    load_templates,
    match_one,
    parse_template,
    run_template,
)


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def test_match_status_word_regex():
    assert match_one({"type": "status", "status": [200]}, FakeResp(200))
    assert not match_one({"type": "status", "status": [200]}, FakeResp(404))

    body = FakeResp(text="PHP Version 7.4 Configuration")
    assert match_one({"type": "word", "words": ["PHP Version", "Configuration"], "condition": "and"}, body)
    assert not match_one({"type": "word", "words": ["PHP Version", "Nope"], "condition": "and"}, body)

    env = FakeResp(text="DB_PASSWORD=secret")
    assert match_one({"type": "regex", "regex": ["DB_PASSWORD="]}, env)
    assert not match_one({"type": "regex", "regex": ["DB_PASSWORD="], "negative": True}, env)


def test_match_word_in_header_part():
    resp = FakeResp(headers={"Server": "nginx/1.18"})
    assert match_one({"type": "word", "words": ["nginx"], "part": "header"}, resp)


def test_evaluate_and_or():
    resp = FakeResp(200, "abc")
    matchers = [{"type": "status", "status": [200]}, {"type": "word", "words": ["xyz"]}]
    assert evaluate_matchers(matchers, "or", resp)
    assert not evaluate_matchers(matchers, "and", resp)


def test_parse_template():
    t = parse_template(
        {"id": "x", "info": {"name": "X", "severity": "high", "cwe": "CWE-200"},
         "requests": [{"method": "GET"}]}
    )
    assert t.id == "x"
    assert t.severity == Severity.HIGH
    assert t.cwe == "CWE-200"


@responses.activate
def test_run_template_matches():
    responses.add(
        responses.GET, "https://t.test/.env", status=200,
        body="APP_KEY=base64:xxx\nDB_PASSWORD=secret",
    )
    template = Template(
        id="env", name="Exposed env", severity=Severity.HIGH, cwe="CWE-200",
        requests=[{
            "method": "GET", "path": ["{{BaseURL}}/.env"], "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "regex": ["DB_PASSWORD="]},
            ],
        }],
    )
    findings = run_template(template, "https://t.test", HttpClient())
    assert findings and findings[0].check == "template:env"
    assert findings[0].severity == Severity.HIGH


def test_load_builtin_templates():
    pytest.importorskip("yaml")
    templates = load_templates(None)
    ids = {t.id for t in templates}
    assert "exposed-env-file" in ids
    assert all(t.requests for t in templates)
