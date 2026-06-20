"""End-to-end tests for the scanner and result model using mocked HTTP."""

from __future__ import annotations

import responses

from webscan.models import ScanResult, Severity
from webscan.scanner import Scanner, _normalize_target


def test_normalize_target_adds_scheme():
    assert _normalize_target("example.com") == "https://example.com"
    assert _normalize_target("http://example.com") == "http://example.com"
    assert _normalize_target("  https://example.com  ") == "https://example.com"


@responses.activate
def test_scan_collects_findings_from_insecure_site():
    responses.add(
        responses.GET,
        "https://example.com/",
        body="<html><body>hello</body></html>",
        status=200,
        headers={"Server": "nginx/1.18.0", "Set-Cookie": "sid=1; Path=/"},
        content_type="text/html",
    )
    responses.add(responses.GET, "https://example.com/.git/config", status=404)

    result = Scanner().scan("https://example.com")

    assert isinstance(result, ScanResult)
    assert result.max_severity() is not None
    checks_hit = {f.check for f in result.findings}
    assert "security-headers" in checks_hit
    assert "cookies" in checks_hit


@responses.activate
def test_scan_records_error_when_target_unreachable():
    result = Scanner().scan("https://unreachable.invalid")
    assert result.errors
    assert result.findings == []


def test_result_counts_and_sorting():
    from webscan.models import Finding

    result = ScanResult(target="https://example.com")
    result.findings = [
        Finding(check="a", title="low", severity=Severity.LOW),
        Finding(check="b", title="high", severity=Severity.HIGH),
        Finding(check="c", title="info", severity=Severity.INFO),
    ]
    ordered = result.sorted_findings()
    assert [f.severity for f in ordered] == [Severity.HIGH, Severity.LOW, Severity.INFO]
    assert result.counts()["high"] == 1
    assert result.max_severity() == Severity.HIGH
