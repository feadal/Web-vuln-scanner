"""Tests for the live progress reporter."""

from __future__ import annotations

import io

from webscan.models import Finding, Severity
from webscan.progress import NullReporter, Reporter


def test_reporter_emits_phases_findings_and_progress():
    buf = io.StringIO()
    r = Reporter(stream=buf, color=False)
    r.phase("Passive checks (15)")
    r.finding(Finding(check="sqli", title="SQL injection", severity=Severity.HIGH, param="id"))
    r.active(2, 5, 120)
    r.active(5, 5, 300)
    r.close()
    out = buf.getvalue()
    assert "Passive checks (15)" in out
    assert "sqli" in out and "SQL injection" in out and "[HIGH]" in out
    assert "[id]" in out
    assert "5/5 points" in out
    assert "300 requests" in out


def test_null_reporter_is_noop():
    r = NullReporter()
    r.phase("x")
    r.info("y")
    r.finding(None)
    r.active(1, 1, 1)
    r.close()
