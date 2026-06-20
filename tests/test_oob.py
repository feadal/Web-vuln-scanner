"""Tests for the out-of-band collaborator and correlation logic."""

from __future__ import annotations

import time

import requests

from webscan.collaborator import HttpCollaborator, correlate
from webscan.models import InjectionPoint, Severity


def test_collaborator_records_callback():
    collab = HttpCollaborator(advertised_host="127.0.0.1", port=0)
    collab.start()
    try:
        token = collab.new_token()
        requests.get(collab.payload_url(token), timeout=5)
        time.sleep(0.1)
        assert collab.received(token)
        assert token in collab.poll()
    finally:
        collab.stop()


def test_collaborator_ignores_unseen_token():
    collab = HttpCollaborator(advertised_host="1.2.3.4", port=0)
    collab.start()
    try:
        url = collab.payload_url("wvsabc")
        assert url.startswith("http://1.2.3.4:")
        assert url.endswith("/wvsabc")
        assert not collab.received("never-called")
    finally:
        collab.stop()


def test_correlate_maps_hits_to_findings():
    point = InjectionPoint(method="GET", url="https://t.test/p", param="url", params={"url": "x"})
    registry = {
        "tokA": (point, "blind SSRF"),
        "tokB": (point, "blind OS command injection"),
    }
    findings = correlate({"tokA"}, registry)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "SSRF" in findings[0].title
    assert findings[0].param == "url"
    assert findings[0].confidence == "firm"
