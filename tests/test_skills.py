"""Tests for the skill-derived checks: JWT weaknesses and forced browsing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

import requests
import responses

from webscan.checks.forced_browsing import ForcedBrowsingCheck
from webscan.checks.jwt import JwtCheck
from webscan.http_client import HttpClient
from webscan.models import ScanContext, Severity


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(header, payload, secret=None) -> str:
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    signing_input = f"{h}.{p}"
    if secret is None:
        return signing_input + "."
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + _b64(sig)


def ctx_with_body(body: str) -> ScanContext:
    resp = requests.Response()
    resp.status_code = 200
    resp.url = "https://t.test/"
    resp._content = body.encode()
    return ScanContext(target="https://t.test/", client=HttpClient(), base_response=resp, base_html="")


def ctx() -> ScanContext:
    return ScanContext(target="https://t.test/", client=HttpClient(), base_response=None, base_html="")


def test_jwt_alg_none_flagged():
    token = make_jwt({"alg": "none", "typ": "JWT"}, {"user": "x", "role": "admin"})
    findings = JwtCheck().run(ctx_with_body(f'{{"token":"{token}"}}'))
    assert any("alg: none" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_jwt_weak_secret_cracked():
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, secret="secret")
    findings = JwtCheck().run(ctx_with_body(f"Authorization: Bearer {token}"))
    assert any("weak HS256" in f.title for f in findings)


def test_jwt_strong_secret_not_cracked():
    token = make_jwt(
        {"alg": "HS256"}, {"sub": "1", "exp": 9999999999},
        secret="3f9a8c-very-long-unguessable-random-secret-2b7e",
    )
    findings = JwtCheck().run(ctx_with_body(token))
    assert not any("weak HS256" in f.title for f in findings)


def test_jwt_missing_exp_flagged():
    token = make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="x")
    findings = JwtCheck().run(ctx_with_body(token))
    assert any("no expiry" in f.title.lower() for f in findings)


@responses.activate
def test_forced_browsing_finds_admin():
    responses.add(responses.GET, "https://t.test/admin", status=200, body="login")
    responses.add(responses.GET, re.compile(r"https://t\.test/.*"), status=404)
    findings = ForcedBrowsingCheck().run(ctx())
    assert any(f.title == "Exposed endpoint: /admin" for f in findings)


@responses.activate
def test_forced_browsing_suppressed_on_catch_all_200():
    responses.add(responses.GET, re.compile(r"https://t\.test/.*"), status=200, body="ok")
    findings = ForcedBrowsingCheck().run(ctx())
    assert findings == []
