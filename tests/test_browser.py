"""Tests for the headless-browser crawler's pure conversion logic.

These do not launch a browser — they exercise records_to_points, which turns
captured network traffic and DOM forms into injection points.
"""

from __future__ import annotations

from webscan.browser_crawler import records_to_points


def test_records_to_points_query_post_and_form():
    records = [
        {"method": "GET", "url": "https://t.test/api/items?id=5&sort=asc",
         "post_data": "", "content_type": "", "resource_type": "xhr"},
        {"method": "POST", "url": "https://t.test/api/login",
         "post_data": "user=a&pass=b", "content_type": "application/x-www-form-urlencoded",
         "resource_type": "fetch"},
        {"method": "GET", "url": "https://t.test/app.js",
         "post_data": "", "content_type": "", "resource_type": "script"},
        {"method": "GET", "url": "https://evil.test/x?q=1",
         "post_data": "", "content_type": "", "resource_type": "xhr"},
    ]
    forms = [{"action": "https://t.test/search", "method": "get", "fields": ["q"]}]
    points = records_to_points(records, forms, "t.test")
    pairs = {(p.method, p.param) for p in points}

    assert ("GET", "id") in pairs and ("GET", "sort") in pairs
    assert ("POST", "user") in pairs and ("POST", "pass") in pairs
    assert ("GET", "q") in pairs
    assert all("evil.test" not in p.url for p in points)
    assert not any(p.url.endswith("app.js") for p in points)


def test_records_to_points_dedup():
    records = [
        {"method": "GET", "url": "https://t.test/a?id=1", "post_data": "",
         "content_type": "", "resource_type": "xhr"},
        {"method": "GET", "url": "https://t.test/a?id=2", "post_data": "",
         "content_type": "", "resource_type": "xhr"},
    ]
    points = records_to_points(records, [], "t.test")
    assert len([p for p in points if p.param == "id"]) == 1
