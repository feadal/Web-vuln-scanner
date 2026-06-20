"""WAF-evasion payload transforms.

Pure string->string mutators distilled from the cybersecurity skill
'performing-web-application-firewall-bypass'. Each can be chained.
"""

from __future__ import annotations

import secrets
import urllib.parse


def url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def space_to_comment(payload: str) -> str:
    return payload.replace(" ", "/**/")


def space_to_tab(payload: str) -> str:
    return payload.replace(" ", "\t")


def random_case(payload: str) -> str:
    return "".join(
        (c.upper() if secrets.randbelow(2) else c.lower()) if c.isalpha() else c for c in payload
    )


_TAMPERS = {
    "url": url_encode,
    "double-url": double_url_encode,
    "space2comment": space_to_comment,
    "space2tab": space_to_tab,
    "randomcase": random_case,
}


def names() -> list[str]:
    return list(_TAMPERS)


def apply(name: str, payload: str) -> str:
    fn = _TAMPERS.get(name)
    return fn(payload) if fn else payload


def chain(tampers, payload: str) -> str:
    for name in tampers:
        payload = apply(name, payload)
    return payload
