"""Payloads and detection signatures used by the active checks.

Everything here is intentionally *non-destructive*: probes either trigger an
error message, get reflected, or read a world-readable file (``/etc/passwd``).
None of them modify data, escalate access, or run harmful commands.
"""

from __future__ import annotations

import re

# --- SQL injection ----------------------------------------------------------

# Single payloads likely to break a naive query and surface a DB error.
SQLI_ERROR_PAYLOADS = ["'", '"', "')", "';", "' OR '1"]

# Signatures of database error messages, by engine.
SQL_ERROR_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning: mysqli?_",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sqlstate\[",
        r"pg_query\(\)|pg_exec\(\)",
        r"psql: error",
        r"sqlite3?\.(operational|programming)error|sqlite_error",
        r"ora-\d{5}",
        r"microsoft (ole db|odbc) .*?sql server",
        r"odbc sql server driver",
        r"mysql_fetch_(array|assoc|row)\(\)",
        r"supplied argument is not a valid mysql",
        r"npgsql\.",
    ]
]

# Boolean-based differential pair (tentative signal).
SQLI_TRUE_PAYLOAD = "' OR '1'='1"
SQLI_FALSE_PAYLOAD = "' AND '1'='2"


def match_sql_error(body: str) -> str:
    """Return the matched error fragment, or '' if none of the signatures hit."""
    if not body:
        return ""
    for sig in SQL_ERROR_SIGNATURES:
        m = sig.search(body)
        if m:
            return m.group(0)
    return ""


# --- Path traversal / LFI ---------------------------------------------------

TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
]

# A real /etc/passwd line looks like "root:x:0:0:root:/root:/bin/bash".
PASSWD_RE = re.compile(r"root:.*?:0:0:")


def match_passwd(body: str) -> str:
    if not body:
        return ""
    m = PASSWD_RE.search(body)
    return m.group(0) if m else ""


# --- Open redirect ----------------------------------------------------------

# Parameter names that commonly carry a redirect target.
REDIRECT_PARAM_NAMES = {
    "url", "u", "next", "redirect", "redirect_uri", "redirect_url", "return",
    "returnurl", "return_url", "dest", "destination", "continue", "goto", "to",
    "out", "view", "go", "link", "target",
}


# --- Reflected XSS -----------------------------------------------------------

# The probe carries a unique token plus HTML metacharacters. If the metachars
# come back un-encoded around the token, the page reflects markup -> XSS.
def xss_probe(token: str) -> str:
    return f'wvs{token}"\'><svg/onload=1>'


def xss_reflected_raw(body: str, token: str) -> bool:
    if not body:
        return False
    marker = f"wvs{token}"
    if marker not in body:
        return False
    # The angle brackets/tag survived un-encoded next to our token.
    return f"{marker}\"'><svg/onload=1>" in body or "<svg/onload=1>" in body


# --- OS command injection ---------------------------------------------------

def cmdi_payloads(a: int, b: int, left: str, right: str) -> list[str]:
    """Arithmetic-echo probes: the shell prints ``left + (a*b) + right``.

    The product is computed by the shell and never appears literally in the
    payload, so a plain reflection of the input cannot produce a false match.
    """
    expr = f"$(({a}*{b}))"
    inner = f"echo {left}{expr}{right}"
    return [
        f"; {inner}",
        f"| {inner}",
        f"& {inner}",
        f"$({inner})",
        f"`{inner}`",
        f"%0a{inner}",
    ]


def cmdi_expected(a: int, b: int, left: str, right: str) -> str:
    return f"{left}{a * b}{right}"
