"""Map each check to an OWASP Top 10 category and a CWE identifier."""

from __future__ import annotations

from webscan.models import Finding

_MAP = {
    "xss": ("A03:2021 Injection", "CWE-79"),
    "sqli": ("A03:2021 Injection", "CWE-89"),
    "nosqli": ("A03:2021 Injection", "CWE-943"),
    "cmd-injection": ("A03:2021 Injection", "CWE-78"),
    "ssti": ("A03:2021 Injection", "CWE-1336"),
    "crlf": ("A03:2021 Injection", "CWE-113"),
    "host-header": ("A03:2021 Injection", "CWE-644"),
    "hpp": ("A03:2021 Injection", "CWE-235"),
    "lfi": ("A01:2021 Broken Access Control", "CWE-98"),
    "path-traversal": ("A01:2021 Broken Access Control", "CWE-22"),
    "open-redirect": ("A01:2021 Broken Access Control", "CWE-601"),
    "forced-browsing": ("A01:2021 Broken Access Control", "CWE-425"),
    "idor": ("A01:2021 Broken Access Control", "CWE-639"),
    "mass-assignment": ("A01:2021 Broken Access Control", "CWE-915"),
    "web-cache-poisoning": ("A05:2021 Security Misconfiguration", "CWE-525"),
    "ssrf": ("A10:2021 SSRF", "CWE-918"),
    "xxe": ("A05:2021 Security Misconfiguration", "CWE-611"),
    "cors": ("A05:2021 Security Misconfiguration", "CWE-942"),
    "http-methods": ("A05:2021 Security Misconfiguration", "CWE-650"),
    "security-headers": ("A05:2021 Security Misconfiguration", "CWE-693"),
    "cookies": ("A05:2021 Security Misconfiguration", "CWE-614"),
    "server-disclosure": ("A05:2021 Security Misconfiguration", "CWE-200"),
    "sensitive-files": ("A05:2021 Security Misconfiguration", "CWE-538"),
    "graphql": ("A05:2021 Security Misconfiguration", "CWE-200"),
    "forms": ("A05:2021 Security Misconfiguration", "CWE-319"),
    "tls": ("A02:2021 Cryptographic Failures", "CWE-319"),
    "jwt": ("A02:2021 Cryptographic Failures", "CWE-347"),
    "secrets": ("A02:2021 Cryptographic Failures", "CWE-798"),
    "web-cache-deception": ("A05:2021 Security Misconfiguration", "CWE-525"),
}


_MITRE = {
    "sqli": "T1190", "nosqli": "T1190", "xss": "T1190", "crlf": "T1190",
    "ssti": "T1190, T1059", "cmd-injection": "T1190, T1059",
    "lfi": "T1190, T1083", "path-traversal": "T1190, T1083",
    "xxe": "T1190, T1059.007", "ssrf": "T1190", "open-redirect": "T1190",
    "hpp": "T1190", "mass-assignment": "T1190", "idor": "T1190, T1083",
    "forced-browsing": "T1190, T1083", "graphql": "T1190",
    "jwt": "T1552, T1078", "secrets": "T1552.001",
    "web-cache-deception": "T1190", "web-cache-poisoning": "T1190",
}


def tag(finding: Finding) -> Finding:
    key = finding.check.split(":", 1)[0]
    owasp, cwe = _MAP.get(key, ("", ""))
    if not finding.owasp:
        finding.owasp = owasp
    if not finding.cwe:
        finding.cwe = cwe
    if not finding.mitre:
        finding.mitre = _MITRE.get(key, "")
    return finding
