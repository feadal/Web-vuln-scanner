# webscan

[![CI](https://github.com/feadal/Web-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/feadal/Web-vuln-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

**webscan** is a lightweight **active** web vulnerability scanner in Python for
**authorized** penetration testing, security training and assessing your own apps.

It crawls the target for inputs (URL parameters and form fields), then probes each
one with benign payloads to **detect** real vulnerabilities — reflected XSS, SQL
injection, OS command injection, path traversal/LFI and open redirects — alongside
passive checks for security headers, cookies, TLS and information disclosure.

> **Detection, not exploitation.** Probes are non-destructive: they trigger an
> error, get reflected, read a world-readable file, or echo an arithmetic result.
> webscan reports issues — it never dumps databases, escalates, or weaponises them.

---

## ⚠️ Legal notice

Use webscan **only** against systems you own or have explicit written permission
to test. Unauthorized scanning is illegal in many jurisdictions (e.g. the CFAA in
the US, the Computer Misuse Act in the UK). You are responsible for your use of
this tool; the authors are not. See [SECURITY.md](SECURITY.md).

---

## Features

### Active checks (send probes — authorized targets only)

| Check | Detects | Technique |
|---|---|---|
| `xss` | Reflected cross-site scripting | Unique token in HTML metachars, checks for un-encoded reflection |
| `sqli` | SQL injection | Error-based + boolean differential + time-based blind (`SLEEP`/`pg_sleep`/`WAITFOR`) |
| `cmd-injection` | OS command injection | Arithmetic-echo probe (`$((A*B))`) — shell prints a product not in the payload |
| `ssti` | Server-side template injection | Template math (`{{A*B}}`, `${A*B}`, ...), often a path to RCE |
| `lfi` | Local file inclusion | `php://filter` base64 wrapper confirms PHP source disclosure |
| `path-traversal` | Path traversal | `../`-style payloads, confirms via `/etc/passwd` readback |
| `open-redirect` | Open redirect | Benign external host in redirect params, inspects `Location` |

### Passive checks (always safe)

| Check | Detects |
|---|---|
| `security-headers` | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `cookies` | Cookies without `Secure` / `HttpOnly` / `SameSite` |
| `server-disclosure` | Version leaks via `Server`, `X-Powered-By` |
| `tls` | Plain HTTP, no HTTPS redirect, invalid certificate |
| `sensitive-files` | Exposed `.git/`, `.env`, backups, directory listing |
| `forms` | Forms over HTTP, password via GET, missing CSRF token |

**Safety rails:** same-host crawl scope, a hard request budget (`--max-requests`),
optional throttling (`--delay`), and a bounded crawl depth (`--max-pages`).

## Installation

```bash
git clone https://github.com/feadal/Web-vuln-scanner.git
cd Web-vuln-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Full scan (passive + active)
webscan https://example.com

# Passive only — no probes are sent
webscan https://example.com --passive-only

# Pick specific checks
webscan https://example.com --checks xss,sqli,security-headers

# Critical findings only (hide medium/low noise)
webscan https://example.com --min-severity high

# Tune scope / politeness
webscan https://example.com --max-pages 20 --max-requests 500 --delay 0.2

# JSON report for CI
webscan https://example.com --format json --output report.json

# List every check
webscan --list-checks
```

Exit code: `0` when nothing at/above `--fail-on` (default `medium`) is found, `1`
otherwise — handy in CI pipelines.

## Try it on the included demo target

The repo ships a **deliberately vulnerable** demo app (localhost only) so you can
watch the scanner work safely:

```bash
python examples/vulnerable_app.py        # serves http://127.0.0.1:8000
webscan http://127.0.0.1:8000            # in another terminal
```

```
webscan 0.2.0 — target: http://127.0.0.1:8000
crawled injection points: 5 · requests sent: 96

[HIGH]    cmd-injection     OS command injection
          ↳ Shell evaluated probe on 'host' -> wvs578120end  →  param 'host'
[HIGH]    path-traversal    Path traversal / local file inclusion
          ↳ /etc/passwd content via 'file': root:x:0:0:  →  param 'file'
[HIGH]    sqli              Error-based SQL injection
          ↳ DB error on 'id': You have an error in your SQL syntax  →  param 'id'
[HIGH]    xss               Reflected cross-site scripting (XSS)
          ↳ Probe reflected un-encoded in parameter 'q'  →  param 'q'
[MEDIUM]  open-redirect     Open redirect
          ↳ Location -> https://wvs-...example.org/ (param 'next')  →  param 'next'

Total: 14 findings (6 high, 5 medium, 3 low)
```

## How it works

```
target ──▶ fetch landing page ──▶ passive checks (headers, cookies, TLS, …)
                │
                ▼
          crawler (same-host, bounded) ──▶ injection points (query params + form fields)
                │
                ▼
   for each point × active check ──▶ benign probe ──▶ analyse response ──▶ findings
```

## Development

```bash
pip install -e ".[dev]"
pytest          # 25 offline tests, no network
ruff check .
```

Add a check by subclassing `PassiveCheck` or `ActiveCheck` in `webscan/checks/`
and registering it in `webscan/checks/__init__.py`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
