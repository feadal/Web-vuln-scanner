# webscan

[![CI](https://github.com/feadal/Web-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/feadal/Web-vuln-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Checks](https://img.shields.io/badge/checks-30-2ea043.svg)](#features)
[![Tests](https://img.shields.io/badge/tests-85-2ea043.svg)](tests)

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

## Highlights

- 🧵 **Concurrent engine** with a global request budget and rate limiting
- 🛡️ **30 checks** across the OWASP Top 10 — passive recon + active probing
- 🌐 **Headless-browser crawling** (Playwright) for SPA / JS-rendered apps
- 📡 **Out-of-band (OAST)** detection of blind SSRF / RCE via a built-in collaborator
- 🧩 **YAML detection templates** (nuclei-style) — add checks without code
- 🔌 **Nuclei integration** — merge thousands of community templates
- 🏷️ **OWASP Top 10 + CWE + MITRE ATT&CK** tags on every finding
- 🥷 **WAF detection** + chainable WAF-evasion transforms (`--tamper`)
- 📤 Output as **text / JSON / HTML / SARIF** (GitHub code scanning, CI)
- 🔐 **Authenticated scanning** (`--cookie` / `--header`) + hidden-parameter discovery
- 🎯 Context-aware XSS, multi-technique SQLi (error / boolean / time-based)
- 📟 **Live progress** — phases, request counter and findings stream as they're found (`--quiet` to hush)
- 🧪 **85 offline tests**, CI on Python 3.9–3.12

---

## Features

### Active checks (send probes — authorized targets only)

| Check | Detects | Technique |
|---|---|---|
| `xss` | Reflected cross-site scripting | Unique token in HTML metachars, checks for un-encoded reflection |
| `sqli` | SQL injection | Error-based + boolean differential + time-based blind (`SLEEP`/`pg_sleep`/`WAITFOR`) |
| `nosqli` | NoSQL injection | Operator payloads (`$ne`, `$gt`, `||`) that surface MongoDB/BSON errors |
| `cmd-injection` | OS command injection | Arithmetic-echo probe (`$((A*B))`) — shell prints a product not in the payload |
| `xxe` | XML external entity | XML params get an entity reading `/etc/passwd` |
| `crlf` | CRLF / header injection | Newline payload injects a marker response header |
| `hpp` | HTTP parameter pollution | Duplicate parameter, both values reflected/used |
| `mass-assignment` | Mass assignment | Privileged field (`role`) accepted & reflected on POST |
| `idor` | IDOR / object enumeration | Numeric reference neighbours return distinct data (hint) |
| `ssti` | Server-side template injection | Template math (`{{A*B}}`, `${A*B}`, ...), often a path to RCE |
| `lfi` | Local file inclusion | `php://filter` base64 wrapper confirms PHP source disclosure |
| `ssrf` | Server-side request forgery | Cloud metadata endpoints + canary URL whose fetched content is reflected |
| `path-traversal` | Path traversal | `../`-style payloads, confirms via `/etc/passwd` readback |
| `open-redirect` | Open redirect | Benign external host in redirect params, inspects `Location` |

### Passive checks (always safe)

| Check | Detects |
|---|---|
| `security-headers` | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `cookies` | Cookies without `Secure` / `HttpOnly` / `SameSite` |
| `server-disclosure` | Version leaks via `Server`, `X-Powered-By` |
| `waf` | Fingerprints a WAF / CDN (Cloudflare, Akamai, Imperva, ...) |
| `tls` | Plain HTTP, no HTTPS redirect, invalid certificate |
| `sensitive-files` | Exposed `.git/`, `.env`, DB dumps, backups, directory listing |
| `forms` | Forms over HTTP, password via GET, missing CSRF token |
| `cors` | Permissive CORS (reflected Origin, wildcard, credentials) |
| `host-header` | Spoofed `Host` / `X-Forwarded-Host` reflected (poisoning) |
| `http-methods` | Dangerous methods enabled (`PUT`, `DELETE`, `TRACE`) |
| `jwt` | JWTs with `alg:none`, weak HS256 secret, or no expiry |
| `forced-browsing` | Exposed admin panels / debug endpoints (`/admin`, `/actuator`, `/graphql`, ...) |
| `graphql` | GraphQL endpoint with introspection enabled |
| `secrets` | Hardcoded API keys / tokens / private keys in responses & JS |
| `web-cache-deception` | Dynamic page served as cacheable static (cache deception) |
| `web-cache-poisoning` | Reflected unkeyed header in a cacheable response |

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

# Probe common hidden parameters (page, file, url, id, ...)
webscan https://example.com --guess-params

# Scan behind a login (session cookie + custom header)
webscan https://example.com --cookie "session=abc; role=admin" --header "Authorization: Bearer TOKEN"

# HTML report
webscan https://example.com --format html -o report.html

# Fast concurrent scan + SARIF for CI / GitHub code scanning
webscan https://example.com --threads 20 --format sarif -o webscan.sarif

# Merge in nuclei's template coverage (requires nuclei on PATH)
webscan https://example.com --nuclei

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

## Engine

- **Concurrent active scanning** — a thread pool fuzzes injection points in parallel (`--threads`), with a global request budget and optional rate limiting.
- **OWASP Top 10 + CWE + MITRE ATT&CK mapping** — every finding is tagged (e.g. `CWE-89` / `A03:2021 Injection` / `T1190`) for triage and reporting.
- **Depth from real tradecraft** — DB fingerprinting on SQLi, template-engine fingerprinting on SSTI, IP-encoding SSRF bypasses, and `--tamper` WAF-evasion (url/double-url/comment/case), distilled from a 750-skill cybersecurity corpus.
- **Output for humans and machines** — `text`, `json`, `html`, and **SARIF** (`--format sarif`) for GitHub code scanning / CI.
- **Nuclei integration** — `--nuclei` runs ProjectDiscovery's nuclei and merges its template findings.
- **Auth-aware** — scan behind a login with `--cookie` / `--header`; discover hidden inputs with `--guess-params`.

## Headless-browser crawling (SPA / JS apps)

The static crawler only parses server-rendered HTML. For React/Vue/Angular apps,
enable the optional headless browser — it renders the page, captures XHR/fetch
API calls and DOM forms, and feeds those endpoints to the active checks.

```bash
pip install -e ".[browser]"
playwright install chromium
webscan https://app.example.com --browser
```

## Out-of-band detection (blind vulns)

Blind SSRF / RCE leave no trace in the response. Enable the built-in OAST
collaborator: payloads carry a unique token, and if the target calls back to the
collaborator, the blind vulnerability is **confirmed** (no false positives — our
own client never follows the callback).

```bash
# the target must be able to reach --oob-host (your public IP / forwarded port)
webscan https://example.com --oob --oob-host YOUR_PUBLIC_IP --oob-port 8000
```

## Detection templates (YAML, no code)

Add checks declaratively in YAML — nuclei-style requests + matchers
(`status` / `word` / `regex`, with `and`/`or` and `negative`). Bundled templates
live in `webscan/templates/`; point `--templates DIR` at your own or community ones.

```bash
pip install -e ".[templates]"
webscan https://example.com --templates                 # bundled templates
webscan https://example.com --templates ./my-templates  # your own
```

```yaml
id: exposed-env-file
info: { name: Exposed .env file, severity: high, cwe: CWE-200 }
requests:
  - method: GET
    path: ["{{BaseURL}}/.env"]
    matchers-condition: and
    matchers:
      - { type: status, status: [200] }
      - { type: regex, part: body, regex: ["DB_PASSWORD=", "APP_KEY="] }
```

## Roadmap

Toward professional-grade coverage (contributions welcome):

- [x] Headless-browser crawling (Playwright) for SPA / JS-rendered apps
- [x] Out-of-band (OAST) collaborator for blind SSRF / RCE
- [ ] DNS-based OAST + blind XXE/SQLi templates; multi-page browser crawl + DOM-XSS
- [ ] Async (httpx/asyncio) request engine with token-bucket rate limiting
- [ ] YAML detection-template engine (nuclei-style matchers/extractors)
- [x] Context-aware XSS (reflection-context classification: HTML/attribute/JS/comment)
- [x] YAML detection-template engine (nuclei-style matchers)
- [x] More checks: secrets, web cache deception, web cache poisoning, HPP, mass assignment, IDOR hint
- [ ] Request smuggling (needs a raw-socket transport) + second-order SQLi (needs stateful crawl)
- [ ] Blind SQLi data extraction (binary-search bisection — exploitation, sqlmap territory) helpers

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
