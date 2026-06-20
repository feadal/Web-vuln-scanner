# Changelog

All notable changes to webscan are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.3.0]

Professional-tier release.

### Added
- Concurrent active scanning (`--threads`) with a thread-safe request budget.
- Out-of-band (OAST) collaborator (`--oob`) confirming blind SSRF / RCE via callbacks.
- Headless-browser crawling (`--browser`, Playwright) for SPA / JS-rendered apps.
- YAML detection-template engine (`--templates`) with bundled and custom templates.
- Nuclei integration (`--nuclei`) to merge community-template findings.
- Context-aware XSS detection (HTML / attribute / JS / comment contexts).
- Time-based blind SQL injection (in addition to error-based and boolean).
- New checks: `lfi`, `ssti`, `ssrf`, `xxe`, `crlf`, `nosqli`, `cors`, `host-header`,
  `http-methods`, `jwt`, `forced-browsing`, `graphql`, `secrets`,
  `web-cache-deception`, `web-cache-poisoning`, `hpp`, `mass-assignment`, `idor`.
- OWASP Top 10 + CWE + MITRE ATT&CK tagging on every finding.
- `waf` check (Cloudflare/Akamai/Imperva/... fingerprinting).
- WAF-evasion transforms (`--tamper`: url, double-url, space2comment, space2tab, randomcase).
- Deeper detection: SQLi database fingerprinting, SSTI template-engine fingerprinting,
  expanded path-traversal (Windows win.ini) and SSRF (IP-encoding / multi-cloud) payloads.
- SARIF and HTML output (`--format sarif|html`) for CI / GitHub code scanning.
- Authenticated scanning (`--cookie`, `--header`) and hidden-parameter discovery (`--guess-params`).
- `--min-severity` filter.
- Live progress reporting (phases, request counter, findings as they're found; `--quiet` to disable).

### Changed
- Findings carry `cwe`, `owasp`, and `confidence` fields.
- Reporting groups and sorts findings by severity.

## [0.2.0]

- Reframed as an active scanner: crawler discovers injection points; active checks
  for reflected XSS, SQL injection, OS command injection, path traversal, open redirect.
- Bundled intentionally vulnerable demo app for local testing.

## [0.1.0]

- Initial passive scanner: security headers, cookie flags, TLS, server disclosure,
  sensitive files, insecure forms.
