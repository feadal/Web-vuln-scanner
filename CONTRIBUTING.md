# Contributing

Thanks for your interest! Contributions are welcome — from typo fixes to new checks.

## Setup

```bash
git clone https://github.com/feadal/Web-vuln-scanner.git
cd Web-vuln-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check .     # linter must pass
pytest -q        # all tests green (they run fully offline)
```

## Adding a check

Checks come in two flavours.

**Passive** — inspects the already-fetched landing page, sends nothing extra:

```python
from webscan.checks.base import PassiveCheck
from webscan.models import Finding, ScanContext, Severity

class MyCheck(PassiveCheck):
    name = "my-check"
    description = "What it checks (one line)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        ...
        return findings
```

**Active** — probes a single injection point with a benign payload:

```python
from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity

class MyActiveCheck(ActiveCheck):
    name = "my-active-check"
    description = "What it detects (one line)"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        resp = self.send(client, point, "payload")   # mutates point.param only
        ...
        return findings
```

Then register the class in `PASSIVE_CHECKS` or `ACTIVE_CHECKS` in
`webscan/checks/__init__.py`, add offline tests under `tests/`, and update the
table in `README.md`.

## Principles

- **Detection, not exploitation.** Payloads must be non-destructive: trigger an
  error, get reflected, read a world-readable file, or echo a benign value. No
  data modification, no privilege escalation, no DoS, no destructive requests.
- **Stay bounded.** Respect the request budget and same-host scope. Don't add
  unbounded brute-forcing.
- **Minimise false positives.** Prefer firm signals; mark heuristics as
  `confidence="tentative"`.
- **Few dependencies.** Stick to the standard library and `requests` where you can.
