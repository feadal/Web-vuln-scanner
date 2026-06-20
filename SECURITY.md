# Security & Responsible Use Policy

## Acceptable use

webscan is an **active** scanner: it sends probes to the target. Use it **only** for:

- testing systems you own;
- engagements with a signed penetration-testing contract and written scope;
- legal CTFs and training labs (DVWA, Juice Shop, the bundled `examples/vulnerable_app.py`, etc.);
- education and research in a controlled environment.

## Unacceptable use

Do not run it against any system without the owner's explicit permission.
Unauthorized scanning may violate the law (CFAA in the US, the Computer Misuse Act
in the UK, and equivalents elsewhere) and your hosting provider's terms. All
responsibility for use of this tool rests with the user; the authors accept none.

## Design choices that keep it a good citizen

- **Detection, not exploitation.** Probes confirm a bug (an error, a reflection,
  reading `/etc/passwd`, echoing an arithmetic result) — they never dump data,
  escalate privileges, or run harmful commands.
- **Bounded by default.** Same-host crawl scope, a hard request budget, optional
  throttling and a limited crawl depth prevent a scan from becoming a flood.
- **Honest output.** Heuristic findings are marked `tentative` so a human verifies
  them before acting.

## Reporting a vulnerability in webscan itself

Please do not open a public issue. Use a private GitHub security advisory to
contact the maintainers. We aim to respond within 7 days.
