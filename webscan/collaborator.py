"""Out-of-band (OAST) collaborator for detecting blind vulnerabilities.

A small HTTP listener records inbound callbacks. Each payload carries a unique
token in its URL; if the target server fetches that URL (blind SSRF, blind RCE,
XXE, ...), the callback proves the vulnerability. The target must be able to
reach the advertised host — set --oob-host to a public/forwarded address.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from webscan.models import Finding, Severity


def _make_handler(hits: set, lock: threading.Lock):
    class _Handler(BaseHTTPRequestHandler):
        def _record(self):
            token = self.path.strip("/").split("/")[0].split("?")[0]
            if token:
                with lock:
                    hits.add(token)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        do_GET = _record
        do_POST = _record
        do_HEAD = _record

        def log_message(self, *args):
            pass

    return _Handler


class HttpCollaborator:
    def __init__(self, advertised_host: str = "127.0.0.1", port: int = 0) -> None:
        self._hits: set = set()
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("0.0.0.0", port), _make_handler(self._hits, self._lock))
        self.port = self._server.server_address[1]
        self.advertised = f"{advertised_host}:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    @staticmethod
    def new_token() -> str:
        return "wvs" + secrets.token_hex(8)

    def payload_url(self, token: str) -> str:
        return f"http://{self.advertised}/{token}"

    def poll(self) -> set:
        with self._lock:
            return set(self._hits)

    def received(self, token: str) -> bool:
        with self._lock:
            return token in self._hits

    def stop(self) -> None:
        if self._thread.is_alive():
            self._server.shutdown()
        self._server.server_close()


OOB_TEMPLATES = [
    ("blind SSRF", lambda u: u),
    ("blind OS command injection", lambda u: f";curl -s {u};"),
    ("blind OS command injection", lambda u: f"$(curl -s {u})"),
    ("blind OS command injection", lambda u: f"|curl -s {u}"),
]


def correlate(hits: set, registry: dict) -> list[Finding]:
    findings: list[Finding] = []
    for token in hits:
        entry = registry.get(token)
        if entry is None:
            continue
        point, kind = entry
        findings.append(
            Finding(
                check="oob",
                title=f"Confirmed {kind} (out-of-band callback)",
                severity=Severity.HIGH,
                confidence="firm",
                description="The target made an out-of-band request to the collaborator, proving a blind vulnerability.",
                evidence=f"callback for token {token} via param '{point.param}'",
                url=point.url,
                param=point.param,
            )
        )
    return findings
