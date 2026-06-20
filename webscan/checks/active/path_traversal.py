"""Path traversal / local file inclusion detection.

Requests a few ``../``-style payloads pointing at ``/etc/passwd`` and looks for
the unmistakable ``root:...:0:0:`` line. Reading a world-readable file is a
non-destructive way to confirm the bug.
"""

from __future__ import annotations

from webscan.checks.base import ActiveCheck
from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, Severity
from webscan.payloads import TRAVERSAL_PAYLOADS, match_traversal


class PathTraversalCheck(ActiveCheck):
    name = "path-traversal"
    description = "Detects path traversal / LFI via /etc/passwd readback"

    def test(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        for payload in TRAVERSAL_PAYLOADS:
            resp = self.send(client, point, payload)
            if resp is None:
                continue
            hit = match_traversal(resp.text or "")
            if hit:
                return [
                    self.finding(
                        title="Path traversal / local file inclusion",
                        severity=Severity.HIGH,
                        confidence="firm",
                        description="The parameter let us read an arbitrary file outside the web root.",
                        evidence=f"/etc/passwd content via '{point.param}': {hit}",
                        remediation="Reject path separators; resolve and confine paths to an allow-listed directory.",
                        url=point.url,
                        param=point.param,
                    )
                ]
        return []
