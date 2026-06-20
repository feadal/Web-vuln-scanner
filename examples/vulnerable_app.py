#!/usr/bin/env python3
"""An intentionally vulnerable demo app — for testing webscan locally.

⚠️  This server is INSECURE ON PURPOSE. It exists only so you can watch the
    active scanner find real issues against a target you own. It binds to
    127.0.0.1 and must never be exposed to a network.

Run it, then in another terminal:

    python examples/vulnerable_app.py        # serves http://127.0.0.1:8000
    webscan http://127.0.0.1:8000            # scan it

Each endpoint mirrors one active check:
  /search?q=     reflected XSS (input echoed raw)
  /item?id=      error-based SQL injection (broken query leaks an error)
  /download?file= path traversal (reads files outside the web root)
  /go?next=      open redirect (Location controlled by the parameter)
  /ping?host=    OS command injection (input passed to a shell)
"""

from __future__ import annotations

import html
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST, PORT = "127.0.0.1", 8000

LANDING = """<!doctype html><html><head><title>Vulnerable demo</title></head>
<body>
  <h1>webscan demo target</h1>
  <ul>
    <li><a href="/search?q=hello">search (XSS)</a></li>
    <li><a href="/item?id=1">item (SQLi)</a></li>
    <li><a href="/download?file=readme.txt">download (path traversal)</a></li>
    <li><a href="/go?next=/item?id=1">go (open redirect)</a></li>
    <li><a href="/ping?host=127.0.0.1">ping (command injection)</a></li>
  </ul>
  <form action="/search" method="get">
    <input name="q" value="test"><button type="submit">Search</button>
  </form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: str, status: int = 200, headers: dict | None = None):
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path == "/":
            return self._send(LANDING)

        if path == "/search":
            return self._send(f"<html>Results for: {q.get('q', '')}</html>")

        if path == "/item":
            item_id = q.get("id", "")
            if "'" in item_id or '"' in item_id:
                return self._send(
                    "Warning: mysqli_query(): You have an error in your SQL "
                    f"syntax near '{item_id}'", status=500
                )
            return self._send(f"<html>Item #{html.escape(item_id)}</html>")

        if path == "/download":
            name = q.get("file", "")
            if "etc/passwd" in name or name == "/etc/passwd":
                return self._send("root:x:0:0:root:/root:/bin/bash\n")
            return self._send("readme.txt: hello\n")

        if path == "/go":
            return self._send("", status=302, headers={"Location": q.get("next", "/")})

        if path == "/ping":
            host = q.get("host", "127.0.0.1")
            try:
                out = subprocess.run(
                    f"echo pinging {host}", shell=True, capture_output=True,
                    text=True, timeout=3,
                ).stdout
            except Exception as exc:
                out = str(exc)
            return self._send(f"<pre>{out}</pre>")

        return self._send("<html>404</html>", status=404)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"⚠️  Vulnerable demo server on http://{HOST}:{PORT} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
