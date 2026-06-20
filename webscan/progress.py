"""Live progress reporting to stderr while a scan runs."""

from __future__ import annotations

import sys

from webscan.models import Severity

_COLORS = {
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_DIM = "\033[90m"
_CLEAR = "\r\033[K"


class NullReporter:
    def phase(self, name): ...
    def info(self, msg): ...
    def finding(self, finding): ...
    def active(self, done, total, requests): ...
    def close(self): ...


class Reporter:
    def __init__(self, stream=None, color=None):
        self.stream = stream if stream is not None else sys.stderr
        self.color = self.stream.isatty() if color is None else color
        self._status_active = False

    def _write(self, text):
        self.stream.write(text)
        self.stream.flush()

    def _drop_status(self):
        if self._status_active:
            self._write(_CLEAR)
            self._status_active = False

    def _tag(self, label):
        return f"{_DIM}{label}{_RESET}" if self.color else label

    def phase(self, name):
        self._drop_status()
        self._write(f"{self._tag('[*]')} {name}\n")

    def info(self, msg):
        self._drop_status()
        self._write(f"{self._tag('[*]')} {msg}\n")

    def finding(self, finding):
        self._drop_status()
        sev = f"[{finding.severity.value.upper()}]".ljust(8)
        if self.color:
            sev = _COLORS[finding.severity] + sev + _RESET
        where = f" [{finding.param}]" if finding.param else ""
        self._write(f"  {sev} {finding.check}{where}: {finding.title}\n")

    def active(self, done, total, requests):
        line = f"{self._tag('[scan]')} {done}/{total} points · {requests} requests"
        if self.color:
            self._write(_CLEAR + line)
            self._status_active = True
        elif done >= total:
            self._write(line + "\n")

    def close(self):
        self._drop_status()
