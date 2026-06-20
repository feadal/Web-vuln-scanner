"""A thin, polite wrapper around :mod:`requests`.

Centralises timeout, user-agent, TLS verification and (optional) inter-request
throttling so individual checks don't each reinvent it.
"""

from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urljoin

import requests

from webscan import __version__

DEFAULT_USER_AGENT = f"webscan/{__version__} (+https://github.com/your-org/webscan)"


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        verify_tls: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        delay: float = 0.0,
        max_redirects: int = 5,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = delay
        self._last_request_at = 0.0
        self.session = requests.Session()
        self.session.max_redirects = max_redirects
        self.session.headers.update({"User-Agent": user_agent})

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

    def get(
        self,
        url: str,
        *,
        allow_redirects: bool = True,
        **kwargs,
    ) -> requests.Response:
        """GET ``url``. Raises :class:`requests.RequestException` on transport errors."""
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", allow_redirects)
        try:
            return self.session.get(url, **kwargs)
        finally:
            self._last_request_at = time.monotonic()

    def try_get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Like :meth:`get` but returns ``None`` instead of raising."""
        try:
            return self.get(url, **kwargs)
        except requests.RequestException:
            return None

    @staticmethod
    def join(base: str, path: str) -> str:
        return urljoin(base, path)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
