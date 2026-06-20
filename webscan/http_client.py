"""A thin, polite wrapper around :mod:`requests`.

Centralises timeout, user-agent, TLS verification, inter-request throttling and
a hard request budget so a single scan can never turn into a flood.
"""

from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urljoin

import requests

from webscan import __version__

DEFAULT_USER_AGENT = f"webscan/{__version__} (+https://github.com/feadal/Web-vuln-scanner)"


class BudgetExceeded(Exception):
    """Raised when a scan reaches its configured maximum number of requests.

    Deliberately *not* a :class:`requests.RequestException` so it propagates
    past the per-check error handling and stops the whole scan cleanly.
    """


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        verify_tls: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        delay: float = 0.0,
        max_redirects: int = 5,
        max_requests: int = 1000,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = delay
        self.max_requests = max_requests
        self.requests_made = 0
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

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Perform a request, enforcing the budget, throttle and defaults.

        Raises :class:`BudgetExceeded` once the request budget is spent and
        :class:`requests.RequestException` on transport errors.
        """
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(
                f"reached request budget of {self.max_requests}"
            )
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        self.requests_made += 1
        try:
            return self.session.request(method, url, **kwargs)
        finally:
            self._last_request_at = time.monotonic()

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def try_get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Like :meth:`get` but returns ``None`` on transport errors.

        Budget exhaustion still propagates so the scan can stop.
        """
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
