"""A thin, polite, thread-safe wrapper around requests with a request budget."""

from __future__ import annotations

import threading
import time
from typing import Optional
from urllib.parse import urljoin

import requests

from webscan import __version__

DEFAULT_USER_AGENT = f"webscan/{__version__} (+https://github.com/feadal/Web-vuln-scanner)"


class BudgetExceeded(Exception):
    """Raised when a scan reaches its configured maximum number of requests."""


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
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = delay
        self.max_requests = max_requests
        self.requests_made = 0
        self._last_request_at = 0.0
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.max_redirects = max_redirects
        self.session.headers.update({"User-Agent": user_agent})
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

    def _reserve(self) -> None:
        with self._lock:
            if self.requests_made >= self.max_requests:
                raise BudgetExceeded(f"reached request budget of {self.max_requests}")
            self.requests_made += 1
            if self.delay > 0:
                wait = self.delay - (time.monotonic() - self._last_request_at)
                if wait > 0:
                    time.sleep(wait)
            self._last_request_at = time.monotonic()

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self._reserve()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def try_get(self, url: str, **kwargs) -> Optional[requests.Response]:
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
