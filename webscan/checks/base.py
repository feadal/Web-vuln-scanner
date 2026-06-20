"""Base classes for the two kinds of checks.

* :class:`PassiveCheck` inspects a response the scanner already fetched. It sends
  no extra payloads and is always safe to run.
* :class:`ActiveCheck` mutates one parameter of an :class:`InjectionPoint`,
  sends a benign probe and analyses the response. Active checks detect issues
  (they never weaponise or escalate them) and only run when the user opts in.
"""

from __future__ import annotations

from typing import Optional

import requests

from webscan.http_client import HttpClient
from webscan.models import Finding, InjectionPoint, ScanContext


class _FindingFactory:
    name: str = "base"

    def finding(self, **kwargs) -> Finding:
        kwargs.setdefault("check", self.name)
        return Finding(**kwargs)


class PassiveCheck(_FindingFactory):
    """A read-only check over the already-fetched landing page."""

    name = "base"
    description = ""

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError


Check = PassiveCheck


class ActiveCheck(_FindingFactory):
    """A check that probes a single injection point with benign payloads."""

    name = "base"
    description = ""
    tamper: list = []

    def test(
        self, point: InjectionPoint, client: HttpClient
    ) -> list[Finding]:
        raise NotImplementedError

    def send(
        self,
        client: HttpClient,
        point: InjectionPoint,
        payload: str,
        *,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """Send ``payload`` in ``point.param``, keeping other values intact.

        Returns ``None`` on transport errors; budget exhaustion propagates so
        the scan stops.
        """
        values = dict(point.params)
        values[point.param] = payload
        try:
            if point.method == "POST":
                return client.request(
                    "POST", point.url, data=values, allow_redirects=allow_redirects
                )
            return client.request(
                "GET", point.url, params=values, allow_redirects=allow_redirects
            )
        except requests.RequestException:
            return None
