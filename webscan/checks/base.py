"""Base class every check inherits from."""

from __future__ import annotations

from webscan.models import Finding, ScanContext


class Check:
    """A single, self-contained scanning module.

    Subclasses set :attr:`name` / :attr:`description` and implement :meth:`run`,
    returning a list of :class:`~webscan.models.Finding`. A check should never
    raise for an expected condition (a closed port, a missing page); the scanner
    catches unexpected exceptions and records them as scan errors.
    """

    #: Short, CLI-friendly identifier (e.g. ``"security-headers"``).
    name: str = "base"
    #: One-line human description shown by ``--list-checks``.
    description: str = ""

    def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    # Convenience factory so subclasses can write ``self.finding(...)``.
    def finding(self, **kwargs) -> Finding:
        kwargs.setdefault("check", self.name)
        return Finding(**kwargs)
