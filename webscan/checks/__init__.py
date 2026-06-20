"""Registry of all available checks.

To add a check: implement a :class:`~webscan.checks.base.Check` subclass and add
it to ``ALL_CHECKS`` below. Order here is the order findings are gathered in.
"""

from __future__ import annotations

from webscan.checks.base import Check
from webscan.checks.cookies import CookieFlagsCheck
from webscan.checks.forms import FormSecurityCheck
from webscan.checks.security_headers import SecurityHeadersCheck
from webscan.checks.sensitive_files import SensitiveFilesCheck
from webscan.checks.server_disclosure import ServerDisclosureCheck
from webscan.checks.tls import TlsCheck

ALL_CHECKS: list[type[Check]] = [
    SecurityHeadersCheck,
    CookieFlagsCheck,
    ServerDisclosureCheck,
    TlsCheck,
    FormSecurityCheck,
    SensitiveFilesCheck,
]

_BY_NAME = {cls.name: cls for cls in ALL_CHECKS}


def all_checks() -> list[Check]:
    """Instantiate every registered check."""
    return [cls() for cls in ALL_CHECKS]


def select_checks(names: list[str]) -> list[Check]:
    """Instantiate the named checks, preserving registry order.

    Raises :class:`KeyError` with the unknown name if one is not registered.
    """
    wanted = set(names)
    unknown = wanted - set(_BY_NAME)
    if unknown:
        raise KeyError(", ".join(sorted(unknown)))
    return [cls() for cls in ALL_CHECKS if cls.name in wanted]


def check_names() -> list[str]:
    return [cls.name for cls in ALL_CHECKS]


__all__ = ["Check", "ALL_CHECKS", "all_checks", "select_checks", "check_names"]
