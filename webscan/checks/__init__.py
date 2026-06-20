"""Registry of all available checks (passive and active).

To add a check: implement a :class:`PassiveCheck` or :class:`ActiveCheck`
subclass and add it to the matching list below.
"""

from __future__ import annotations

from webscan.checks.active.command_injection import CommandInjectionCheck
from webscan.checks.active.open_redirect import OpenRedirectCheck
from webscan.checks.active.path_traversal import PathTraversalCheck
from webscan.checks.active.sqli import SqlInjectionCheck
from webscan.checks.active.xss import ReflectedXssCheck
from webscan.checks.base import ActiveCheck, PassiveCheck
from webscan.checks.cookies import CookieFlagsCheck
from webscan.checks.forms import FormSecurityCheck
from webscan.checks.security_headers import SecurityHeadersCheck
from webscan.checks.sensitive_files import SensitiveFilesCheck
from webscan.checks.server_disclosure import ServerDisclosureCheck
from webscan.checks.tls import TlsCheck

PASSIVE_CHECKS: list[type[PassiveCheck]] = [
    SecurityHeadersCheck,
    CookieFlagsCheck,
    ServerDisclosureCheck,
    TlsCheck,
    FormSecurityCheck,
    SensitiveFilesCheck,
]

ACTIVE_CHECKS: list[type[ActiveCheck]] = [
    ReflectedXssCheck,
    SqlInjectionCheck,
    CommandInjectionCheck,
    PathTraversalCheck,
    OpenRedirectCheck,
]

_ALL = PASSIVE_CHECKS + ACTIVE_CHECKS
_BY_NAME = {cls.name: cls for cls in _ALL}


def all_passive() -> list[PassiveCheck]:
    return [cls() for cls in PASSIVE_CHECKS]


def all_active() -> list[ActiveCheck]:
    return [cls() for cls in ACTIVE_CHECKS]


def passive_names() -> list[str]:
    return [cls.name for cls in PASSIVE_CHECKS]


def active_names() -> list[str]:
    return [cls.name for cls in ACTIVE_CHECKS]


def all_names() -> list[str]:
    return [cls.name for cls in _ALL]


def select(names: list[str]) -> tuple[list[PassiveCheck], list[ActiveCheck]]:
    """Instantiate the named checks, split into (passive, active).

    Raises :class:`KeyError` naming the unknown check(s) if any are unregistered.
    """
    wanted = set(names)
    unknown = wanted - set(_BY_NAME)
    if unknown:
        raise KeyError(", ".join(sorted(unknown)))
    passive = [cls() for cls in PASSIVE_CHECKS if cls.name in wanted]
    active = [cls() for cls in ACTIVE_CHECKS if cls.name in wanted]
    return passive, active


__all__ = [
    "PassiveCheck",
    "ActiveCheck",
    "PASSIVE_CHECKS",
    "ACTIVE_CHECKS",
    "all_passive",
    "all_active",
    "passive_names",
    "active_names",
    "all_names",
    "select",
]
