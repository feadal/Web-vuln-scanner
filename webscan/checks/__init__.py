"""Registry of all available checks (passive and active)."""

from __future__ import annotations

from webscan.checks.active.command_injection import CommandInjectionCheck
from webscan.checks.active.crlf import CrlfCheck
from webscan.checks.active.hpp import HppCheck
from webscan.checks.active.idor import IdorCheck
from webscan.checks.active.lfi import LfiCheck
from webscan.checks.active.mass_assignment import MassAssignmentCheck
from webscan.checks.active.nosqli import NoSqlInjectionCheck
from webscan.checks.active.open_redirect import OpenRedirectCheck
from webscan.checks.active.path_traversal import PathTraversalCheck
from webscan.checks.active.sqli import SqlInjectionCheck
from webscan.checks.active.ssrf import SsrfCheck
from webscan.checks.active.ssti import SstiCheck
from webscan.checks.active.xss import ReflectedXssCheck
from webscan.checks.active.xxe import XxeCheck
from webscan.checks.base import ActiveCheck, PassiveCheck
from webscan.checks.cookies import CookieFlagsCheck
from webscan.checks.cors import CorsCheck
from webscan.checks.forced_browsing import ForcedBrowsingCheck
from webscan.checks.forms import FormSecurityCheck
from webscan.checks.graphql_introspection import GraphqlIntrospectionCheck
from webscan.checks.host_header import HostHeaderCheck
from webscan.checks.http_methods import HttpMethodsCheck
from webscan.checks.jwt import JwtCheck
from webscan.checks.secrets import SecretsCheck
from webscan.checks.security_headers import SecurityHeadersCheck
from webscan.checks.sensitive_files import SensitiveFilesCheck
from webscan.checks.server_disclosure import ServerDisclosureCheck
from webscan.checks.tls import TlsCheck
from webscan.checks.waf import WafCheck
from webscan.checks.web_cache_deception import WebCacheDeceptionCheck
from webscan.checks.web_cache_poisoning import WebCachePoisoningCheck

PASSIVE_CHECKS: list[type[PassiveCheck]] = [
    SecurityHeadersCheck,
    CookieFlagsCheck,
    ServerDisclosureCheck,
    TlsCheck,
    FormSecurityCheck,
    SensitiveFilesCheck,
    CorsCheck,
    HostHeaderCheck,
    HttpMethodsCheck,
    JwtCheck,
    ForcedBrowsingCheck,
    GraphqlIntrospectionCheck,
    SecretsCheck,
    WafCheck,
    WebCacheDeceptionCheck,
    WebCachePoisoningCheck,
]

ACTIVE_CHECKS: list[type[ActiveCheck]] = [
    ReflectedXssCheck,
    SqlInjectionCheck,
    NoSqlInjectionCheck,
    CommandInjectionCheck,
    LfiCheck,
    SstiCheck,
    SsrfCheck,
    XxeCheck,
    CrlfCheck,
    HppCheck,
    MassAssignmentCheck,
    IdorCheck,
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
