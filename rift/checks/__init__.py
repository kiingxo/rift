"""Registry of checks. Add a check by writing a Check subclass and listing it here."""

from __future__ import annotations

from typing import Sequence

from rift.checks.base import PASSIVE, PROBE, Check, CheckContext
from rift.checks.content import ContentCheck
from rift.checks.cookies import CookieCheck
from rift.checks.disclosure import DisclosureCheck
from rift.checks.headers import SecurityHeadersCheck
from rift.checks.secrets import JwtCheck, SecretsCheck

REDIRECT_CHECK_ID = "open-redirect"
REDIRECT_TITLE = "Open redirect"
REDIRECT_SUMMARY = "Parameters that send visitors to an attacker-chosen site (CWE-601)."


def all_checks() -> list[Check]:
    """One fresh instance of every check, in the order they run."""

    from rift.checks.api_surface import ApiSurfaceCheck
    from rift.checks.cors import CorsCheck
    from rift.checks.dns_checks import EmailAuthCheck, TakeoverCheck
    from rift.checks.exposure import ExposedFilesCheck
    from rift.checks.server_config import ServerConfigCheck
    from rift.checks.session import SignedInCheck
    from rift.checks.transport import TransportCheck

    return [
        SecurityHeadersCheck(),
        CookieCheck(),
        ContentCheck(),
        DisclosureCheck(),
        SecretsCheck(),
        JwtCheck(),
        TransportCheck(),
        CorsCheck(),
        ServerConfigCheck(),
        ExposedFilesCheck(),
        ApiSurfaceCheck(),
        SignedInCheck(),
        EmailAuthCheck(),
        TakeoverCheck(),
    ]


def catalog() -> list[tuple[str, str, str, str]]:
    """(id, title, summary, kind) for every check, including the redirect engine."""

    rows = [(check.id, check.title, check.summary, check.kind) for check in all_checks()]
    rows.append((REDIRECT_CHECK_ID, REDIRECT_TITLE, REDIRECT_SUMMARY, PROBE))
    return rows


def resolve_checks(selected: Sequence[str] | None) -> tuple[list[Check], bool]:
    """Checks to run and whether the redirect engine is included. None means everything."""

    available = all_checks()
    if selected is None:
        return available, True
    wanted = {item.strip().lower() for item in selected if item and item.strip()}
    known = {check.id for check in available} | {REDIRECT_CHECK_ID}
    unknown = sorted(wanted - known)
    if unknown:
        raise ValueError(f"Unknown check: {', '.join(unknown)}. Available: {', '.join(sorted(known))}")
    return [check for check in available if check.id in wanted], REDIRECT_CHECK_ID in wanted


__all__ = [
    "PASSIVE",
    "PROBE",
    "REDIRECT_CHECK_ID",
    "Check",
    "CheckContext",
    "all_checks",
    "catalog",
    "resolve_checks",
]
