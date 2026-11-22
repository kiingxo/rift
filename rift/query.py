"""Classify an existing query string before any redirect payload is sent.

Known redirect names and values that already look like destinations are tested
first. Ordinary campaign parameters stay as they are. Authentication,
unsubscribe, and other opaque tokens are never replaced automatically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import parse_qsl, urlsplit

from rift.catalog import load_parameters

_SENSITIVE_NAMES = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "authorization",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "csrf",
        "csrftoken",
        "_csrf",
        "xsrf",
        "unsubscribe",
        "unsubscribe_token",
        "unsub",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "signature",
        "sig",
        "hmac",
        "nonce",
        "ticket",
        "credential",
        "credentials",
        "jwt",
        "bearer",
        "otp",
        "auth_token",
        "session_token",
        "reset_token",
        "confirm_token",
    }
)
_SENSITIVE_PARTS = ("token", "session", "password", "secret", "unsubscribe", "csrf", "auth")
_ORDINARY_EXACT = frozenset(
    {
        "lang",
        "locale",
        "hl",
        "page",
        "limit",
        "offset",
        "sort",
        "format",
        "fbclid",
        "gclid",
        "gclsrc",
        "dclid",
        "msclkid",
        "yclid",
        "_ga",
    }
)
_ORDINARY_PREFIXES = ("utm_", "mc_")
_HEX = re.compile(r"^[A-Fa-f0-9]{32,}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,}$")


@dataclass(frozen=True)
class QueryReview:
    navigation: tuple[str, ...]
    preserved: tuple[str, ...]
    sensitive: tuple[str, ...]
    manual: tuple[str, ...]


def review_query(url: str) -> QueryReview:
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    navigation, preserved, sensitive, manual, _candidates, _protected = _classify(pairs, ())
    return QueryReview(
        navigation=tuple(navigation),
        preserved=tuple(preserved),
        sensitive=tuple(sensitive),
        manual=tuple(manual),
    )


def manual_parameter_names(urls: Sequence[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for url in urls:
        for name in review_query(url).manual:
            if name.lower() not in seen:
                seen.add(name.lower())
                found.append(name)
    return found


def focus_plan(
    pairs: list[tuple[str, str]],
    catalog_names: Sequence[str],
    manual_parameters: Sequence[str],
) -> tuple[list[str], set[str], set[str]]:
    """Return focus order, names that may be neutralised, and names left untouched."""

    navigation, _preserved, _sensitive, _manual, candidates, protected = _classify(pairs, manual_parameters)
    seen = {name.lower() for name in navigation}
    ordered = list(navigation)
    for name in manual_parameters:
        if _is_sensitive_name(name):
            continue
        if name.lower() in seen:
            continue
        if not any(key.lower() == name.lower() for key, _value in pairs):
            continue
        ordered.append(name)
        seen.add(name.lower())
        candidates.add(name.lower())
    for name in catalog_names:
        if name.lower() not in seen and not _is_sensitive_name(name):
            ordered.append(name)
            seen.add(name.lower())
            candidates.add(name.lower())
    return ordered, candidates, protected


def _classify(
    pairs: list[tuple[str, str]],
    manual_parameters: Sequence[str],
) -> tuple[list[str], list[str], list[str], list[str], set[str], set[str]]:
    known = {item.name.lower() for item in load_parameters()}
    selected = {name.lower() for name in manual_parameters}
    navigation: list[tuple[int, int, str]] = []
    preserved: list[str] = []
    sensitive: list[str] = []
    manual: list[str] = []
    protected: set[str] = set()
    seen: set[str] = set()
    for index, (key, value) in enumerate(pairs):
        lowered = key.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        if _is_sensitive_name(lowered):
            sensitive.append(key)
            protected.add(lowered)
            continue
        if lowered in known or _looks_like_navigation(value) or _looks_like_redirect_name(lowered):
            navigation.append((_rank(lowered, value, known), index, key))
            continue
        if _is_ordinary_name(lowered):
            preserved.append(key)
            continue
        manual.append(key)
        if lowered in selected:
            navigation.append((1, index, key))
    navigation.sort(key=lambda item: (-item[0], item[1]))
    names = [item[2] for item in navigation]
    candidates = {name.lower() for name in names} | known
    candidates -= protected
    return names, preserved, sensitive, manual, candidates, protected


def _rank(name: str, value: str, known: set[str]) -> int:
    score = 0
    if _looks_offsite(value):
        score += 4
    elif _looks_like_navigation(value):
        score += 2
    if name in known:
        score += 1
    return score


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    if lowered in _SENSITIVE_NAMES:
        return True
    return any(part in lowered for part in _SENSITIVE_PARTS)


def _is_ordinary_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in _ORDINARY_EXACT or lowered.startswith(_ORDINARY_PREFIXES)


def _looks_like_redirect_name(name: str) -> bool:
    """Names such as turl are redirect parameters even when they are not in the catalog."""

    lowered = name.lower().replace("-", "_")
    if _is_ordinary_name(lowered) or _is_sensitive_name(lowered):
        return False
    if any(part in lowered for part in ("hash", "checksum", "digest", "md5", "sha")):
        return False
    return any(part in lowered for part in ("url", "uri", "redir", "dest", "goto", "link"))


def _looks_like_navigation(value: str) -> bool:
    stripped = value.strip()
    if not stripped or _is_opaque(stripped):
        return False
    lowered = stripped.lower()
    if lowered.startswith(("http://", "https://", "//", "/\\", "\\\\", "\\")):
        return True
    if lowered.startswith("/"):
        return True
    return any(token in lowered for token in ("%2f%2f", "%2f/", "/%2f", "%5c", "%2e%2e", "%252f"))


def _looks_offsite(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered.startswith(("http://", "https://", "//", "/\\", "\\\\")):
        return True
    return any(token in lowered for token in ("%2f%2f", "%252f", "%5c%5c"))


def _is_opaque(value: str) -> bool:
    compact = value.strip()
    if compact.startswith("eyJ") and compact.count(".") == 2:
        return True
    if _HEX.fullmatch(compact) or _TOKEN.fullmatch(compact):
        return True
    return False
