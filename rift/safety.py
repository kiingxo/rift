"""Scope checks for authorised hosts, private networks, and metadata endpoints."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

from rift.config import ScanConfig, allow_internal_from_env, env_setting, local_allowlist_path

# Addresses that must never be contacted, including in lab mode.
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)

_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.google.com",
        "metadata",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

# Extra ranges that are not globally routable on every Python version.
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

_SENSITIVE_SEGMENTS = frozenset(
    {
        "logout",
        "log-out",
        "signout",
        "sign-out",
        "subscribe",
        "register",
        "signup",
        "sign-up",
        "activate",
        "deactivate",
        "confirm",
        "invite",
        "delete",
        "destroy",
        "remove",
        "trade",
        "trades",
        "order",
        "orders",
        "buy",
        "sell",
        "swap",
        "withdraw",
        "withdrawal",
        "deposit",
        "transfer",
        "payment",
        "payments",
        "checkout",
        "purchase",
        "password",
        "passwd",
        "reset-password",
        "unsubscribe",
    }
)

_STATIC_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".pdf",
    ".zip",
)


class ScopeError(Exception):
    """The URL is outside the configured scan scope."""


def normalize_host(host: str) -> str:
    if host is None:
        raise ScopeError("URL is missing a host")
    value = host.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        raise ScopeError("URL is missing a host")
    if "%" in value:
        raise ScopeError("Scoped network addresses are blocked")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("Host name is not valid") from exc


def is_metadata_host(host: str) -> bool:
    normalized = normalize_host(host)
    return normalized in _METADATA_HOSTS or normalized.endswith(".metadata.google.internal")


def is_local_name(host: str) -> bool:
    normalized = normalize_host(host)
    return (
        normalized in {"localhost", "localhost.localdomain"}
        or normalized.endswith(".localhost")
        or normalized.endswith(".local")
        or normalized.endswith(".internal")
    )


def canonical_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return mapped
    return address


def _is_metadata_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address in _METADATA_IPS:
        return True
    return address.version == 4 and address == ipaddress.ip_address("169.254.169.254")


def _is_globally_routable(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_private
    ):
        return False
    if hasattr(address, "is_global") and not address.is_global:
        return False
    for network in _BLOCKED_NETWORKS:
        if network.version == address.version and address in network:
            return False
    return True


def ensure_ip_allowed(ip: str, *, allow_internal: bool) -> None:
    address = canonical_ip(ip)
    if _is_metadata_address(address):
        raise ScopeError(f"Cloud metadata address {address} is blocked")
    if address.is_multicast or address.is_unspecified or (address.is_reserved and not address.is_loopback):
        raise ScopeError(f"Address {address} is blocked")
    if _is_globally_routable(address):
        return
    if allow_internal and (address.is_loopback or address.is_private or address.is_link_local):
        return
    raise ScopeError(f"Non-public address {address} is blocked")


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def host_is_allowlisted(host: str, allowlist: Sequence[str]) -> bool:
    normalized = normalize_host(host)
    for entry in allowlist:
        allowed = normalize_host(entry)
        if normalized == allowed or normalized.endswith("." + allowed):
            return True
    return False


def validate_allowlist_entry(value: str, *, allow_internal: bool = False) -> str:
    raw = value.strip()
    if not raw or any(character in raw for character in " \t\r\n/\\?#@*"):
        raise ScopeError("Enter a bare domain such as app.example.com, with no scheme, path, or wildcard")
    if "://" in raw:
        raise ScopeError("Enter a domain, not a URL")
    host = normalize_host(raw)
    if is_metadata_host(host):
        raise ScopeError("Cloud metadata hosts cannot be allowlisted")
    if is_ip_literal(host):
        if not allow_internal:
            raise ScopeError("IP addresses cannot be allowlisted. Add the public hostname you are authorised to test.")
        ensure_ip_allowed(host, allow_internal=True)
        return host
    if is_local_name(host):
        if not allow_internal:
            raise ScopeError("Local host names cannot be allowlisted unless lab mode is enabled")
        return host
    if not _DOMAIN_RE.fullmatch(host):
        raise ScopeError("Domain is not valid. Use a hostname such as app.example.com")
    return host


def _dedupe(items: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return tuple(ordered)


def _read_allowlist_source(text: str, *, allow_internal: bool) -> list[str]:
    found: list[str] = []
    for piece in text.replace(",", "\n").splitlines():
        item = piece.strip()
        if not item or item.startswith("#"):
            continue
        found.append(validate_allowlist_entry(item, allow_internal=allow_internal))
    return found


def load_allowlist(path: Path | None = None) -> tuple[str, ...]:
    allow_internal = allow_internal_from_env()
    domains = _read_allowlist_source(env_setting("ALLOWLIST"), allow_internal=allow_internal)
    file_path = path or local_allowlist_path()
    if file_path.exists():
        domains.extend(_read_allowlist_source(file_path.read_text(encoding="utf-8"), allow_internal=allow_internal))
    return _dedupe(domains)


def save_extra_domains(domains: Sequence[str], path: Path | None = None) -> None:
    allow_internal = allow_internal_from_env()
    saved: list[str] = []
    for domain in domains:
        saved.append(validate_allowlist_entry(domain, allow_internal=allow_internal))
    destination = path or local_allowlist_path()
    lines = ["# Saved authorised domains. One hostname per line.", *_dedupe(saved)]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _format_netloc(host: str, port: int | None) -> str:
    formatted = f"[{host}]" if ":" in host else host
    if port is None:
        return formatted
    return f"{formatted}:{port}"


def _is_sensitive_path(path: str) -> bool:
    segments = {segment.lower() for segment in path.split("/") if segment}
    return bool(segments & _SENSITIVE_SEGMENTS)


def _is_static_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return any(name.endswith(extension) for extension in _STATIC_EXTENSIONS)


def validate_target(url: str, config: ScanConfig, *, allow_static: bool = False) -> str:
    """Return a canonical URL, or raise ScopeError before any socket is opened.

    allow_static lifts only the static-file rule, for checks that read scripts
    or look for exposed files. Every other scope rule still applies.
    """

    if not isinstance(url, str):
        raise ScopeError("URL must be text")
    raw = url.strip()
    if not raw:
        raise ScopeError("Empty URL")
    if len(raw) > 4096:
        raise ScopeError("URL exceeds 4096 characters")
    if any(character in raw for character in "\r\n\t\\"):
        raise ScopeError("URL contains a line break, tab, or backslash")
    try:
        parts = urlsplit(raw)
        explicit_port = parts.port
    except ValueError as exc:
        raise ScopeError("URL could not be parsed") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ScopeError("Only http and https URLs can be scanned")
    if parts.username or parts.password:
        raise ScopeError("URLs with embedded credentials are not scanned")
    if not parts.hostname:
        raise ScopeError("URL is missing a host")
    host = normalize_host(parts.hostname)
    if host.isdigit():
        raise ScopeError("Numeric host names are blocked")
    if is_metadata_host(host):
        raise ScopeError("Cloud metadata hosts are blocked")
    if is_local_name(host) and not config.allow_internal:
        raise ScopeError("Local and internal host names are blocked")
    if is_ip_literal(host):
        if not config.allow_internal:
            raise ScopeError("IP addresses are blocked. Scan an authorised hostname instead.")
        ensure_ip_allowed(host, allow_internal=True)
    if not host_is_allowlisted(host, config.allowlist):
        raise ScopeError(f"{host} is not on the authorised domain allowlist")
    port = 443 if scheme == "https" else 80
    if explicit_port is not None:
        port = explicit_port
    if port not in {80, 443} and not config.allow_internal:
        raise ScopeError("Only ports 80 and 443 are scanned")
    if not 1 <= port <= 65535:
        raise ScopeError("URL port is not valid")
    path = parts.path or "/"
    if _is_sensitive_path(path):
        raise ScopeError(
            "This path looks like a state-changing route and was not requested"
        )
    if not allow_static and _is_static_path(path):
        raise ScopeError("This path looks like a static asset and was not requested")
    return urlunsplit((scheme, _format_netloc(host, explicit_port), path, parts.query, ""))
