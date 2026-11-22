"""Parse URL lists from the dashboard, a text file, or the command line."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

from rift.config import ScanConfig
from rift.safety import ScopeError, normalize_host, validate_target


@dataclass(frozen=True)
class Submission:
    """URLs that can be scanned, the domains they use, and the rows that were left out."""

    urls: tuple[str, ...]
    domains: tuple[str, ...]
    excluded: tuple[tuple[str, str], ...]


def prepare_submission(urls: Sequence[str], *, allow_internal: bool = False) -> Submission:
    """Deduplicate URLs and keep only destinations that pass the safety checks.

    The saved domain list is not consulted. Each accepted host becomes part of
    the temporary allowlist for this submission. Local hosts, private addresses,
    metadata endpoints, and state-changing paths are excluded and are not added
    to that allowlist.
    """

    accepted: list[str] = []
    excluded: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url in urls:
        host = _host_or_blank(url)
        probe = ScanConfig(allowlist=(host,) if host else (), allow_internal=allow_internal)
        try:
            canonical = validate_target(url, probe)
        except ScopeError as exc:
            excluded.append((url, str(exc)))
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        accepted.append(canonical)
    domains: list[str] = []
    seen_hosts: set[str] = set()
    for url in accepted:
        host = normalize_host(urlsplit(url).hostname or "")
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            domains.append(host)
    return Submission(tuple(accepted), tuple(domains), tuple(excluded))


def _host_or_blank(url: str) -> str:
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return ""
    if not host:
        return ""
    try:
        return normalize_host(host)
    except ScopeError:
        return ""


def parse_url_lines(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value not in seen:
            seen.add(value)
            urls.append(value)
    return urls


def collect_targets(items: Sequence[str]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for item in items:
        path = Path(item)
        if "://" not in item and path.suffix.lower() == ".txt" and path.is_file():
            found = parse_url_lines(path.read_text(encoding="utf-8-sig"))
        else:
            found = parse_url_lines(item)
        for url in found:
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls
