"""Find more URLs on an authorised host before the redirect checks run.

Discovery starts from the submitted URL. A redirect to another host inside
the confirmed domain, such as the apex host sending browsers to www, is
followed and then crawled. Off-site links, including the canary, are ignored.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Callable, Protocol
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from rift.catalog import load_redirect_paths
from rift.param_discovery import EvidenceIndex, collect_html, collect_javascript, collect_openapi
from rift.query import _looks_like_navigation, _looks_like_redirect_name
from rift.classify import REDIRECT_STATUSES, is_google_destination, resolve_redirect
from rift.config import ScanConfig
from rift.models import Observation
from rift.safety import ScopeError, validate_target

PRIORITY_WORDS = (
    "redirect",
    "tracking",
    "login",
    "logout",
    "callback",
    "out",
    "forward",
    "oauth",
    "signin",
    "signout",
    "return",
    "sso",
)

_SKIP_PREFIXES = ("javascript:", "mailto:", "data:", "tel:")
_LOCALE_PATH = re.compile(r"^/([a-z]{2}(?:-[a-z]{2})?)/?$", re.IGNORECASE)
_QUOTED_PATH = re.compile(r"""["'](/[^"'\\\s<>]{1,180})["']""")
_MAX_PATH_PROBES = 24
_PROBES_PER_DIRECTORY = 8
_MAX_SCRIPTS = 4


class DiscoveryRequester(Protocol):
    def get(self, url: str, include_body: bool = False) -> Observation:
        """Perform one GET. include_body asks for a capped document."""


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        wanted = set()
        if name in {"a", "area", "link"}:
            wanted.add("href")
        elif name == "form":
            wanted.add("action")
        elif name in {"script", "iframe"}:
            wanted.add("src")
        if not wanted:
            return
        for key, value in attrs:
            if key.lower() in wanted and value:
                target = value.strip()
                if name == "script" and key.lower() == "src":
                    self.scripts.append(target)
                else:
                    self.hrefs.append(target)


def discover_endpoints(
    seeds: list[str],
    requester: DiscoveryRequester,
    config: ScanConfig,
    *,
    probes: tuple[str, ...],
    max_discovered: int,
    on_status: Callable[[str], None] | None = None,
    fetch_scripts: bool = True,
    max_path_probes: int = _MAX_PATH_PROBES,
    probes_per_directory: int = _PROBES_PER_DIRECTORY,
    should_stop: Callable[[], bool] | None = None,
    evidence: EvidenceIndex | None = None,
) -> list[str]:
    """Return seeds first, then same-origin URLs ranked by redirect-like paths."""

    if max_discovered <= 0:
        return list(seeds)
    ordered: list[str] = []
    seen: set[str] = set()
    extras: list[str] = []
    promoted_urls: list[str] = []
    pending: list[tuple[str, int]] = []
    current_depth = 0
    origins_seen: set[str] = set()
    probed: set[str] = set()
    absent: dict[str, tuple[int | None, str]] = {}
    scripts_fetched: list[int] = [0]
    scheduled: set[str] = set()
    crawl_budget = [0]

    def add_seed(url: str) -> None:
        if url not in seen:
            seen.add(url)
            ordered.append(url)

    def add_extra(url: str, follow: bool = False) -> None:
        try:
            cleaned = validate_target(url, config)
        except ScopeError:
            return
        if cleaned not in seen:
            seen.add(cleaned)
            extras.append(cleaned)
        if follow:
            _schedule(cleaned)

    def _schedule(url: str) -> None:
        """Open folders the site linked to, then probe redirect filenames there."""

        if current_depth >= config.discovery_depth:
            return
        targets = list(_section_directories(url))
        if _priority(url) > 0 or _query_has_destination(url):
            bare = urlunsplit((*urlsplit(url)[:3], "", ""))
            targets.insert(0, bare)
        for target in targets:
            if crawl_budget[0] >= max_discovered or target in scheduled:
                continue
            if target in {item[0] for item in pending}:
                continue
            scheduled.add(target)
            pending.append((target, current_depth + 1))
            crawl_budget[0] += 1

    def add_promoted(url: str) -> None:
        try:
            cleaned = validate_target(url, config)
        except ScopeError:
            return
        if cleaned not in seen and len(promoted_urls) < max_discovered and current_depth < config.discovery_depth:
            seen.add(cleaned)
            promoted_urls.append(cleaned)
            pending.append((cleaned, current_depth + 1))

    for seed in seeds:
        try:
            normalized = validate_target(seed, config)
        except ScopeError:
            add_seed(seed)
            continue
        add_seed(normalized)
        pending.append((normalized, 0))

    while pending:
        if should_stop is not None and should_stop():
            break
        current, current_depth = pending.pop(0)
        origin = _origin(current)
        if on_status is not None:
            on_status(f"Opening {current}")
        page = requester.get(current, include_body=True)
        promoted = _promoted_redirect(current, page, config)
        if promoted:
            add_promoted(promoted)
        if evidence is not None and page.body:
            evidence.endpoints_analysed += 1
            collect_html(current, page.body, evidence)
        for link in _links_from_document(current, page.body or ""):
            add_extra(link, follow=True)
        if fetch_scripts:
            _fetch_scripts(current, page.body or "", requester, add_extra, scripts_fetched, evidence)
        _probe_redirect_paths(
            current,
            origin,
            requester,
            add_extra,
            probed,
            absent,
            on_status,
            max_path_probes=max_path_probes,
            probes_per_directory=probes_per_directory,
            should_stop=should_stop,
        )
        if origin in origins_seen:
            continue
        origins_seen.add(origin)
        for probe in probes:
            document = requester.get(origin + probe, include_body=True)
            if document.safety_block or document.error or not document.body:
                continue
            if probe.endswith(".json") or probe.endswith("api-docs"):
                if evidence is not None:
                    collect_openapi(origin, document.body, evidence)
                for link in _links_from_openapi(origin, document.body):
                    add_extra(link, follow=True)
            elif probe.endswith("robots.txt"):
                for sitemap in _sitemaps_from_robots(document.body):
                    located = _same_origin(origin, current, sitemap)
                    if not located:
                        continue
                    add_extra(located, follow=True)
                    if located.endswith(".xml"):
                        child = requester.get(located, include_body=True)
                        for link in _links_from_sitemap(child.body or ""):
                            same = _same_origin(origin, current, link)
                            if same:
                                add_extra(same, follow=True)
            else:
                for link in _links_from_sitemap(document.body):
                    same = _same_origin(origin, current, link)
                    if same:
                        add_extra(same, follow=True)

    seed_hosts = {urlsplit(url).hostname for url in ordered}

    def keep(url: str) -> bool:
        if _priority(url) > 0 or _query_has_destination(url):
            return True
        if evidence is not None and evidence.direct_names(url, 1):
            return True
        return urlsplit(url).hostname not in seed_hosts

    promoted_kept = [url for url in promoted_urls if keep(url)]
    extras = [url for url in extras if keep(url)]
    extras.sort(key=lambda url: (-_priority(url), url))
    remaining = max(0, max_discovered - len(promoted_kept))
    return ordered + promoted_kept + extras[:remaining]


def _promoted_redirect(base: str, page: Observation, config: ScanConfig) -> str | None:
    """Return an in-scope Location that should be scanned as its own endpoint."""

    if page.status_code not in REDIRECT_STATUSES or not page.location_header:
        return None
    absolute, problem = resolve_redirect(base, page.location_header)
    if problem or not absolute or is_google_destination(absolute):
        return None
    try:
        cleaned = validate_target(absolute, config)
    except ScopeError:
        return None
    current = urlsplit(base)
    nxt = urlsplit(cleaned)
    if (nxt.scheme, nxt.netloc, nxt.path, nxt.query) == (current.scheme, current.netloc, current.path, current.query):
        return None
    return cleaned


def _probe_redirect_paths(
    page_url,
    origin,
    requester,
    add_extra,
    probed,
    absent,
    on_status=None,
    max_path_probes=_MAX_PATH_PROBES,
    probes_per_directory=_PROBES_PER_DIRECTORY,
    should_stop=None,
) -> None:
    """Request likely redirect endpoints under a page that was already opened.

    A language homepage such as /pt-br does not advertise /pt-br/redirect in a
    link. One GET per likely path is enough to decide whether that endpoint
    should join the scan. A response that matches a missing-page canary is
    left out, so a site that answers 200 for every path is not fully retested.
    """

    for base in _bases(page_url):
        used = 0
        for name in load_redirect_paths():
            if should_stop is not None and should_stop():
                return
            if len(probed) >= max_path_probes or used >= probes_per_directory:
                break
            used += 1
            candidate = base.rstrip("/") + "/" + name
            if candidate in probed:
                continue
            probed.add(candidate)
            if on_status is not None:
                on_status(f"Checking {candidate}")
            document = requester.get(candidate, include_body=True)
            if _route_exists(origin, document, requester, absent):
                add_extra(candidate)


def _section_directories(url: str) -> list[str]:
    """Parent folders of a link the site published. The names come from that link."""

    origin = _origin(url)
    parts = [part for part in (urlsplit(url).path or "/").split("/") if part]
    if parts and "." in parts[-1]:
        parts = parts[:-1]
    found = []
    for count in range(1, min(len(parts), 2) + 1):
        found.append(origin + "/" + "/".join(parts[:count]))
    return found


def _query_has_destination(url: str) -> bool:
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if _looks_like_navigation(value):
            return True
        if value.strip() and _looks_like_redirect_name(key):
            return True
    return False


def _route_exists(origin, document: Observation, requester, absent) -> bool:
    if document.safety_block or document.error or document.status_code is None:
        return False
    if document.status_code in {400, 404, 410}:
        return False
    if document.status_code in REDIRECT_STATUSES:
        return True
    if origin not in absent:
        missing = requester.get(origin + "/__blueprint_absent_path__", include_body=True)
        absent[origin] = (missing.status_code, (missing.body or "")[:400])
    status, sample = absent[origin]
    if document.status_code == status and (document.body or "")[:400] == sample:
        return False
    return document.status_code < 400


def _bases(url: str) -> list[str]:
    origin = _origin(url)
    found = [origin]
    path = urlsplit(url).path or "/"
    trimmed = path[:-1] if path.endswith("/") else path
    segment = trimmed.rsplit("/", 1)[-1]
    if "." in segment:
        trimmed = trimmed.rsplit("/", 1)[0]
    if trimmed and trimmed != "/":
        found.append(origin + trimmed)
    return found


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _priority(url: str) -> int:
    parts = urlsplit(url)
    tokens = []
    for segment in parts.path.lower().split("/"):
        if segment:
            tokens.append(segment.split(".", 1)[0].replace("-", ""))
    for name, _value in parse_qsl(parts.query):
        tokens.append(name.lower().replace("-", ""))
    score = 0
    for word in _priority_stems():
        needle = word.replace("-", "")
        if any(token == needle or (len(needle) >= 4 and token.startswith(needle)) for token in tokens):
            score += 1
    return score


def _priority_stems() -> tuple[str, ...]:
    stems = []
    seen: set[str] = set()
    for name in (*PRIORITY_WORDS, *load_redirect_paths()):
        stem = name.split(".", 1)[0].replace("-", "").lower()
        if stem and stem not in seen:
            seen.add(stem)
            stems.append(stem)
    return tuple(stems)


def _fetch_scripts(page_url: str, body: str, requester, add_extra, fetched: list[int], evidence: EvidenceIndex | None = None) -> None:
    origin = _origin(page_url)
    parser = _AnchorParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - a broken page should not abort discovery
        return
    for src in parser.scripts:
        if fetched[0] >= _MAX_SCRIPTS:
            return
        script = _same_origin(origin, page_url, src)
        if not script or not urlsplit(script).path.lower().endswith(".js"):
            continue
        fetched[0] += 1
        document = requester.get(script, include_body=True)
        if document.error or document.safety_block or not document.body:
            continue
        if evidence is not None:
            collect_javascript(page_url, document.body, evidence, script)
        for link in _links_from_document(script, document.body):
            add_extra(link, follow=True)


def _same_origin(origin: str, base: str, candidate: str) -> str | None:
    if not candidate or candidate.startswith("#") or candidate.lower().startswith(_SKIP_PREFIXES):
        return None
    absolute = urljoin(base, candidate)
    parts = urlsplit(absolute)
    if urlunsplit((parts.scheme, parts.netloc, "", "", "")) != origin:
        return None
    cleaned = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    return cleaned


def _links_from_document(base: str, body: str) -> list[str]:
    parser = _AnchorParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - a broken page should not abort discovery
        parser.hrefs = []
    origin = _origin(base)
    found = []
    candidates = list(parser.hrefs)
    candidates.extend(match.group(1) for match in _QUOTED_PATH.finditer(body))
    for href in candidates:
        same = _same_origin(origin, base, href)
        if same and same not in found:
            found.append(same)
    return found


def _links_from_sitemap(body: str) -> list[str]:
    found = []
    lowered = body.lower()
    start = 0
    while True:
        open_at = lowered.find("<loc>", start)
        if open_at < 0:
            break
        close_at = lowered.find("</loc>", open_at)
        if close_at < 0:
            break
        found.append(body[open_at + 5 : close_at].strip())
        start = close_at + 6
    return found


def _sitemaps_from_robots(body: str) -> list[str]:
    found = []
    for line in body.splitlines():
        if line.lower().startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value:
                found.append(value)
    return found


def _links_from_openapi(origin: str, body: str) -> list[str]:
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return []
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return []
    found = []
    for path, operations in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if not isinstance(operations, dict) or "get" not in {str(key).lower() for key in operations}:
            continue
        operation = operations.get("get") or operations.get("GET") or {}
        query = []
        parameters = operation.get("parameters") if isinstance(operation, dict) else None
        if isinstance(parameters, list):
            for item in parameters:
                if isinstance(item, dict) and item.get("in") == "query" and item.get("name"):
                    query.append(f"{item['name']}=1")
        concrete = path.replace("{", "").replace("}", "")
        url = origin + concrete
        if query:
            url = url + "?" + "&".join(query)
        found.append(url)
    return found
