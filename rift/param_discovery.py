"""Discover parameter names before the redirect payloads run.

The techniques follow the same ideas as parameter miners and crawlers:
read names the application already exposes, generate a bounded set of
spellings, then isolate names that change a response. Arjun is AGPL-3.0 and
its source is not included. This module is original.

A name that never appears in evidence and is not in the candidate list cannot
be found. Callers must say so instead of claiming the application is secure.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

from rift.catalog import load_parameters
from rift.config import tool_root
from rift.query import _is_ordinary_name, _is_sensitive_name, _looks_like_redirect_name

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,40}$")
_MARKER = "bpProbeValue"
_SENTINEL = "bpProbeUnused"
_SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb"}
_SOURCE_CALLS = (
    "request.args.get",
    "request.GET",
    "req.query",
    "c.Query",
    "r.URL.Query().Get",
    "$_GET",
    "$_REQUEST",
    "searchParams.get",
    "searchParams.set",
    "params.get",
)
_JS_HINTS = ("urlsearchparams", "searchparams", ".set(", ".append(", "location", "redirect", "href", "fetch(")


@dataclass(frozen=True)
class ParameterEvidence:
    name: str
    endpoint: str
    source: str
    detail: str


@dataclass
class DiscoveryReport:
    endpoints_analysed: int = 0
    existing_parameters: list[str] = field(default_factory=list)
    passive_parameters: list[str] = field(default_factory=list)
    candidates_generated: int = 0
    candidates_tested: int = 0
    recognised: list[str] = field(default_factory=list)
    verified: list[str] = field(default_factory=list)
    redirect_parameters: list[str] = field(default_factory=list)
    requests: int = 0
    limitations: list[str] = field(default_factory=list)
    records: list[ParameterEvidence] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        lines = [
            f"Endpoints analysed: {self.endpoints_analysed}",
            f"Existing parameters: {len(self.existing_parameters)}",
            f"Passive parameters: {len(self.passive_parameters)}",
            f"Candidates generated: {self.candidates_generated}",
            f"Candidates tested: {self.candidates_tested}",
            f"Parameters potentially recognised: {len(self.recognised)}",
            f"Parameters verified for redirect testing: {len(self.verified)}",
            f"Redirect-related parameters confirmed: {len(self.redirect_parameters)}",
            f"Discovery requests: {self.requests}",
        ]
        if self.limitations:
            lines.append("Coverage limitations:")
            lines.extend(f"- {item}" for item in self.limitations)
        return lines


class EvidenceIndex:
    """Parameter names learned during one scan, keyed by host and path."""

    def __init__(self) -> None:
        self.records: list[ParameterEvidence] = []
        self.limitations: list[str] = []
        self.candidates_generated = 0
        self.candidates_tested = 0
        self.recognised: list[str] = []
        self.verified: list[str] = []
        self.redirect_parameters: list[str] = []
        self.requests = 0
        self.endpoints_analysed = 0
        self._seen: set[tuple[str, str, str]] = set()
        self._lock = threading.Lock()

    def add(self, endpoint: str, name: str, source: str, detail: str) -> None:
        cleaned = _clean_name(name)
        if cleaned is None:
            return
        parts = urlsplit(endpoint) if "://" in endpoint else None
        host = (parts.hostname or "") if parts else ""
        path = (parts.path or "/") if parts else (endpoint or "/")
        key = (host, path, cleaned.lower())
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            self.records.append(ParameterEvidence(cleaned, endpoint, source, detail))

    def add_limitation(self, text: str) -> None:
        with self._lock:
            if text not in self.limitations:
                self.limitations.append(text)

    def note_request(self, count: int = 1) -> None:
        with self._lock:
            self.requests += count

    def note_tested(self, count: int) -> None:
        with self._lock:
            self.candidates_tested += count

    def note_generated(self, count: int) -> None:
        with self._lock:
            self.candidates_generated += count

    def note_recognised(self, name: str) -> None:
        with self._lock:
            if name not in self.recognised:
                self.recognised.append(name)

    def note_verified(self, name: str) -> None:
        with self._lock:
            if name not in self.verified:
                self.verified.append(name)

    def note_redirect(self, name: str) -> None:
        with self._lock:
            if name not in self.redirect_parameters:
                self.redirect_parameters.append(name)

    def direct_names(self, url: str, limit: int) -> list[str]:
        host = (urlsplit(url).hostname or "").lower()
        path = urlsplit(url).path or "/"
        found: list[str] = []
        seen: set[str] = set()
        for record in self.records:
            record_host = (urlsplit(record.endpoint).hostname or "").lower() if "://" in record.endpoint else ""
            record_path = urlsplit(record.endpoint).path or "/" if "://" in record.endpoint else record.endpoint or "/"
            if record_path != path:
                continue
            if record_host and record_host != host:
                continue
            lowered = record.name.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            found.append(record.name)
            if len(found) >= limit:
                break
        return found

    def existing_query_names(self, urls: list[str]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for url in urls:
            for key, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
                cleaned = _clean_name(key)
                if cleaned and cleaned.lower() not in seen:
                    seen.add(cleaned.lower())
                    names.append(cleaned)
        return names

    def report(self, mode: str) -> DiscoveryReport:
        passive = []
        seen: set[str] = set()
        for record in self.records:
            if record.name.lower() in seen:
                continue
            seen.add(record.name.lower())
            passive.append(f"{record.name} · {record.source} · {record.detail}")
        limitations = list(self.limitations)
        if mode == "fast":
            limitations.insert(
                0,
                "Fast Scan reads parameter names from pages it already opens. "
                "It does not run active parameter mining, archive lookups, or a large guess list.",
            )
        limitations.append(
            "A parameter name with no evidence in the fetched pages, supplied dictionaries, "
            "or candidate list cannot be discovered by black-box testing."
        )
        if not self.records and mode == "fast":
            limitations.append("No parameter names were exposed by the pages opened in this scan.")
        return DiscoveryReport(
            endpoints_analysed=self.endpoints_analysed,
            existing_parameters=self.existing_query_names([]),
            passive_parameters=passive,
            candidates_generated=self.candidates_generated,
            candidates_tested=self.candidates_tested,
            recognised=list(self.recognised),
            verified=list(self.verified),
            redirect_parameters=list(self.redirect_parameters),
            requests=self.requests,
            limitations=limitations,
            records=list(self.records),
        )


def collect_html(page_url: str, body: str, evidence: EvidenceIndex) -> None:
    parser = _DocumentParser()
    try:
        parser.feed(body or "")
        parser.close()
    except Exception:  # noqa: BLE001 - one broken page should not abort discovery
        return
    origin = _origin(page_url)
    for href in parser.hrefs:
        absolute = _same_origin(origin, page_url, href)
        if not absolute:
            continue
        for key, _value in parse_qsl(urlsplit(absolute).query, keep_blank_values=True):
            evidence.add(absolute, key, "html", "link")
    for action, names in parser.forms:
        target = _same_origin(origin, page_url, action) if action else page_url
        if not target:
            target = page_url
        for name in names:
            evidence.add(target, name, "html", "form field")
    for script in parser.inline_scripts:
        for name in javascript_names(script):
            evidence.add(page_url, name, "javascript", "inline script")


def collect_javascript(page_url: str, body: str, evidence: EvidenceIndex, detail: str) -> None:
    for name in javascript_names(body or ""):
        evidence.add(page_url, name, "javascript", detail)


def collect_openapi(origin: str, body: str, evidence: EvidenceIndex) -> None:
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return
    for path, operations in paths.items():
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for operation in operations.values():
            if not isinstance(operation, dict):
                continue
            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                continue
            for item in parameters:
                if isinstance(item, dict) and item.get("in") == "query" and item.get("name"):
                    evidence.add(origin + path.split("{", 1)[0], str(item["name"]), "openapi", "query parameter")


def collect_historical(text: str, evidence: EvidenceIndex) -> None:
    """Read a local list of previously seen URLs. Values are discarded."""

    for line in (text or "").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or "://" not in value:
            continue
        parts = urlsplit(value)
        bare = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        for key, _ignored in parse_qsl(parts.query, keep_blank_values=True):
            evidence.add(bare, key, "historical", "supplied URL list")


def collect_source_tree(root: str, endpoints: list[str], evidence: EvidenceIndex) -> None:
    """Optional local source read. It does not fetch anything."""

    base = Path(root)
    if not root or not base.is_dir():
        if root:
            evidence.add_limitation("The source directory was not available, so repository analysis was skipped.")
        return
    seen_files = 0
    for path in base.rglob("*"):
        if seen_files >= 200:
            evidence.add_limitation("Source analysis stopped after 200 files.")
            break
        if not path.is_file() or path.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue
        if path.stat().st_size > 200_000:
            continue
        seen_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in _source_names(text):
            for endpoint in endpoints:
                evidence.add(endpoint, name, "source", path.name)


def mining_candidates(
    endpoint: str,
    observed: list[str],
    catalog: tuple[str, ...],
    extras: tuple[str, ...],
    limit: int,
) -> list[str]:
    """Bounded guesses. Observed names are not repeated here; they are tested directly."""

    known = {name.lower() for name in catalog}
    known.update(name.lower() for name in observed)
    ranked: list[str] = []
    seen: set[str] = set()

    def push(name: str) -> None:
        cleaned = _clean_name(name)
        if cleaned is None or cleaned.lower() in known or cleaned.lower() in seen:
            return
        if len(ranked) >= limit:
            return
        seen.add(cleaned.lower())
        ranked.append(cleaned)

    for name in extras:
        push(name)
    for name in observed:
        for variant in _name_variants(name):
            push(variant)
    segment = _path_segment(endpoint)
    if segment:
        push(segment + "Url")
        push(segment + "Target")
        push(segment + "_url")
    for name in load_mining_words():
        push(name)
    return ranked


def load_mining_words() -> tuple[str, ...]:
    raw = json.loads((tool_root() / "rift" / "mining_words.json").read_text(encoding="utf-8"))
    return tuple(str(item) for item in raw.get("words", []))


def javascript_names(source: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def keep(name: str) -> None:
        cleaned = _clean_name(name)
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            found.append(cleaned)

    for name in _search_param_keys(source):
        keep(name)
    for index, text in _string_literals(source):
        window = source[max(0, index - 80) : index].lower()
        hinted = any(token in window for token in _JS_HINTS)
        if hinted:
            keep(text)
        if "?" in text or "&" in text or (hinted and "=" in text):
            for key, _value in _pairs_in_text(text):
                keep(key)
    return found


def _search_param_keys(source: str) -> list[str]:
    """Read identifier keys inside URLSearchParams({ ... })."""

    found: list[str] = []
    lowered = source.lower()
    cursor = 0
    while True:
        at = lowered.find("urlsearchparams", cursor)
        if at < 0:
            break
        cursor = at + len("urlsearchparams")
        brace = source.find("{", at, at + 48)
        if brace < 0:
            continue
        depth = 0
        token: list[str] = []
        index = brace
        while index < len(source):
            char = source[index]
            if char in {"'", '"'}:
                end = index + 1
                while end < len(source) and source[end] != char:
                    end += 2 if source[end] == "\\" else 1
                index = end + 1
                token = []
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            elif char == ":" and depth == 1:
                found.append("".join(token).strip())
                token = []
            elif char in {",", "\n", "\r"}:
                token = []
            elif char not in " \t":
                token.append(char)
            index += 1
    return found


def normalize_body(body: str, marker: str = _MARKER) -> str:
    text = body or ""
    text = text.replace(marker, "")
    text = re.sub(r"\b\d{10,13}\b", "", text)
    text = re.sub(r"\b[a-fA-F0-9]{16,}\b", "", text)
    text = re.sub(r"(?i)\b[a-z_][a-z0-9_-]{0,40}=(?=&|\s|$)", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def response_changed(baseline_status, baseline_location, baseline_body, observed) -> bool:
    if observed is None or observed.error:
        return False
    if observed.status_code != baseline_status:
        return True
    if (observed.location_header or "") != (baseline_location or ""):
        return True
    return normalize_body(observed.body or "") != normalize_body(baseline_body or "")


def isolate_parameters(endpoint, requester, names, max_requests, should_stop, on_status, evidence: EvidenceIndex) -> list[str]:
    """Split batches until one name is shown to change the response, twice."""

    if not names or max_requests <= 0:
        return []
    evidence.note_generated(len(names))
    if on_status is not None:
        on_status(f"Mining candidate parameters on {endpoint}")
    baseline = _get(requester, endpoint, evidence)
    again = _get(requester, endpoint, evidence)
    if baseline is None or again is None:
        return []
    if response_changed(baseline.status_code, baseline.location_header, baseline.body, again):
        evidence.add_limitation(f"{endpoint} returned unstable responses, so parameter mining was skipped.")
        return []
    sentinel = _with_query(endpoint, [(_SENTINEL, _MARKER)])
    probe = _get(requester, sentinel, evidence)
    evidence.note_tested(1)
    if response_changed(baseline.status_code, baseline.location_header, baseline.body, probe):
        evidence.add_limitation(
            f"{endpoint} changes its response for every added parameter, so mining cannot identify a real name."
        )
        return []
    found: list[str] = []
    budget = {"left": max_requests}

    def walk(batch: list[str]) -> None:
        if not batch or budget["left"] <= 0 or (should_stop is not None and should_stop()):
            return
        target = _with_query(endpoint, [(name, _MARKER) for name in batch])
        if len(target) > 1800 and len(batch) > 1:
            middle = max(1, len(batch) // 2)
            walk(batch[:middle])
            walk(batch[middle:])
            return
        observed = _get(requester, target, evidence)
        budget["left"] -= 1
        evidence.note_tested(len(batch) if observed is not None else 0)
        if observed is None:
            return
        rejected = observed.status_code in {400, 413, 414, 431} and observed.status_code != baseline.status_code
        if rejected and len(batch) > 1:
            evidence.add_limitation(f"{endpoint} rejected a large parameter batch, so the batch was split.")
            middle = max(1, len(batch) // 2)
            walk(batch[:middle])
            walk(batch[middle:])
            return
        if not response_changed(baseline.status_code, baseline.location_header, baseline.body, observed):
            return
        if len(batch) > 1:
            middle = max(1, len(batch) // 2)
            walk(batch[:middle])
            walk(batch[middle:])
            return
        confirm = _get(requester, target, evidence)
        budget["left"] -= 1
        if response_changed(baseline.status_code, baseline.location_header, baseline.body, confirm):
            found.append(batch[0])
            evidence.note_recognised(batch[0])
            evidence.add(endpoint, batch[0], "mined", "response differed from the baseline")
            if on_status is not None:
                on_status(f"Verifying parameter {batch[0]}")

    group = 8
    for start in range(0, len(names), group):
        walk(names[start : start + group])
        if budget["left"] <= 0:
            evidence.add_limitation(f"Parameter mining on {endpoint} stopped at its request budget.")
            break
    return found


def _get(requester, url, evidence: EvidenceIndex):
    evidence.note_request()
    try:
        return requester.get(url, include_body=True)
    except TypeError:
        return requester.get(url)
    except Exception:  # noqa: BLE001 - mining must not abort the scan
        return None


def _with_query(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(url)
    extra = "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in pairs)
    query = extra if not parts.query else parts.query + "&" + extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def _clean_name(name: str) -> str | None:
    text = (name or "").strip()
    if not _NAME.fullmatch(text):
        return None
    if _is_ordinary_name(text) or _is_sensitive_name(text):
        return None
    if text.lower() in {_SENTINEL.lower(), _MARKER.lower()}:
        return None
    return text


def _name_variants(name: str) -> list[str]:
    if "_" in name:
        parts = [part for part in name.split("_") if part]
        if len(parts) > 1:
            camel = parts[0].lower() + "".join(part.capitalize() for part in parts[1:])
            return [camel, "-".join(part.lower() for part in parts)]
    pieces = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", name)
    if len(pieces) > 1:
        return ["_".join(part.lower() for part in pieces), "-".join(part.lower() for part in pieces)]
    return []


def _path_segment(url: str) -> str:
    parts = [part for part in (urlsplit(url).path or "/").split("/") if part]
    if not parts:
        return ""
    segment = parts[-1].split(".", 1)[0]
    if not segment.isalpha() or not 4 <= len(segment) <= 24:
        return ""
    if _looks_like_redirect_name(segment):
        return ""
    return segment


def _source_names(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for index, literal in _string_literals(text):
        window = text[max(0, index - 60) : index]
        if not any(call in window for call in _SOURCE_CALLS):
            continue
        cleaned = _clean_name(literal)
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            found.append(cleaned)
    return found


def _string_literals(source: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    index = 0
    length = len(source)
    while index < length:
        quote = source[index]
        if quote not in {"'", '"'}:
            index += 1
            continue
        start = index
        index += 1
        chars: list[str] = []
        while index < length:
            char = source[index]
            if char == "\\":
                if index + 1 < length:
                    chars.append(source[index + 1])
                    index += 2
                    continue
            if char == quote:
                found.append((start, "".join(chars)))
                index += 1
                break
            chars.append(char)
            index += 1
        else:
            break
    return found


def _pairs_in_text(text: str) -> list[tuple[str, str]]:
    candidate = text
    if "?" in candidate:
        candidate = candidate.split("?", 1)[1]
    if "=" not in candidate:
        return []
    return parse_qsl(candidate.replace(";", "&"), keep_blank_values=True)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _same_origin(origin: str, base: str, candidate: str) -> str | None:
    if not candidate or candidate.startswith("#"):
        return None
    lowered = candidate.lower()
    if lowered.startswith(("javascript:", "mailto:", "data:", "tel:")):
        return None
    absolute = urljoin(base, candidate)
    parts = urlsplit(absolute)
    if urlunsplit((parts.scheme, parts.netloc, "", "", "")) != origin:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.forms: list[tuple[str, list[str]]] = []
        self.inline_scripts: list[str] = []
        self._script = False
        self._buffer: list[str] = []
        self._form: list[str] | None = None
        self._action = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        attributes = {key.lower(): (value or "") for key, value in attrs}
        if name == "script" and not attributes.get("src"):
            self._script = True
            self._buffer = []
        if name in {"a", "area", "link"} and attributes.get("href"):
            self.hrefs.append(attributes["href"].strip())
        if name == "form":
            self._form = []
            self._action = attributes.get("action", "").strip()
        if name in {"input", "select", "textarea", "button"} and self._form is not None:
            field = attributes.get("name", "").strip()
            if field:
                self._form.append(field)
        for key, value in attributes.items():
            if key.startswith("data-") and value and _clean_name(value) and "param" in key:
                if self._form is None:
                    self._form = []
                    self._action = ""
                self._form.append(value)

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name == "script" and self._script:
            self.inline_scripts.append("".join(self._buffer))
            self._script = False
            self._buffer = []
        if name == "form" and self._form is not None:
            self.forms.append((self._action, list(self._form)))
            self._form = None
            self._action = ""

    def handle_data(self, data: str) -> None:
        if self._script:
            self._buffer.append(data)


def catalog_names_for_report() -> list[str]:
    return [item.name for item in load_parameters()]
