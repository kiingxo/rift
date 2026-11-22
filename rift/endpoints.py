"""API addresses written in an app's JavaScript.

A single-page app shows almost nothing in its HTML: the browser runs the
bundle, and the bundle asks an API for the account's data. Rift does not run
JavaScript. It reads the bundle as text and picks out:

- the API's base address, from ``baseUrl: "https://api.example.com/api/"``
  (axios, fetch wrappers, Redux Toolkit Query) or a variable holding one;
- read calls made against that base: ``api.get("auth/profile")``,
  ``api.get(`${BASE}patients`)``, and Redux Toolkit Query endpoints declared
  with ``builder.query({ query: () => "/users" })``. Mutations, and calls whose
  path holds a placeholder (``${id}``), are left out;
- literal API paths (``"/api/me"``, ``"/v1/orders"``) and full API URLs;
- PocketBase: ``new PocketBase("https://pb.example.com")`` names its server, and
  ``pb.collection("patients")`` reads ``/api/collections/patients/records`` there.
  PocketBase's own admin paths (settings, logs, backups) are ignored: they are
  part of the library, not of the app.

Nothing here sends a request. The signed-in check decides which addresses are
safe to read (see ``readable``), asks list endpoints for one record (``shrink``)
and requests them with GET only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from rift.session import action_word

_IDENT = r"[A-Za-z_$][\w$]{0,40}"
_URL = re.compile(r"""["'`](https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~%/-]*)?)["'`]""")
# NAME = "https://host/api/"  or  baseUrl: "https://host/api/"
_BASE = re.compile(
    rf"""(?:\b({_IDENT})\s*=\s*|\bbase(?:Url|URL|_url)\s*:\s*)["'`](https?://[A-Za-z0-9.-]+(?::\d{{1,5}})?/[A-Za-z0-9._~%/-]*)["'`]"""
)
_API_PATH = re.compile(
    r"""["'`](/(?:api|rest|v[0-9]{1,2}|graphql|_api|json)(?:/[A-Za-z0-9._~%-]+)*/?(?:\?[A-Za-z0-9._~%=&-]*)?)["'`]"""
)
_FULL_API = re.compile(
    r"""["'`](https?://[A-Za-z0-9.-]+(?::\d{1,5})?/(?:api|rest|v[0-9]{1,2}|_api)(?:/[A-Za-z0-9._~%-]+)+/?)["'`]"""
)
# client.get("path") / client.get(`${BASE}path`): an HTTP read through a client object.
_GET_CALL = re.compile(rf"""\.get\(\s*["'`](?:\$\{{({_IDENT})\}})?([A-Za-z0-9_/][^"'`\s]{{0,160}})["'`]""")
# Redux Toolkit Query: builder.query({ query: (arg) => "path" | ({ url: "path", ... }) })
_RTK_QUERY = re.compile(
    rf"""\.query\(\{{\s*query:\s*(?:\([^)]{{0,120}}\)|{_IDENT})\s*=>\s*(?:\(\{{\s*url:\s*)?["'`](?:\$\{{({_IDENT})\}})?([A-Za-z0-9_/][^"'`\s]{{0,160}})["'`]"""
)
_WRITE_METHOD = re.compile(r"""method:\s*["'`](?:POST|PUT|PATCH|DELETE)["'`]""", re.IGNORECASE)
_POCKETBASE_CLIENT = re.compile(r"""\bnew\s+[A-Za-z_$][\w$]{0,30}\(\s*["'`](https?://[A-Za-z0-9.-]+(?::\d{1,5})?)/?["'`]\s*\)""")
_POCKETBASE = re.compile(r"""\.collection\(\s*["'`]([A-Za-z0-9_]{1,64})["'`]\s*\)""")
_POCKETBASE_SIGN = "/api/collections/"
# Paths the PocketBase library itself uses for its admin dashboard.
_POCKETBASE_INTERNAL = re.compile(r"^/api/(?:admins|settings|logs|backups|realtime|files|health|collections/?$|crons)")
# Scripts a bundle loads later (code splitting): "assets/Patients-1a2b3c.js", "./chunk-9f8e.js".
_CHUNK = re.compile(r"""["'`]((?:\./|\.\./|/)?(?:[A-Za-z0-9_-]+/){0,3}[A-Za-z0-9_.-]+\.m?js)["'`]""")
_HASHED = re.compile(r"[-.][A-Za-z0-9_]{6,}\.m?js$")
# A REST path as apps write them: lower-case segments, maybe a query.
_REST_PATH = re.compile(r"^/?[a-z0-9][a-z0-9_.~%-]*(?:/[a-z0-9_.~%-]+)*/?(?:\?.*)?$")
# Arguments to .get() that are not paths: headers, storage keys, URL parameters.
_NOT_PATHS = frozenset(
    {
        "content-type", "authorization", "accept", "cookie", "token", "email", "user", "id", "name",
        "page", "limit", "code", "state", "type", "lang", "locale", "theme", "redirect", "next", "q",
    }
)

# Addresses that can do something, hold a connection open, or download files.
# A GET to them is not sent even when the HTTP method looks harmless.
_SKIP_WORDS = frozenset(
    {
        "generate", "test", "trigger", "run", "execute", "start", "sync", "import", "export",
        "backup", "backups", "realtime", "stream", "events", "sse", "ws", "websocket", "socket",
        "webhook", "webhooks", "callback", "redirect", "oauth", "oauth2", "login", "signin", "logout",
        "token", "tokens", "refresh", "otp", "mfa", "upload", "download", "file", "files", "batch",
        "notify", "email", "sms", "mail", "publish", "cron", "crons", "jobs", "job", "queue", "verify",
    }
)
# Query parameters that set a page size. Lists are read one record at a time.
_PAGE_SIZE = frozenset({"limit", "perpage", "per_page", "pagesize", "page_size", "size", "take", "count", "first", "top"})
_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_MAX_PER_SCRIPT = 600


@dataclass
class ApiHints:
    """What the scripts say about the app's API."""

    # Origins named in full URLs, with how many times each appears.
    origins: dict[str, int] = field(default_factory=dict)
    # Base addresses under which the API sits ("https://api.example.com/api/"), most used first.
    bases: list[str] = field(default_factory=list)
    # Paths or full URLs to read, in the order they were found.
    addresses: list[str] = field(default_factory=list)
    # PocketBase servers the app creates a client for, and the collections it reads.
    pocketbase: list[str] = field(default_factory=list)
    collections: list[str] = field(default_factory=list)
    # Absolute addresses the app itself reads with GET (client.get, query endpoints, PocketBase lists).
    app_reads: set[str] = field(default_factory=set)


def _add(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def _clean_path(path: str) -> str | None:
    """A path without placeholders, or None. A placeholder in the query only drops the query."""

    route, _, query = path.partition("?")
    if "${" in route or not route.strip("/"):
        return None
    if "${" in query or "`" in query:
        query = ""
    # One lower-case word ("currency") or several segments ("auth/sendPhoneNumberOTP").
    # A single camelCase word ("invitationId") is a parameter name, not a path.
    candidate = route + ("?" + query if query else "")
    if not _REST_PATH.fullmatch(candidate) and not (
        "/" in route.strip("/") and _REST_PATH.fullmatch(route.lower() + ("?" + query if query else ""))
    ):
        return None
    if route.strip("/").lower() in _NOT_PATHS:
        return None
    return route + ("?" + query if query else "")


def find_api_hints(texts: list[str]) -> ApiHints:
    """Read script text and collect the API addresses it names. Sends nothing."""

    hints = ApiHints()
    variables: dict[str, str] = {}
    declared: dict[str, int] = {}
    calls: list[tuple[str | None, str]] = []
    pocketbase = False
    for text in texts:
        if not text:
            continue
        has_pocketbase = _POCKETBASE_SIGN in text
        pocketbase = pocketbase or has_pocketbase
        for count, match in enumerate(_URL.finditer(text)):
            if count >= _MAX_PER_SCRIPT:
                break
            parts = urlsplit(match.group(1))
            if not parts.hostname or ("." not in parts.hostname and parts.hostname != "localhost"):
                continue
            origin = urlunsplit((parts.scheme, parts.netloc.lower(), "", "", ""))
            hints.origins[origin] = hints.origins.get(origin, 0) + 1
            if re.fullmatch(r"/(?:api|rest|v[0-9]{1,2}|_api)/?", parts.path or ""):
                base = origin + parts.path.rstrip("/") + "/"
                declared[base] = declared.get(base, 0) + 1
        for match in _BASE.finditer(text):
            name, url = match.group(1), match.group(2)
            # A variable is an API base only when its path says so; baseUrl: always is.
            if name is not None and not re.search(r"/(?:api|rest|v[0-9]{1,2}|_api|graphql)(?:/|$)", urlsplit(url).path):
                continue
            base = url if url.endswith("/") else url + "/"
            declared[base] = declared.get(base, 0) + (3 if name is None else 1)
            if name:
                variables[name] = base
        for count, match in enumerate(_FULL_API.finditer(text)):
            if count >= _MAX_PER_SCRIPT:
                break
            _add(hints.addresses, match.group(1))
        for count, match in enumerate(_API_PATH.finditer(text)):
            if count >= _MAX_PER_SCRIPT:
                break
            path = match.group(1)
            if has_pocketbase and _POCKETBASE_INTERNAL.match(path):
                continue
            _add(hints.addresses, path)
        for pattern in (_GET_CALL, _RTK_QUERY):
            for count, match in enumerate(pattern.finditer(text)):
                if count >= _MAX_PER_SCRIPT:
                    break
                # Only this endpoint's own options count: stop at the end of its object.
                if pattern is _RTK_QUERY and _WRITE_METHOD.search(text[match.end() : match.end() + 160].split("})", 1)[0]):
                    continue
                path = _clean_path(match.group(2))
                if path is not None:
                    calls.append((match.group(1), path))
        if has_pocketbase:
            for match in _POCKETBASE_CLIENT.finditer(text):
                _add(hints.pocketbase, match.group(1).rstrip("/"))
        for count, match in enumerate(_POCKETBASE.finditer(text)):
            if count >= _MAX_PER_SCRIPT:
                break
            _add(hints.collections, match.group(1))
    hints.bases = sorted(declared, key=lambda base: -declared[base])
    main = hints.bases[0] if hints.bases else None
    for name, path in calls:
        if path.startswith("api/collections/") and hints.pocketbase:
            continue  # a PocketBase call made through a generic client; read below instead
        if name is not None:
            base = variables.get(name)
            if base is None:
                continue
            url = _join(base, path)
        elif main is not None:
            url = _join(main, path)
        else:
            continue
        _add(hints.addresses, url)
        hints.app_reads.add(url)
    if pocketbase:
        servers = hints.pocketbase or [""]
        for name in hints.collections:
            for server in servers:
                url = f"{server}/api/collections/{name}/records?perPage=1"
                _add(hints.addresses, url)
                if server:
                    hints.app_reads.add(url)
    return hints


def chunk_scripts(script_url: str, text: str, limit: int = 40) -> list[str]:
    """Other bundle files a script loads later, as absolute URLs on the same origin."""

    found: list[str] = []
    origin = urlunsplit(urlsplit(script_url)[:2] + ("", "", ""))
    for match in _CHUNK.finditer(text or ""):
        reference = match.group(1)
        if not _HASHED.search(reference) or "//" in reference:
            continue
        if reference.startswith(("./", "../")):
            absolute = urljoin(script_url, reference)
        elif reference.startswith("/"):
            absolute = origin + reference
        else:
            # Vite and webpack write chunk paths relative to the site root ("assets/x.js").
            absolute = origin + "/" + reference
        if urlsplit(absolute).netloc == urlsplit(script_url).netloc and absolute not in found:
            found.append(absolute)
            if len(found) >= limit:
                break
    return found


def resolve(address: str, page_origin: str, bases: list[str]) -> str:
    """An absolute URL for an address, placed under the API base it belongs to."""

    if address.startswith(("http://", "https://")):
        return address
    for base in bases:
        base_path = urlsplit(base).path
        if base_path and address.startswith(base_path):
            return urlunsplit(urlsplit(base)[:2] + ("", "", "")) + address
    return page_origin + address


def _words(text: str) -> set[str]:
    spaced = _CAMEL.sub(r"\1 \2", text)
    return {word for word in _SPLIT.split(spaced.lower()) if word}


# Even for the app's own reads: sign-in flows and live streams are not opened.
_APP_READ_SKIP_WORDS = frozenset(
    {
        "realtime", "stream", "sse", "ws", "websocket", "socket", "events", "oauth", "oauth2", "callback",
        "redirect", "login", "signin", "logout", "token", "tokens", "refresh", "otp", "mfa",
    }
)


def skip_reason(url: str, *, app_read: bool = False) -> str | None:
    """Why a GET to this address is not sent while signed in, or None when it only reads.

    app_read: the app's own JavaScript reads this address with GET, so only clear
    actions, sign-in flows and live streams are skipped. Other addresses found in
    the scripts get the strict rule.
    """

    if any(character in url for character in "${}<>*`"):
        return "has a placeholder that Rift cannot fill"
    parts = urlsplit(url)
    if re.search(r"/:[A-Za-z]", parts.path):
        return "has a placeholder that Rift cannot fill"
    word = action_word(url, app_read=app_read)
    if word:
        return f"names an action (\u201c{word}\u201d)"
    hit = _words(parts.path + " " + parts.query) & (_APP_READ_SKIP_WORDS if app_read else _SKIP_WORDS)
    if hit:
        word = sorted(hit)[0]
        if word in _APP_READ_SKIP_WORDS:
            return f"is a sign-in step or live connection (\u201c{word}\u201d)"
        return f"may start a job, send a message or move a file (\u201c{word}\u201d)"
    return None


def readable(url: str, *, app_read: bool = False) -> bool:
    """True when a GET to this address only reads: no action words, no placeholders, no streams."""

    return skip_reason(url, app_read=app_read) is None


def shrink(url: str) -> str:
    """Ask a list for one record: limit=All or perPage=50 becomes 1."""

    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    changed = [(key, "1" if key.lower().replace("-", "_") in _PAGE_SIZE else value) for key, value in pairs]
    if changed == pairs:
        return url
    return urlunsplit(parts._replace(query=urlencode(changed, safe="[]")))


def one_per_route(urls: list[str]) -> list[str]:
    """Read each route once, asking lists for a single record.

    `/api/patients` and `/api/patients?limit=All` are the same list: keep the
    form with a query (already shrunk to one record). A bare route gets the
    page-size parameter the app uses elsewhere, set to 1, which a server that
    does not know it ignores.
    """

    # The page-size parameter each API uses, learned from its own calls (PocketBase's perPage stays with PocketBase).
    names: dict[str, dict[str, int]] = {}
    for url in urls:
        parts = urlsplit(url)
        if "/api/collections/" in parts.path:
            continue
        for key, _value in parse_qsl(parts.query):
            if key.lower().replace("-", "_") in _PAGE_SIZE:
                counts = names.setdefault(parts.netloc, {})
                counts[key] = counts.get(key, 0) + 1
    chosen: dict[str, str] = {}
    for url in urls:
        parts = urlsplit(url)
        route = urlunsplit(parts._replace(path=parts.path.rstrip("/") or "/", query="", fragment=""))
        current = chosen.get(route)
        if current is None or (not urlsplit(current).query and parts.query):
            chosen[route] = url
    out: list[str] = []
    for route, url in chosen.items():
        counts = names.get(urlsplit(route).netloc) or {}
        size = max(counts, key=lambda key: counts[key]) if counts else None
        last = urlsplit(route).path.rsplit("/", 1)[-1].lower()
        single = last in {"me", "profile", "account", "whoami", "session", "current", "settings"}
        if not urlsplit(url).query and size and not single and urlsplit(route).path.count("/") >= 2:
            url = route + "?" + urlencode({size: "1"})
        out.append(url)
    return out


def site_of(host: str) -> str:
    """The registrable part of a host, roughly: auth-uat.example.co.uk -> example.co.uk."""

    labels = (host or "").lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def priority(url: str) -> tuple[int, int]:
    """Read the addresses most likely to show the signed-in user's own data first."""

    path = urlsplit(url).path.lower()
    own = any(word in path for word in ("/me", "profile", "account", "user", "session", "whoami", "current"))
    records = "/records" in path
    return (0 if own else 1 if records else 2, len(path))
