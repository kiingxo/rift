"""Signed-in access: what a test account's session reveals.

Runs only when the scan has a session (rift.session.SignedInSession). Every page
the signed-in crawl read is requested a second time with no session, and the
two answers are compared:

- the anonymous request is refused (401, 403, 404, or a redirect to sign in),
  or the signed-in text appears only in the signed-in answer: the page is
  private, and its caching headers are checked;
- the signed-in text also appears in the anonymous answer: the page shows the
  account's data to anyone, which is reported as critical.

It also looks for the session value inside links and page HTML, judges the
session token itself when it is a JSON Web Token, and repeats the comparison
for GET endpoints in a public API description and for the API addresses the
app's JavaScript names (rift.endpoints): a single-page app keeps its data
behind those, not in its HTML.

Whether signing out ends the session needs the person to sign out first, so
it is a separate step after the scan (see session_end_finding).
"""

from __future__ import annotations

import json
import re
import threading
from urllib.parse import quote, urlsplit

from rift.checks.base import PROBE, Check, CheckContext, is_json, merge_by_title
from rift.models import Finding, Observation, Severity

SESSION_STATE_KEY = "signed-in-state"
_STATE_LOCK = threading.Lock()
_REFUSED = frozenset({301, 302, 303, 307, 308, 401, 403, 404, 410})
_URL_ATTRIBUTE = r"""(?:href|src|action|formaction|data-url|data-href)\s*=\s*["'][^"']*"""
_MAX_AGE = re.compile(r"(?:^|,)\s*(s-maxage|max-age)\s*=\s*\"?(\d+)", re.IGNORECASE)
_OWASP_ACCESS = "A01:2021 Broken Access Control"
_OWASP_AUTH = "A07:2021 Identification and Authentication Failures"


def _path(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _contains(body: str | None, text: str) -> bool:
    return bool(text) and bool(body) and text.casefold() in (body or "").casefold()


def _records(page: Observation) -> int:
    """How many records a JSON list answer holds, or -1 when it is not one."""

    if not is_json(page) or not page.body:
        return -1
    try:
        data = json.loads(page.body)
    except ValueError:
        return -1
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("items", "data", "results", "records", "rows"):
            if isinstance(data.get(key), list):
                return len(data[key])
    return -1


class SignedInCheck(Check):
    id = "signed-in"
    title = "Signed-in access"
    summary = (
        "Needs a test account's session. Private pages that also answer without signing in, private pages "
        "that shared caches may keep, session tokens in links, and whether signing out ends the session."
    )
    kind = PROBE

    def run(self, ctx: CheckContext) -> list[Finding]:
        session = ctx.session
        if session is None or not session.applies_to(ctx.host):
            return []
        state = self._state(ctx)
        found: list[Finding] = []
        signed = [page for page in ctx.pages if page.signed_in and page.status_code == 200 and page.body is not None]
        refused = [page for page in ctx.pages if page.signed_in and page.status_code in _REFUSED and page.status_code != 404]
        with _STATE_LOCK:
            state["pages"] = int(state.get("pages", 0)) + len(signed)
            state["refused"] = int(state.get("refused", 0)) + len(refused)
        for page in signed:
            found.extend(self._compare(ctx, session, page, state))
            found.extend(self._token_exposure(ctx, session, page))
        for page in ctx.pages:
            location = page.location_header or ""
            if page.signed_in and any(token in location for token in self._url_variants(session)):
                found.append(self._token_in_url(ctx, page.url, f"The redirect from {_path(page.url)} puts the session value in its Location header."))
        found.extend(self._api(ctx, session, state))
        found.extend(self._scripted(ctx, session, state))
        found.extend(self._jwt(ctx, session, state))
        return merge_by_title(found)

    # ---- comparison ---------------------------------------------------------

    @staticmethod
    def _state(ctx: CheckContext) -> dict:
        with _STATE_LOCK:
            state = ctx.shared.get(SESSION_STATE_KEY)
            if not isinstance(state, dict):
                state = {
                    "pages": 0,
                    "private": [],
                    "marker_seen": False,
                    "jwt_done": False,
                    "requested": set(),
                    "script_addresses": 0,
                    "script_answers": 0,
                    "hosts_missing": [],
                    "refused": 0,
                }
                ctx.shared[SESSION_STATE_KEY] = state
            return state

    def _compare(self, ctx: CheckContext, session, page: Observation, state: dict) -> list[Finding]:
        marker = session.marker
        signed_has = _contains(page.body, marker)
        anonymous = ctx.fetch(page.url)
        if anonymous.status_code is None:
            return []
        anon_has = anonymous.status_code == 200 and _contains(anonymous.body, marker)
        # The text proves the session works only where a request without it does not show it too.
        if signed_has and not anon_has:
            with _STATE_LOCK:
                state["marker_seen"] = True
        if anon_has:
            return [self._leak(ctx, page, anonymous)]
        # An API that filters by owner answers 200 with an empty list when nobody is signed in.
        emptied = anonymous.status_code == 200 and _records(page) > 0 and _records(anonymous) == 0
        private = anonymous.status_code in _REFUSED or (signed_has and not anon_has) or emptied
        if not private:
            return []
        with _STATE_LOCK:
            if page.url not in state["private"]:
                state["private"].append(page.url)
        return self._caching(ctx, page, anonymous)

    def _leak(self, ctx: CheckContext, page: Observation, anonymous: Observation) -> Finding:
        path = _path(page.url)
        return self.finding(
            ctx,
            url=page.url,
            title="Private data is shown without signing in",
            severity=Severity.CRITICAL.value,
            evidence=(
                f"Signed in: GET {path} returned HTTP 200 containing the signed-in text.\n"
                f"No session: GET {path} returned HTTP {anonymous.status_code} containing the same text."
            ),
            explanation=(
                "This address shows the test account's own data to a request with no cookie and no token. "
                "Anyone who has or guesses the address can read it, and addresses with numeric IDs are easy to guess."
            ),
            remediation=(
                "Check for a valid session on the server for this route and everything under it, and answer 401 or "
                "redirect to sign-in when there is none. Then check that the signed-in user owns the record they ask "
                "for. Add a test that requests the page without a session and expects 401."
            ),
            cwe="CWE-306",
            owasp="API2:2023 Broken Authentication" if is_json(page) else _OWASP_ACCESS,
        )

    def _caching(self, ctx: CheckContext, page: Observation, anonymous: Observation) -> list[Finding]:
        control = (page.header("cache-control") or "").lower()
        directives = {part.strip().split("=", 1)[0] for part in control.split(",") if part.strip()}
        if "no-store" in directives or "private" in directives:
            return []
        ages = {name.lower(): int(value) for name, value in _MAX_AGE.findall(control)}
        why = (
            f"Without a session, GET {_path(page.url)} returned HTTP {anonymous.status_code}, so the page is private. "
            f"Signed in, it was sent with Cache-Control: {page.header('cache-control') or '(none)'}."
        )
        common = dict(
            url=page.url,
            cwe="CWE-524",
            owasp="A05:2021 Security Misconfiguration",
            remediation=(
                "Send `Cache-Control: no-store` on every response that needs a login (at least `private`), and make "
                "sure the CDN or reverse proxy does not cache paths that carry the session cookie."
            ),
        )
        if "public" in directives or ages.get("s-maxage", 0) > 0:
            return [
                self.finding(
                    ctx,
                    title="Private page is marked public for shared caches",
                    severity=Severity.HIGH.value,
                    evidence=why,
                    explanation=(
                        "A CDN or proxy is told it may store this signed-in page and serve the stored copy to other "
                        "visitors, who would then see this account's data."
                    ),
                    **common,
                )
            ]
        if ages.get("max-age", 0) > 0:
            return [
                self.finding(
                    ctx,
                    title="Private page can be stored by caches",
                    severity=Severity.MEDIUM.value,
                    evidence=why,
                    explanation=(
                        "The page allows caching for a while without saying `private`, so a shared cache may keep it, "
                        "and the browser keeps it on disk where the next person on a shared computer can open it."
                    ),
                    **common,
                )
            ]
        return [
            self.finding(
                ctx,
                title="Private page does not tell caches not to store it",
                severity=Severity.LOW.value,
                evidence=why,
                explanation=(
                    "Without `no-store` or `private`, caches decide for themselves. A CDN rule or a browser on a "
                    "shared computer can keep a copy of this signed-in page."
                ),
                **common,
            )
        ]

    # ---- the session value in pages -----------------------------------------

    @staticmethod
    def _url_variants(session) -> list[str]:
        variants: set[str] = set()
        for token in session.tokens():
            if len(token) >= 12:
                variants.update({token, quote(token, safe="")})
        return sorted(variants, key=len, reverse=True)

    def _token_exposure(self, ctx: CheckContext, session, page: Observation) -> list[Finding]:
        body = page.body or ""
        found: list[Finding] = []
        variants = self._url_variants(session)
        in_link = any(token in page.url for token in variants) or any(
            re.search(_URL_ATTRIBUTE + re.escape(token), body, re.IGNORECASE) for token in variants
        )
        if in_link:
            found.append(self._token_in_url(ctx, page.url, f"A link or form on {_path(page.url)} carries the session value."))
        for token in session.cookie_tokens():
            in_links = len(re.findall(_URL_ATTRIBUTE + re.escape(token), body, re.IGNORECASE))
            if body.count(token) > in_links:
                found.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="Session cookie value is written into the page",
                        severity=Severity.MEDIUM.value,
                        evidence=f"The HTML of {_path(page.url)} contains the session cookie's value ([session]).",
                        explanation=(
                            "Any script on the page, including one injected through a cross-site scripting bug, "
                            "can read the session from the HTML, so marking the cookie HttpOnly no longer protects it."
                        ),
                        remediation=(
                            "Do not render the session ID into pages. Let the browser send the cookie on its own, "
                            "and use a separate CSRF token where scripts need one."
                        ),
                        cwe="CWE-1004",
                        owasp=_OWASP_AUTH,
                        confidence="medium",
                    )
                )
                break
        return found

    def _token_in_url(self, ctx: CheckContext, url: str, evidence: str) -> Finding:
        return self.finding(
            ctx,
            url=url,
            title="Session token appears in a URL",
            severity=Severity.HIGH.value,
            evidence=evidence + " The value is shown as [session].",
            explanation=(
                "URLs are kept in browser history, server and proxy logs, analytics, and the Referer header sent to "
                "other sites. A session token in a URL leaks to all of them, and whoever finds it is signed in as this user."
            ),
            remediation=(
                "Keep session tokens out of URLs. Send them only in a cookie (HttpOnly, Secure, SameSite) or an "
                "Authorization header, and rotate any token that has been in a URL."
            ),
            cwe="CWE-598",
            owasp=_OWASP_AUTH,
        )

    # ---- API description ----------------------------------------------------

    def _api(self, ctx: CheckContext, session, state: dict) -> list[Finding]:
        from rift.checks.api_surface import find_spec, get_operations

        located = find_spec(ctx)
        if located is None:
            return []
        _url, spec = located
        found: list[Finding] = []
        seen = {page.url for page in ctx.pages}
        limit = 25 if ctx.deep else 10
        for path, _secured in get_operations(spec)[:limit]:
            url = ctx.origin + path
            if url in seen:
                continue
            response = ctx.fetch(url, signed_in=True)
            if response.status_code != 200 or not response.body or not is_json(response):
                continue
            with _STATE_LOCK:
                state["pages"] = int(state.get("pages", 0)) + 1
            found.extend(self._compare(ctx, session, response, state))
        return found

    # ---- API addresses in the app's JavaScript --------------------------------

    def _scripted(self, ctx: CheckContext, session, state: dict) -> list[Finding]:
        from rift.endpoints import find_api_hints, one_per_route, priority, resolve, shrink, site_of, skip_reason

        if not ctx.scripts:
            return []
        hints = find_api_hints([script.body or "" for script in ctx.scripts])
        site = site_of(ctx.host)
        api_hosts = {urlsplit(base).hostname or "" for base in hints.bases}
        api_hosts.update(urlsplit(address).hostname or "" for address in hints.addresses if "://" in address)
        # A PocketBase server the app opens a client for is its own backend, wherever it is hosted.
        own_backends = {urlsplit(server).hostname or "" for server in hints.pocketbase}
        wanted = {host for host in api_hosts if site_of(host) == site} | own_backends
        for host in sorted(host for host in wanted if host and not session.applies_to(host)):
            with _STATE_LOCK:
                if host in state["hosts_missing"]:
                    continue
                state["hosts_missing"].append(host)
            ctx.note(
                self.id,
                f"The app's JavaScript sends API requests to {host}, which is not part of this scan, so the "
                f"session was not sent there. Add https://{host}/ as a target to read that API signed in.",
            )
        readable_urls: list[str] = []
        app_reads: set[str] = set()
        for address in hints.addresses:
            url = resolve(address, ctx.origin, hints.bases)
            if not session.applies_to(urlsplit(url).hostname or ""):
                continue
            own = url in hints.app_reads
            reason = skip_reason(url, app_read=own)
            if reason:
                self._skipped(state, url, reason)
                continue
            readable_urls.append(shrink(url))
            if own:
                app_reads.add(readable_urls[-1])
        candidates = sorted(one_per_route(readable_urls), key=priority)
        own_routes = {read.split("?", 1)[0].rstrip("/") for read in app_reads}
        # The app's own reads are what its users load every day; guessed addresses get a smaller budget.
        limit = (80 if ctx.deep else 25) if app_reads else (40 if ctx.deep else 15)
        found: list[Finding] = []
        tried = 0
        for url in candidates:
            if tried >= limit:
                break
            with _STATE_LOCK:
                if url in state["requested"]:
                    continue
                state["requested"].add(url)
            tried += 1
            own = url.split("?", 1)[0].rstrip("/") in own_routes
            response = ctx.fetch(url, signed_in=True, app_read=own)
            if response.safety_block:
                self._skipped(state, url, "was refused by Rift's safety rules")
                continue
            if response.signed_in and response.status_code in {401, 403}:
                with _STATE_LOCK:
                    state["refused"] = int(state.get("refused", 0)) + 1
            if response.status_code != 200 or response.body is None or not response.signed_in:
                continue
            with _STATE_LOCK:
                state["pages"] = int(state.get("pages", 0)) + 1
                state["script_answers"] = int(state.get("script_answers", 0)) + 1
            host = urlsplit(url).hostname or ctx.host
            for item in self._compare(ctx, session, response, state):
                item.domain = host
                found.append(item)
        with _STATE_LOCK:
            state["script_addresses"] = int(state.get("script_addresses", 0)) + tried
        return found

    @staticmethod
    def _skipped(state: dict, url: str, reason: str) -> None:
        with _STATE_LOCK:
            listed = state.setdefault("skipped", [])
            if len(listed) < 200 and all(item["url"] != url for item in listed):
                listed.append({"url": url, "reason": reason})

    # ---- the token itself ---------------------------------------------------

    def _jwt(self, ctx: CheckContext, session, state: dict) -> list[Finding]:
        from rift.checks.secrets import _JWT, JwtCheck, decode_jwt

        with _STATE_LOCK:
            if state.get("jwt_done"):
                return []
            state["jwt_done"] = True
        judge = JwtCheck()
        found: list[Finding] = []
        for token in session.tokens():
            if not _JWT.fullmatch(token):
                continue
            decoded = decode_jwt(token)
            if decoded is None:
                continue
            for item in judge._judge(ctx, ctx.origin, token, *decoded):
                item.check = self.id
                item.title = item.title.replace(
                    "Site issues an unsigned JSON Web Token", "Session token is an unsigned JWT"
                ).replace("JSON Web Token", "Session token (JWT)")
                item.evidence = "The test account's session token: " + item.evidence
                found.append(item)
        return found


def session_end_finding(
    session,
    probe_url: str,
    fetch,
    domain: str,
) -> tuple[Finding | None, str]:
    """After the person signed out, is the old session still accepted?

    probe_url is a private page from the scan. fetch(url, signed_in) sends one
    read-only request. Returns (finding or None, plain-language outcome).
    """

    path = _path(probe_url)
    signed = fetch(probe_url, True)
    if signed.status_code is None:
        return None, f"Rift could not reach {path}: {signed.error or 'no response'}. Try again."
    if session.marker:
        still = signed.status_code == 200 and _contains(signed.body, session.marker)
    else:
        still = signed.status_code == 200
    if not still:
        return None, f"Passed. After signing out, {path} no longer accepts the old session (HTTP {signed.status_code})."
    anonymous = fetch(probe_url, False)
    if anonymous.status_code == 200 and not session.marker:
        return None, f"Inconclusive. {path} now answers without a session too, so it cannot show whether the session ended."
    finding = Finding(
        check=SignedInCheck.id,
        title="Signing out does not end the session",
        severity=Severity.HIGH.value,
        url=probe_url,
        evidence=(
            f"After you signed out of the test account, GET {path} with the old session still returned HTTP 200"
            + (" with the signed-in text." if session.marker else ".")
            + f" Without a session it returns HTTP {anonymous.status_code}."
        ),
        explanation=(
            "Signing out only removed the session from the browser; the server still accepts it. Anyone who copied "
            "the cookie or token (from a shared computer, a log, or malware) stays signed in after the user signs out."
        ),
        remediation=(
            "End the session on the server at sign-out: delete it from the session store, or add the token to a deny "
            "list until it expires. For JSON Web Tokens, keep access tokens short-lived and revoke the refresh token."
        ),
        cwe="CWE-613",
        owasp=_OWASP_AUTH,
        domain=domain,
        affected_urls=[probe_url],
    )
    return finding, "Failed. The server still accepts the session after you signed out."
