"""Run every selected check against a list of authorised URLs.

One pass collects the pages and scripts of each origin. Passive checks read
those. Probe checks send a small number of extra read-only requests through
the same scoped client. The open-redirect engine runs last and shares the
client, so its results land in the same report.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit

from rift.checks import REDIRECT_CHECK_ID, all_checks, resolve_checks
from rift.checks.base import Check, CheckContext, is_html
from rift.checks.content import parse_resources
from rift.config import MAX_SCRIPT_BYTES, ScanConfig
from rift.endpoints import chunk_scripts
from rift.http_client import HttpxRequester
from rift.models import CheckNote, Finding, Observation, ScanResult, Severity, Verdict
from rift.safety import ScopeError, validate_target

ProgressCallback = Callable[[int, int, str], None]
FindingCallback = Callable[[Finding], None]

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_HOPS = 3
# Scripts read for one site, in total, so a site with many chunks cannot fill memory.
_SCRIPT_BYTES_PER_SITE = 24_000_000


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)
    notes: list[CheckNote] = field(default_factory=list)
    origins: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    submitted_urls: list[str] = field(default_factory=list)
    requests_sent: int = 0
    mode: str = "fast"
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    cancelled: bool = False
    redirects: list[ScanResult] | None = None
    # What the report may say about a test-account session (never its value), or None.
    session: dict | None = None

    def counts(self) -> dict[str, int]:
        totals = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            totals[finding.severity] = totals.get(finding.severity, 0) + 1
        totals["total"] = len(self.findings)
        return totals

    def worst(self) -> str | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda item: item.rank).severity


class _Fetcher:
    """Counts requests, enforces the per-domain cap, and never raises."""

    def __init__(self, requester, config: ScanConfig, cancel: threading.Event | None) -> None:
        self.requester = requester
        self.config = config
        self.cancel = cancel
        self.sent = 0
        self._per_host: dict[str, int] = {}
        self._lock = threading.Lock()

    def stopped(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def __call__(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        include_body: bool = True,
        signed_in: bool = False,
        max_bytes: int | None = None,
        app_read: bool = False,
    ) -> Observation:
        if self.stopped():
            return Observation(error="Scan cancelled", url=url)
        host = urlsplit(url).hostname or ""
        with self._lock:
            used = self._per_host.get(host, 0)
            if used >= self.config.max_requests_per_domain:
                return Observation(error="This domain reached its request limit", url=url)
            self._per_host[host] = used + 1
            self.sent += 1
        try:
            if hasattr(self.requester, "request"):
                options: dict[str, object] = {"signed_in": True} if signed_in else {}
                if max_bytes:
                    options["max_bytes"] = max_bytes
                if app_read:
                    options["app_read"] = True
                observation = self.requester.request(
                    url, method=method, headers=headers, include_body=include_body, allow_static=True, **options
                )
            elif method == "GET" and not headers:
                observation = self.requester.get(url, include_body=include_body)
            else:
                observation = Observation(error="This client cannot send that request")
        except Exception as exc:  # noqa: BLE001 - one bad response must not stop the scan
            observation = Observation(error=f"Request failed: {exc.__class__.__name__}")
        if not observation.url:
            observation.url = url
        return observation


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _in_scope(url: str, config: ScanConfig, *, allow_static: bool = False) -> str | None:
    try:
        return validate_target(url, config, allow_static=allow_static)
    except ScopeError:
        return None


def _collect(
    seeds: list[str],
    fetch: _Fetcher,
    config: ScanConfig,
    deep: bool,
    announce: Callable[[str], None],
    signed_in: bool = False,
) -> tuple[dict[str, list[Observation]], dict[str, list[Observation]], list[CheckNote]]:
    """Fetch the submitted URLs, follow in-scope redirects, then a few linked pages and scripts.

    Signed in, the crawl reads more pages and follows links from every page it
    reads, not only the first, because the private part of an app sits behind
    a dashboard: the account page links to the invoice list, which links to
    each invoice.
    """

    pages: dict[str, list[Observation]] = {}
    scripts: dict[str, list[Observation]] = {}
    notes: list[CheckNote] = []
    seen: set[str] = set()
    extra_pages = 12 if deep else 4
    max_scripts = 20 if deep else 8
    if signed_in:
        extra_pages = 30 if deep else 12

    def keep(observation: Observation) -> None:
        pages.setdefault(_origin(observation.url), []).append(observation)

    def open_page(url: str) -> Observation | None:
        """Fetch one URL and follow redirects that stay inside the authorised scope."""

        current = url
        landed: Observation | None = None
        for _hop in range(_MAX_HOPS + 1):
            if current in seen or fetch.stopped():
                return landed
            seen.add(current)
            announce(f"Opening {current}" + (" (signed in)" if signed_in else ""))
            observation = fetch(current, include_body=True, signed_in=signed_in)
            if observation.status_code is None:
                notes.append(CheckNote("collect", current, observation.error or "No response"))
                return landed
            keep(observation)
            landed = observation
            if observation.status_code not in _REDIRECT_STATUSES or not observation.location_header:
                return landed
            target = _in_scope(urljoin(current, observation.location_header), config)
            if target is None:
                return landed
            current = target
        return landed

    landings: list[Observation] = []
    for seed in seeds:
        landed = open_page(seed)
        if landed is not None and landed.status_code == 200:
            landings.append(landed)

    added_per_origin: dict[str, int] = {}
    queue = list(landings)
    while queue:
        landing = queue.pop(0)
        if fetch.stopped() or not is_html(landing):
            continue
        origin = _origin(landing.url)
        resources = parse_resources(landing.body or "")
        # Signed in, the budget is per site; anonymous, it is per submitted URL, as before.
        budget_key = origin if signed_in else landing.url
        for href in resources.links:
            if added_per_origin.get(budget_key, 0) >= extra_pages:
                break
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            target = _in_scope(urljoin(landing.url, href).split("#", 1)[0], config)
            if target is None or _origin(target) != origin or target in seen:
                continue
            opened = open_page(target)
            if opened is not None:
                added_per_origin[budget_key] = added_per_origin.get(budget_key, 0) + 1
                if signed_in and opened.status_code == 200:
                    queue.append(opened)
    script_budget = (60 if deep else 25) if signed_in else max_scripts
    script_bytes: dict[str, int] = {}

    def read_script(origin: str, target: str) -> Observation | None:
        bucket = scripts.setdefault(origin, [])
        if len(bucket) >= script_budget or script_bytes.get(origin, 0) >= _SCRIPT_BYTES_PER_SITE or fetch.stopped():
            return None
        seen.add(target)
        announce(f"Reading script {target}")
        script = fetch(target, include_body=True, max_bytes=MAX_SCRIPT_BYTES)
        if script.status_code == 200 and script.body:
            bucket.append(script)
            script_bytes[origin] = script_bytes.get(origin, 0) + len(script.body)
            return script
        return None

    for landing in landings:
        if fetch.stopped() or not is_html(landing):
            continue
        origin = _origin(landing.url)
        resources = parse_resources(landing.body or "")
        sources = [item["src"] for item in resources.scripts] + resources.preloads
        read: list[Observation] = []
        for source in sources:
            if len(scripts.get(origin, [])) >= script_budget or fetch.stopped():
                break
            target = _in_scope(urljoin(landing.url, source).split("#", 1)[0], config, allow_static=True)
            if target is None or _origin(target) != origin or target in seen:
                continue
            script = read_script(origin, target)
            if script is not None:
                read.append(script)
        if not signed_in:
            continue
        # A single-page app loads most of its code later, in chunks named inside the bundle.
        # Their API calls are what the signed-in check reads, so follow them while signed in.
        while read and not fetch.stopped():
            current = read.pop(0)
            for chunk in chunk_scripts(current.url, current.body or ""):
                if len(scripts.get(origin, [])) >= script_budget:
                    break
                target = _in_scope(chunk, config, allow_static=True)
                if target is None or _origin(target) != origin or target in seen:
                    continue
                script = read_script(origin, target)
                if script is not None:
                    read.append(script)
    return pages, scripts, notes


def redirect_finding(row: ScanResult) -> Finding:
    """The open-redirect engine's row, in the shape every other check reports."""

    return Finding(
        check=REDIRECT_CHECK_ID,
        title=f"Open redirect through `{row.tested_parameter or 'parameter'}`",
        severity=Severity.MEDIUM.value,
        url=row.original_url,
        evidence=(
            f"GET {row.test_url}\nHTTP {row.http_status} · Location: {row.location_header or '—'}\n"
            f"Resolved destination: {row.redirect_destination or '—'}"
        ),
        explanation=row.explanation,
        remediation=row.remediation,
        cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        confidence=row.confidence or "high",
        domain=row.domain or (urlsplit(row.original_url).hostname or ""),
        affected_urls=[row.original_url],
    )


def run_audit(
    urls: Sequence[str],
    config: ScanConfig | None = None,
    *,
    checks: Sequence[str] | None = None,
    requester=None,
    on_progress: ProgressCallback | None = None,
    on_finding: FindingCallback | None = None,
    cancel: threading.Event | None = None,
    pause: threading.Event | None = None,
    session=None,
) -> AuditReport:
    """Run the selected checks. session is a rift.session.SignedInSession for a signed-in scan."""

    active = config or ScanConfig()
    selected, wants_redirects = resolve_checks(checks)
    deep = active.mode in {"deep", "standard"}
    report = AuditReport(
        mode="deep" if deep else "fast",
        submitted_urls=list(urls),
        started_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        checks_run=[check.id for check in selected] + ([REDIRECT_CHECK_ID] if wants_redirects else []),
    )
    if not urls:
        report.finished_at = report.started_at
        return report
    if len(urls) > active.max_urls:
        raise ScopeError(f"A scan can include up to {active.max_urls} URLs. This request has {len(urls)}.")
    started = time.monotonic()
    owns_client = requester is None
    client = requester or HttpxRequester(active, session=session)
    if session is not None and hasattr(client, "session"):
        client.session = session
    scrub = session.scrub if session is not None else (lambda text: text)
    if cancel is not None and hasattr(client, "cancel"):
        client.cancel = cancel
    if pause is not None and hasattr(client, "pause"):
        client.pause = pause
    fetch = _Fetcher(client, active, cancel)
    lock = threading.Lock()
    step = [0]
    total = [1]

    def announce(detail: str) -> None:
        if on_progress is not None:
            on_progress(step[0], total[0], scrub(detail))

    def emit(found: list[Finding]) -> None:
        if session is not None:
            found = [_scrub_finding(item, scrub) for item in found]
        with lock:
            report.findings.extend(found)
        if on_finding is not None:
            for item in found:
                on_finding(item)

    try:
        seeds: list[str] = []
        for url in urls:
            target = _in_scope(url, active)
            if target is None:
                report.notes.append(CheckNote("scope", url, "Outside the authorised scope. It was not requested."))
            elif target not in seeds:
                seeds.append(target)
        pages: dict[str, list[Observation]] = {}
        scripts: dict[str, list[Observation]] = {}
        if selected and seeds:
            pages, scripts, notes = _collect(seeds, fetch, active, deep, announce, signed_in=session is not None)
            report.notes.extend(notes)
        # A submitted host that never answered still gets the DNS-only checks.
        silent = sorted({_origin(seed) for seed in seeds} - set(pages)) if selected else []
        for origin in silent:
            pages[origin] = []
        report.origins = sorted(pages)
        report.pages = [page.url for group in pages.values() for page in group]
        report.scripts = [item.url for group in scripts.values() for item in group]
        total[0] = max(1, len(pages) * len(selected) + (1 if wants_redirects else 0))
        resolver = getattr(client, "resolve_checked", None)
        shared: dict[str, object] = {}

        def audit_origin(origin: str) -> None:
            context = CheckContext(
                origin=origin,
                config=active,
                pages=pages[origin],
                scripts=scripts.get(origin, []),
                fetcher=fetch,
                deep=deep,
                resolver=resolver,
                shared=shared,
                session=session,
            )
            for check in selected:
                if fetch.stopped():
                    break
                if check.needs_pages and not context.pages:
                    continue
                with lock:
                    step[0] += 1
                announce(f"{check.title} · {origin}")
                try:
                    emit(check.run(context))
                except Exception as exc:  # noqa: BLE001 - one check must not abort the others
                    context.note(check.id, f"The check stopped on an unexpected error ({exc.__class__.__name__}).")
            with lock:
                report.notes.extend(context.notes)

        if len(pages) <= 1:
            for origin in pages:
                audit_origin(origin)
        else:
            with ThreadPoolExecutor(max_workers=min(4, len(pages))) as pool:
                list(pool.map(audit_origin, sorted(pages)))

        if wants_redirects and seeds and not fetch.stopped():
            from rift.engine import scan_urls  # imported late: the engine pulls in the whole redirect catalog

            announce("Open redirect checks")

            def redirect_progress(done: int, count: int, detail: str) -> None:
                if on_progress is not None:
                    on_progress(done, max(count, 1), detail)

            batch = scan_urls(
                seeds,
                active,
                requester=client,
                on_progress=redirect_progress,
                on_finding=lambda row: emit([redirect_finding(row)]),
                cancel=cancel,
                pause=pause,
            )
            report.redirects = batch
            fetch.sent += getattr(batch, "requests_sent", 0)
            already = {(item.url, item.title) for item in report.findings if item.check == REDIRECT_CHECK_ID}
            for row in batch:
                if row.result == Verdict.POTENTIAL.value:
                    converted = redirect_finding(row)
                    if (converted.url, converted.title) not in already:
                        already.add((converted.url, converted.title))
                        report.findings.append(converted)
    finally:
        if owns_client and isinstance(client, HttpxRequester):
            client.close()
    if session is not None:
        report.findings = [_scrub_finding(item, scrub) for item in report.findings]
        for note in report.notes:
            note.url, note.detail = scrub(note.url), scrub(note.detail)
        report.pages = [scrub(url) for url in report.pages]
        report.scripts = [scrub(url) for url in report.scripts]
        report.session = _session_summary(session, shared, report.checks_run, scrub)
    report.findings = _dedupe(report.findings)
    report.findings.sort(key=lambda item: (item.rank, item.domain, item.check, item.title))
    report.requests_sent = fetch.sent
    report.cancelled = fetch.stopped()
    report.duration_seconds = round(time.monotonic() - started, 2)
    report.finished_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return report


def _scrub_finding(item: Finding, scrub: Callable[[str], str]) -> Finding:
    item.title = scrub(item.title)
    item.url = scrub(item.url)
    item.evidence = scrub(item.evidence)
    item.explanation = scrub(item.explanation)
    item.remediation = scrub(item.remediation)
    item.affected_urls = [scrub(url) for url in item.affected_urls]
    return item


def _session_summary(session, shared: dict, checks_run: list[str], scrub: Callable[[str], str]) -> dict:
    """How the signed-in part of the scan went, for the report. Never the credential."""

    from rift.checks.session import SESSION_STATE_KEY

    summary = dict(session.describe())
    state = shared.get(SESSION_STATE_KEY)
    if "signed-in" not in checks_run or not isinstance(state, dict):
        summary.update({"status": "not-checked", "pages_signed_in": 0, "private_pages": 0, "signed_in_text_seen": False})
        return summary
    private = list(state.get("private", []))
    seen_text = bool(state.get("marker_seen"))
    missing = list(state.get("hosts_missing", []))
    if seen_text or private:
        status = "confirmed"
    elif missing:
        # The app's data sits behind an API host the scan did not include.
        status = "api-missing"
    elif int(state.get("refused", 0)) > 0:
        # Signed-in requests were turned away (401, 403, or a redirect to sign in).
        status = "rejected"
    else:
        # Nothing refused the session and nothing proved it: no page Rift read needed it.
        status = "unconfirmed"
    summary.update(
        {
            "status": status,
            "pages_signed_in": int(state.get("pages", 0)),
            "private_pages": len(private),
            "signed_in_text_seen": seen_text,
            "private_examples": [scrub(url) for url in private[:10]],
            "script_addresses": int(state.get("script_addresses", 0)),
            "script_answers": int(state.get("script_answers", 0)),
            "hosts_missing": missing,
            "refused": int(state.get("refused", 0)),
            "skipped_addresses": [
                {"url": scrub(item["url"]), "reason": item["reason"]} for item in list(state.get("skipped", []))[:200]
            ],
        }
    )
    return summary


def _dedupe(findings: list[Finding]) -> list[Finding]:
    kept: dict[tuple[str, str, str, str], Finding] = {}
    for item in findings:
        key = (item.check, item.title, item.domain, item.url if item.check == REDIRECT_CHECK_ID else "")
        if key not in kept:
            kept[key] = item
    return list(kept.values())


def describe_checks() -> list[Check]:
    return all_checks()
