"""Local web console: a small JSON API over the audit engine, plus the static frontend.

The server is meant to run on the machine of the person doing the scan. It binds
to 127.0.0.1 by default and defends itself against other websites open in the
same browser:

- every API call needs a token that is generated at start-up and handed only to
  the page this server serves, so another site cannot start a scan (CSRF);
- requests whose Host header is not this server are refused, so a hostile
  domain that re-points its DNS at 127.0.0.1 cannot reach the API (DNS rebinding);
- the page ships a strict Content-Security-Policy with no inline script, and the
  frontend never inserts scanned content as HTML.

It has no user accounts. Do not expose it on a network without putting real
authentication in front of it.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from rift.audit import AuditReport, run_audit
from rift.audit_report import report_from_dict, score, to_csv, to_html, to_json, to_sarif
from rift.checks import catalog, resolve_checks
from rift.config import ScanConfig, TOOL_NAME, VERSION, allow_internal_from_env, env_setting, tool_root
from rift.models import Finding, Severity
from rift.report import AUTHORIZATION_STATEMENT
from rift.safety import ScopeError
from rift.session import PLACEHOLDER, SessionError, SignedInSession
from rift.targets import parse_url_lines, prepare_submission

WEB_ROOT = Path(__file__).resolve().parent / "web"
_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
_MAX_RUNNING = 2
# How long a finished scan keeps the test account's session in memory for the sign-out check.
_SESSION_HOLD_SECONDS = 3600
_EXPORTS = {
    "html": ("text/html; charset=utf-8", "html"),
    "json": ("application/json", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
    "sarif": ("application/json", "sarif"),
}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cache-Control": "no-store",
}


def data_directory() -> Path:
    configured = env_setting("DATA_DIR")
    return Path(configured).expanduser() if configured else tool_root() / "scans"


class ScanRequest(BaseModel):
    targets: str = Field(..., max_length=400_000)
    mode: str = Field("fast", pattern="^(fast|deep)$")
    checks: Optional[List[str]] = None
    authorised: bool = False
    max_requests_per_domain: int = Field(500, ge=20, le=5000)
    min_interval_seconds: float = Field(0.25, ge=0.05, le=5)
    timeout_seconds: float = Field(8, ge=2, le=30)
    # A test account's session. Kept in memory only; never saved or returned.
    session_cookie: str = Field("", max_length=8192)
    session_header: str = Field("", max_length=8192)
    signed_in_text: str = Field("", max_length=200)


class PreviewRequest(BaseModel):
    targets: str = Field(..., max_length=400_000)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _counts(findings: Iterable[Finding]) -> dict[str, int]:
    totals = {severity.value: 0 for severity in Severity}
    count = 0
    for item in findings:
        totals[item.severity] = totals.get(item.severity, 0) + 1
        count += 1
    totals["total"] = count
    return totals


class Job:
    """One scan, running or finished, with what the page needs to draw it."""

    def __init__(self, scan_id: str, targets: list[str], domains: list[str], mode: str, checks: list[str]) -> None:
        self.id = scan_id
        self.targets = targets
        self.domains = domains
        self.mode = mode
        self.checks = checks
        self.created_at = _now()
        self.state = "running"
        self.detail = "Starting"
        self.done = 0
        self.total = 1
        self.logs: deque = deque(maxlen=200)
        self.findings: list[Finding] = []
        self.report: AuditReport | None = None
        self.error = ""
        self.cancel = threading.Event()
        self.pause = threading.Event()
        self.lock = threading.Lock()
        self.started = time.monotonic()
        # In memory only, for the sign-out check after the scan. Never written to disk.
        self.session: SignedInSession | None = None
        self.session_until = 0.0
        self.config: ScanConfig | None = None
        self.authorization = {
            "acknowledged": True,
            "statement": AUTHORIZATION_STATEMENT,
            "acknowledged_at": self.created_at,
            "domains": list(domains),
        }

    def log(self, text: str) -> None:
        self.logs.append({"at": datetime.now().strftime("%H:%M:%S"), "text": text})

    def session_info(self) -> dict | None:
        if self.report is not None and self.report.session:
            return self.report.session
        if self.session is not None:
            return self.session.describe()
        return None

    def session_probe(self) -> str:
        """A private page from the scan to test the old session against, or ''."""

        info = self.session_info() or {}
        for url in info.get("private_examples") or []:
            if PLACEHOLDER not in url:
                return str(url)
        return ""

    def session_check_open(self) -> bool:
        return (
            self.session is not None
            and time.monotonic() < self.session_until
            and self.state in {"finished", "cancelled"}
            and bool(self.session_probe())
        )

    def summary(self) -> dict[str, object]:
        with self.lock:
            findings = list(self.report.findings if self.report is not None else self.findings)
            value, grade = score(findings)
            return {
                "id": self.id,
                "state": "paused" if self.state == "running" and self.pause.is_set() else self.state,
                "created_at": self.created_at,
                "targets": self.targets,
                "domains": self.domains,
                "mode": self.mode,
                "checks": self.checks,
                "summary": _counts(findings),
                "score": value,
                "grade": grade,
                "requests_sent": self.report.requests_sent if self.report else 0,
                "signed_in": self.session_info() is not None,
                "duration_seconds": self.report.duration_seconds if self.report else round(time.monotonic() - self.started, 1),
            }

    def detail_view(self) -> dict[str, object]:
        view = self.summary()
        with self.lock:
            findings = list(self.report.findings if self.report is not None else self.findings)
            findings.sort(key=lambda item: (item.rank, item.domain, item.check, item.title))
            view.update(
                {
                    "progress": {"done": self.done, "total": max(self.total, 1), "detail": self.detail},
                    "logs": list(self.logs)[-60:],
                    "findings": [item.as_dict() for item in findings],
                    "notes": [note.as_dict() for note in self.report.notes] if self.report else [],
                    "pages": list(self.report.pages) if self.report else [],
                    "scripts": list(self.report.scripts) if self.report else [],
                    "origins": list(self.report.origins) if self.report else [],
                    "error": self.error,
                    "authorization": self.authorization,
                    "session": self.session_info(),
                    "session_check_open": self.session_check_open(),
                }
            )
        return view


class ScanStore:
    """Finished scans as one JSON file each. Evidence in them is already redacted."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path(self, scan_id: str) -> Path:
        if not _ID.fullmatch(scan_id):
            raise KeyError(scan_id)
        return self.directory / f"{scan_id}.json"

    def save(self, job: Job) -> None:
        if job.report is None:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        record = {
            "id": job.id,
            "created_at": job.created_at,
            "state": job.state,
            "targets": job.targets,
            "domains": job.domains,
            "mode": job.mode,
            "checks": job.checks,
            "authorization": job.authorization,
            "report": json.loads(to_json(job.report, authorization=job.authorization)),
        }
        path = self._path(job.id)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record), encoding="utf-8")
        temporary.replace(path)

    def load(self, scan_id: str) -> Job | None:
        try:
            path = self._path(scan_id)
            record = json.loads(path.read_text(encoding="utf-8"))
        except (KeyError, OSError, ValueError):
            return None
        job = Job(
            scan_id,
            list(record.get("targets", [])),
            list(record.get("domains", [])),
            str(record.get("mode", "fast")),
            list(record.get("checks", [])),
        )
        job.created_at = str(record.get("created_at", ""))
        job.state = str(record.get("state", "finished"))
        job.authorization = record.get("authorization") or job.authorization
        job.report = report_from_dict(record.get("report") or {})
        job.done = job.total = 1
        job.detail = "Finished"
        return job

    def ids(self) -> list[str]:
        if not self.directory.is_dir():
            return []
        return sorted((path.stem for path in self.directory.glob("*.json") if _ID.fullmatch(path.stem)), reverse=True)

    def delete(self, scan_id: str) -> bool:
        try:
            self._path(scan_id).unlink()
        except (KeyError, OSError):
            return False
        return True


class ScanManager:
    def __init__(self, store: ScanStore) -> None:
        self.store = store
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def get(self, scan_id: str) -> Job | None:
        if not _ID.fullmatch(scan_id):
            return None
        with self.lock:
            job = self.jobs.get(scan_id)
        if job is None:
            job = self.store.load(scan_id)
            if job is not None:
                with self.lock:
                    self.jobs.setdefault(scan_id, job)
        return job

    def list(self) -> list[dict[str, object]]:
        with self.lock:
            known = dict(self.jobs)
        for scan_id in self.store.ids():
            if scan_id not in known:
                loaded = self.get(scan_id)
                if loaded is not None:
                    known[scan_id] = loaded
        return [known[key].summary() for key in sorted(known, reverse=True)]

    def running(self) -> int:
        with self.lock:
            return sum(1 for job in self.jobs.values() if job.state == "running")

    def start(
        self,
        urls: list[str],
        domains: list[str],
        config: ScanConfig,
        checks: list[str],
        requester=None,
        session: SignedInSession | None = None,
    ) -> Job:
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        job = Job(scan_id, urls, domains, config.mode, checks)
        job.session = session
        job.config = config
        job.log(f"Starting {config.mode} scan of {len(urls)} URL(s) with {len(checks)} checks")
        if session is not None:
            job.log(f"Signed in with a test account ({session.method}) for {', '.join(session.hosts)}")
        with self.lock:
            self.jobs[scan_id] = job

        def on_progress(done: int, total: int, detail: str) -> None:
            with job.lock:
                job.done, job.total, job.detail = done, max(total, 1), detail
                job.log(detail)

        def on_finding(finding: Finding) -> None:
            with job.lock:
                job.findings.append(finding)
                job.log(f"{finding.severity.upper()} · {finding.title}")

        def work() -> None:
            try:
                report = run_audit(
                    urls,
                    config,
                    checks=checks,
                    requester=requester,
                    on_progress=on_progress,
                    on_finding=on_finding,
                    cancel=job.cancel,
                    pause=job.pause,
                    session=session,
                )
                with job.lock:
                    job.session_until = time.monotonic() + _SESSION_HOLD_SECONDS
                    job.report = report
                    job.state = "cancelled" if report.cancelled else "finished"
                    job.detail = "Cancelled" if report.cancelled else "Finished"
                    job.done = job.total
                self.store.save(job)
            except Exception as exc:  # noqa: BLE001 - shown to the user instead of a silent dead scan
                with job.lock:
                    job.state = "failed"
                    job.session = None
                    job.error = f"{exc.__class__.__name__}: {exc}"
                    if session is not None:
                        job.error = session.scrub(job.error)
                    job.detail = "Failed"

        threading.Thread(target=work, name=f"rift-scan-{scan_id}", daemon=True).start()
        return job


def create_app(
    *,
    data_dir: Path | None = None,
    token: str | None = None,
    allowed_hosts: Iterable[str] = ("127.0.0.1", "localhost", "[::1]"),
    requester_factory=None,
) -> FastAPI:
    app = FastAPI(title=TOOL_NAME, version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    api_token = token or secrets.token_urlsafe(32)
    hosts = {host.lower() for host in allowed_hosts}
    manager = ScanManager(ScanStore(data_dir or data_directory()))
    app.state.token = api_token
    app.state.manager = manager

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "").lower()
        name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        if name not in hosts:
            return JSONResponse({"detail": "This address is not served here."}, status_code=421, headers=_SECURITY_HEADERS)
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("x-rift-token", "")
            if not hmac.compare_digest(supplied.encode(), api_token.encode()):
                return JSONResponse({"detail": "Missing or wrong session token. Reload the page."}, status_code=401, headers=_SECURITY_HEADERS)
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    def _file(name: str, media_type: str) -> Response:
        return Response((WEB_ROOT / name).read_bytes(), media_type=media_type)

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        page = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(page.replace("__RIFT_TOKEN__", api_token))

    @app.get("/app.css")
    def stylesheet() -> Response:
        return _file("app.css", "text/css; charset=utf-8")

    @app.get("/app.js")
    def script() -> Response:
        return _file("app.js", "text/javascript; charset=utf-8")

    @app.get("/theme.js")
    def theme_script() -> Response:
        return _file("theme.js", "text/javascript; charset=utf-8")

    @app.get("/favicon.svg")
    def favicon() -> Response:
        return _file("favicon.svg", "image/svg+xml")

    @app.get("/api/meta")
    def meta() -> dict[str, object]:
        defaults = ScanConfig()
        return {
            "name": TOOL_NAME,
            "version": VERSION,
            "lab_mode": allow_internal_from_env(),
            "statement": AUTHORIZATION_STATEMENT,
            "checks": [{"id": row[0], "title": row[1], "summary": row[2], "kind": row[3]} for row in catalog()],
            "defaults": {
                "max_requests_per_domain": defaults.max_requests_per_domain,
                "min_interval_seconds": defaults.min_interval_seconds,
                "timeout_seconds": defaults.timeout_seconds,
            },
        }

    def _submission(text: str):
        urls = parse_url_lines(text)
        if len(urls) > ScanConfig().max_urls:
            raise HTTPException(400, f"A scan can include up to {ScanConfig().max_urls} URLs.")
        return prepare_submission(urls, allow_internal=allow_internal_from_env())

    @app.post("/api/preview")
    def preview(body: PreviewRequest) -> dict[str, object]:
        submission = _submission(body.targets)
        return {
            "urls": list(submission.urls),
            "domains": list(submission.domains),
            "excluded": [{"url": url, "reason": reason} for url, reason in submission.excluded],
        }

    @app.get("/api/scans")
    def list_scans() -> dict[str, object]:
        return {"scans": manager.list()}

    @app.post("/api/scans", status_code=201)
    def start_scan(body: ScanRequest) -> dict[str, object]:
        if not body.authorised:
            raise HTTPException(400, "Confirm that you are authorised to test these targets.")
        submission = _submission(body.targets)
        if not submission.urls:
            raise HTTPException(400, "None of these URLs can be scanned.")
        known = [row[0] for row in catalog()]
        selected = [item for item in (body.checks if body.checks is not None else known)]
        try:
            resolve_checks(selected)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not selected:
            raise HTTPException(400, "Select at least one check.")
        if manager.running() >= _MAX_RUNNING:
            raise HTTPException(409, "Two scans are already running. Wait for one to finish or cancel it.")
        config = replace(
            ScanConfig(),
            allowlist=tuple(submission.domains),
            allow_internal=allow_internal_from_env(),
            mode=body.mode,
            max_requests_per_domain=body.max_requests_per_domain,
            min_interval_seconds=body.min_interval_seconds,
            timeout_seconds=body.timeout_seconds,
        )
        ordered = [name for name in known if name in set(selected)]
        try:
            session = SignedInSession.build(
                cookie=body.session_cookie,
                header=body.session_header,
                marker=body.signed_in_text,
                hosts=[urlsplit(url).hostname or "" for url in submission.urls],
            )
        except SessionError as exc:
            raise HTTPException(400, str(exc)) from exc
        requester = requester_factory(config) if requester_factory is not None else None
        try:
            job = manager.start(
                list(submission.urls), list(submission.domains), config, ordered, requester=requester, session=session
            )
        except ScopeError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"id": job.id}

    def _job(scan_id: str) -> Job:
        job = manager.get(scan_id)
        if job is None:
            raise HTTPException(404, "No such scan.")
        return job

    @app.get("/api/scans/{scan_id}")
    def scan_detail(scan_id: str) -> dict[str, object]:
        return _job(scan_id).detail_view()

    @app.post("/api/scans/{scan_id}/session-end")
    def session_end(scan_id: str) -> dict[str, object]:
        """After the person signed out of the test account: is the old session still accepted?"""

        from rift.checks.session import session_end_finding
        from rift.http_client import HttpxRequester

        job = _job(scan_id)
        if not job.session_check_open() or job.session is None or job.config is None or job.report is None:
            raise HTTPException(
                409,
                "This check is only available for an hour after a signed-in scan that found a private page, "
                "while the console keeps the session in memory. Run the scan again to check.",
            )
        session, probe = job.session, job.session_probe()
        requester = requester_factory(job.config) if requester_factory is not None else HttpxRequester(job.config, session=session)
        if hasattr(requester, "session"):
            requester.session = session
        try:
            finding, outcome = session_end_finding(
                session,
                probe,
                lambda url, signed: requester.request(url, include_body=True, signed_in=signed),
                urlsplit(probe).hostname or "",
            )
        finally:
            close = getattr(requester, "close", None)
            if callable(close):
                close()
        result = "failed" if finding is not None else "passed" if outcome.startswith("Passed") else "inconclusive"
        with job.lock:
            if finding is not None:
                finding.url = session.scrub(finding.url)
                finding.evidence = session.scrub(finding.evidence)
                finding.affected_urls = [session.scrub(url) for url in finding.affected_urls]
                job.report.findings.append(finding)
                job.report.findings.sort(key=lambda item: (item.rank, item.domain, item.check, item.title))
            job.report.session = dict(job.report.session or session.describe())
            job.report.session["session_end"] = {"result": result, "detail": session.scrub(outcome), "checked_at": _now()}
            job.log(f"Sign-out check: {session.scrub(outcome)}")
            if result in {"passed", "failed"}:
                job.session = None
        manager.store.save(job)
        return {"result": result, "detail": session.scrub(outcome), "scan": job.detail_view()}

    @app.post("/api/scans/{scan_id}/{action}")
    def control(scan_id: str, action: str) -> dict[str, object]:
        job = _job(scan_id)
        if action == "cancel":
            job.cancel.set()
            job.pause.clear()
            job.log("Cancel requested. Finished checks are kept.")
        elif action == "pause":
            job.pause.set()
            job.log("Paused")
        elif action == "resume":
            job.pause.clear()
            job.log("Resumed")
        else:
            raise HTTPException(404, "Unknown action.")
        return job.summary()

    @app.delete("/api/scans/{scan_id}")
    def delete_scan(scan_id: str) -> dict[str, object]:
        job = _job(scan_id)
        if job.state == "running":
            raise HTTPException(409, "Cancel the scan before deleting it.")
        with manager.lock:
            manager.jobs.pop(scan_id, None)
        manager.store.delete(scan_id)
        return {"deleted": scan_id}

    @app.get("/api/scans/{scan_id}/export/{kind}")
    def export(scan_id: str, kind: str) -> Response:
        job = _job(scan_id)
        if kind not in _EXPORTS:
            raise HTTPException(404, "Unknown report format.")
        if job.report is None:
            raise HTTPException(409, "The scan has not finished.")
        media_type, extension = _EXPORTS[kind]
        if kind == "html":
            content = to_html(job.report, authorization=job.authorization)
        elif kind == "json":
            content = to_json(job.report, authorization=job.authorization)
        elif kind == "csv":
            content = to_csv(job.report)
        else:
            content = to_sarif(job.report)
        return Response(
            content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="rift-{scan_id}.{extension}"'},
        )

    return app


def serve(host: str = "127.0.0.1", port: int = 8600, open_browser: bool = True) -> None:
    import uvicorn

    import os

    hosts = {"127.0.0.1", "localhost", "[::1]"}
    in_container = os.environ.get("RIFT_CONTAINER") == "1"
    if host not in {"127.0.0.1", "localhost", "::1"}:
        hosts.add(host.lower())
        if in_container:
            print(
                "Running in a container. Publish the port to this computer only "
                "(docker-compose.yml uses 127.0.0.1:8600:8600): the console has no user accounts.",
                flush=True,
            )
        else:
            print(
                f"Warning: listening on {host}. The console has no user accounts; anyone who can reach this "
                "address and load the page can run scans. Put authentication in front of it.",
                flush=True,
            )
    app = create_app(allowed_hosts=hosts)
    shown = "localhost" if in_container or host in {"127.0.0.1", "::1", "0.0.0.0", "::"} else host
    address = f"http://{'127.0.0.1' if shown == 'localhost' and not in_container else shown}:{port}"
    print(f"{TOOL_NAME} {VERSION} console: {address}", flush=True)
    if open_browser:
        import webbrowser

        threading.Timer(1.0, lambda: webbrowser.open(address)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
