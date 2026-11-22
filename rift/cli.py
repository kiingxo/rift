"""Command-line entry point. It runs the same audit as the dashboard.

    python -m rift serve                       # the web console
    python -m rift https://app.example.com --i-am-authorised
    python -m rift urls.txt --mode deep --html report.html --sarif rift.sarif --fail-on high
    python -m rift --list-checks
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from typing import Sequence, TextIO
from urllib.parse import urlsplit

from rift.audit import run_audit
from rift.audit_report import SEVERITIES, score, session_sentence, to_csv, to_html, to_json, to_sarif
from rift.checks import catalog
from rift.config import ScanConfig, TOOL_NAME, VENDOR, VERSION, allow_internal_from_env
from rift.models import SEVERITY_ORDER
from rift.report import AUTHORIZATION_STATEMENT
from rift.safety import ScopeError, load_allowlist, validate_allowlist_entry
from rift.session import SessionError, SignedInSession
from rift.targets import collect_targets, prepare_submission


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rift",
        description=f"{TOOL_NAME} {VERSION} by {VENDOR}. Read-only security checks for websites and APIs you are authorised to test.",
    )
    parser.add_argument("targets", nargs="*", help="URLs, or a .txt file with one URL per line")
    parser.add_argument("--mode", choices=("fast", "deep"), default="fast", help="deep reads more pages and probes more paths")
    parser.add_argument("--checks", help="comma-separated check ids to run (default: all)")
    parser.add_argument("--skip", help="comma-separated check ids to leave out")
    parser.add_argument("--list-checks", action="store_true", help="print the available checks and exit")
    parser.add_argument("--allow", action="append", default=[], help="additional authorised domain")
    parser.add_argument(
        "--i-am-authorised",
        "--i-am-authorized",
        dest="authorised",
        action="store_true",
        help="confirm you own or have explicit permission to test every submitted domain",
    )
    signed = parser.add_argument_group(
        "signed-in testing",
        "Sign in to a TEST account in your browser and copy its session. Prefer the environment variables, "
        "so the value does not land in your shell history. It is sent only to the submitted hosts and never written to a report.",
    )
    signed.add_argument("--cookie", help="the test account's Cookie header value (or set RIFT_TEST_COOKIE)")
    signed.add_argument("--auth-header", help='a header such as "Authorization: Bearer eyJ..." (or set RIFT_TEST_HEADER)')
    signed.add_argument(
        "--signed-in-text",
        help="text only a signed-in user sees, such as the test account's email; confirms the login and catches private data shown to anyone",
    )
    parser.add_argument("--json", help="write the JSON report to this path")
    parser.add_argument("--csv", help="write the CSV report to this path")
    parser.add_argument("--html", help="write the HTML report to this path")
    parser.add_argument("--sarif", help="write a SARIF 2.1.0 report to this path (for CI code-scanning)")
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit with status 1 when a finding of this severity or worse exists (for CI pipelines)",
    )
    parser.add_argument("--quiet", action="store_true", help="do not print progress")
    return parser


def _split(value: str | None) -> list[str]:
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


def serve_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="rift serve", description=f"Start the {TOOL_NAME} web console on this machine.")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default: this machine only)")
    parser.add_argument("--port", type=int, default=8600)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = parser.parse_args(list(argv))
    from rift.server import serve

    serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None, requester=None) -> int:
    output = stdout or sys.stdout
    arguments = list(argv) if argv is not None else sys.argv[1:]
    if arguments[:1] == ["serve"]:
        return serve_main(arguments[1:])
    parser = build_parser()
    args = parser.parse_args(arguments)
    rows = catalog()
    if args.list_checks:
        for check_id, title, summary, kind in rows:
            print(f"{check_id:20} {kind:8} {title}. {summary}", file=output)
        return 0
    urls = collect_targets(args.targets)
    if not urls:
        parser.error("Provide at least one URL or a .txt file")
    known = [row[0] for row in rows]
    selected = _split(args.checks) or list(known)
    skipped = set(_split(args.skip))
    unknown = sorted((set(selected) | skipped) - set(known))
    if unknown:
        print(f"Unknown check: {', '.join(unknown)}. Run with --list-checks to see the names.", file=sys.stderr)
        return 2
    selected = [name for name in selected if name not in skipped]
    allow_internal = allow_internal_from_env()
    try:
        submission = prepare_submission(urls, allow_internal=allow_internal)
        saved = list(load_allowlist())
        for domain in args.allow:
            saved.append(validate_allowlist_entry(domain, allow_internal=allow_internal))
    except ScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    for excluded, reason in submission.excluded:
        print(f"Not scanned: {excluded} ({reason})", file=sys.stderr)
    if not submission.urls:
        print("None of these URLs can be scanned.", file=sys.stderr)
        return 2
    # Without the flag, only domains already saved as authorised may be scanned.
    if args.authorised:
        allowlist = tuple(dict.fromkeys([*submission.domains, *saved]))
    else:
        allowlist = tuple(dict.fromkeys(saved))
        if not allowlist:
            print(
                f"{AUTHORIZATION_STATEMENT}\nRe-run with --i-am-authorised to confirm this for: {', '.join(submission.domains)}",
                file=sys.stderr,
            )
            return 2
    config = replace(ScanConfig(), allowlist=allowlist, allow_internal=allow_internal, mode=args.mode)
    try:
        session = SignedInSession.build(
            cookie=args.cookie or os.environ.get("RIFT_TEST_COOKIE", ""),
            header=args.auth_header or os.environ.get("RIFT_TEST_HEADER", ""),
            marker=args.signed_in_text or "",
            hosts=[urlsplit(url).hostname or "" for url in submission.urls],
        )
    except SessionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if session is not None and not args.quiet:
        print(f"Signed in with a test account ({session.method}) for {', '.join(session.hosts)}", file=sys.stderr)

    def progress(done: int, total: int, detail: str) -> None:
        if not args.quiet:
            print(f"  {detail}", file=sys.stderr)

    try:
        report = run_audit(
            list(submission.urls), config, checks=selected, requester=requester, on_progress=progress, session=session
        )
    except ScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    counts = report.counts()
    value, grade = score(report.findings)
    print(
        f"{TOOL_NAME} {VERSION} · {len(report.origins)} site(s) · {report.requests_sent} requests · {report.duration_seconds}s",
        file=output,
    )
    print(
        f"Grade {grade} ({value}/100) · " + " · ".join(f"{counts.get(name, 0)} {name}" for name in SEVERITIES),
        file=output,
    )
    for item in report.findings:
        print(f"[{item.severity.upper():8}] {item.title}", file=output)
        print(f"           {item.url}", file=output)
        if item.severity in {"critical", "high", "medium"}:
            print(f"           Fix: {item.remediation}", file=output)
    for note in report.notes:
        print(f"note: {note.check} · {note.url} · {note.detail}", file=output)
    if session is not None:
        print(f"login: {session_sentence(report.session)}", file=output)
        for item in (report.session or {}).get("skipped_addresses") or []:
            print(f"  not opened while signed in: {item['url']} ({item['reason']})", file=output)
    authorization = {
        "acknowledged": bool(args.authorised),
        "statement": AUTHORIZATION_STATEMENT,
        "acknowledged_at": report.started_at if args.authorised else "",
        "domains": list(allowlist),
    }
    writers = (
        (args.json, lambda: to_json(report, authorization=authorization)),
        (args.csv, lambda: to_csv(report)),
        (args.html, lambda: to_html(report, authorization=authorization)),
        (args.sarif, lambda: to_sarif(report)),
    )
    for path, render in writers:
        if path:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(render())
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(item.rank <= threshold for item in report.findings):
            return 1
    return 0
