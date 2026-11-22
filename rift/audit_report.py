"""Reports for a full audit: JSON, CSV, a self-contained HTML page, and SARIF for CI."""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Sequence

from rift.audit import AuditReport
from rift.checks import catalog
from rift.config import TOOL_NAME, VENDOR, VERSION
from rift.models import Finding, Severity
from rift.report import AUTHORIZATION_STATEMENT

SEVERITIES = tuple(severity.value for severity in Severity)
_PENALTY = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
# The report is black and white. These colours mark severity only, as a small square beside the label.
_COLOURS = {"critical": "#d92d20", "high": "#e8590c", "medium": "#c08400", "low": "#2563eb", "info": "#8a8a8a"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}

CSV_FIELDS = (
    "severity",
    "check",
    "title",
    "domain",
    "url",
    "affected_urls",
    "evidence",
    "explanation",
    "remediation",
    "cwe",
    "owasp",
    "confidence",
    "reference",
)


def score(findings: Sequence[Finding]) -> tuple[int, str]:
    """A 0-100 score and letter grade. A rough summary for a dashboard, not a guarantee.

    Each distinct finding subtracts a fixed amount by severity. Low-confidence
    findings count half. Any critical finding caps the grade at F and any high
    finding caps it at C, so a long list of small issues cannot hide a serious one.
    """

    total = 100.0
    for item in findings:
        weight = _PENALTY.get(item.severity, 0)
        total -= weight / 2 if item.confidence == "low" else weight
    value = max(0, round(total))
    grade = "A" if value >= 90 else "B" if value >= 75 else "C" if value >= 60 else "D" if value >= 40 else "F"
    severities = {item.severity for item in findings}
    if "critical" in severities:
        grade = "F"
    elif "high" in severities and grade in {"A", "B"}:
        grade = "C"
    return value, grade


def _authorization(authorization: dict[str, object] | None) -> dict[str, object]:
    return authorization or {"acknowledged": False, "statement": AUTHORIZATION_STATEMENT, "acknowledged_at": "", "domains": []}


def to_json(report: AuditReport, *, authorization: dict[str, object] | None = None) -> str:
    value, grade = score(report.findings)
    payload = {
        "tool": TOOL_NAME,
        "vendor": VENDOR,
        "version": VERSION,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "duration_seconds": report.duration_seconds,
        "mode": report.mode,
        "cancelled": report.cancelled,
        "authorization": _authorization(authorization),
        "submitted_urls": report.submitted_urls,
        "origins": report.origins,
        "pages_read": report.pages,
        "scripts_read": report.scripts,
        "checks_run": report.checks_run,
        "requests_sent": report.requests_sent,
        "score": value,
        "grade": grade,
        "summary": report.counts(),
        "findings": [item.as_dict() for item in report.findings],
        "notes": [note.as_dict() for note in report.notes],
        "session": report.session,
    }
    return json.dumps(payload, indent=2) + "\n"


def _csv_safe(value: object) -> str:
    """Stop a spreadsheet from treating server-controlled text as a formula."""

    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + text
    return text


def to_csv(report: AuditReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for item in report.findings:
        row = item.as_dict()
        row["affected_urls"] = "; ".join(item.affected_urls)
        writer.writerow({field: _csv_safe(row.get(field)) for field in CSV_FIELDS})
    return buffer.getvalue()


def to_sarif(report: AuditReport) -> str:
    """SARIF 2.1.0, the format GitHub code scanning and most CI dashboards accept."""

    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    summaries = {row[0]: (row[1], row[2]) for row in catalog()}
    for item in report.findings:
        if item.check not in rules:
            title, summary = summaries.get(item.check, (item.check, ""))
            rules[item.check] = {
                "id": item.check,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": summary or title},
                "helpUri": item.reference or "https://owasp.org/Top10/",
            }
        results.append(
            {
                "ruleId": item.check,
                "level": _SARIF_LEVEL.get(item.severity, "note"),
                "message": {"text": f"{item.title}. {item.explanation} Fix: {item.remediation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.url}}}],
                "properties": {
                    "severity": item.severity,
                    "security-severity": _SARIF_SCORE.get(item.severity, "0.0"),
                    "cwe": item.cwe,
                    "owasp": item.owasp,
                    "confidence": item.confidence,
                    "evidence": item.evidence,
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": TOOL_NAME, "version": VERSION, "organization": VENDOR, "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def to_html(report: AuditReport, *, authorization: dict[str, object] | None = None) -> str:
    """One self-contained page with no scripts and no external files, safe to email or archive."""

    value, grade = score(report.findings)
    counts = report.counts()
    chips = "".join(
        f'<span class="chip"><i style="background:{_COLOURS[name]}"></i>{counts.get(name, 0)} {name}</span>'
        for name in SEVERITIES
    )
    grade_class = "bad" if grade == "F" else "warn" if grade in {"C", "D"} else "good"
    cards: list[str] = []
    for index, item in enumerate(report.findings, start=1):
        affected = ""
        if len(item.affected_urls) > 1:
            listed = "".join(f"<li>{_e(url)}</li>" for url in item.affected_urls[:25])
            more = f"<li>and {len(item.affected_urls) - 25} more</li>" if len(item.affected_urls) > 25 else ""
            affected = f"<h4>Affected pages ({len(item.affected_urls)})</h4><ul>{listed}{more}</ul>"
        tags = " · ".join(_e(part) for part in (item.cwe, item.owasp, f"confidence {item.confidence}") if part)
        reference = f'<p class="ref">Reference: {_e(item.reference)}</p>' if item.reference else ""
        cards.append(
            f"""<section class="finding">
<h3><span class="sev"><i style="background:{_COLOURS.get(item.severity, '#8a8a8a')}"></i>{_e(item.severity)}</span> {index}. {_e(item.title)}</h3>
<p class="where">{_e(item.url)}</p>
<p class="tags">{_e(item.check)} · {tags}</p>
<h4>What this means</h4><p>{_e(item.explanation)}</p>
<h4>Evidence</h4><pre>{_e(item.evidence)}</pre>
<h4>How to fix it</h4><p>{_e(item.remediation)}</p>
{affected}{reference}
</section>"""
        )
    notes = "".join(f"<li><b>{_e(note.check)}</b> · {_e(note.url)} · {_e(note.detail)}</li>" for note in report.notes)
    signed = session_sentence(report.session)
    skipped_list = (report.session or {}).get("skipped_addresses") or []
    skipped_html = (
        "<p><b>Not opened while signed in.</b> Found in the app's JavaScript but skipped, because opening them could change data, send something or start a sign-in step:</p><ul>"
        + "".join(f"<li><code>{_e(item.get('url'))}</code> &mdash; {_e(item.get('reason'))}</li>" for item in skipped_list)
        + "</ul>"
        if skipped_list
        else ""
    )
    confirmed = _authorization(authorization)
    scope = ", ".join(_e(domain) for domain in confirmed.get("domains") or []) or "not recorded"
    body = "\n".join(cards) or "<p>No findings. That means these checks found nothing; it is not proof the site is secure.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(TOOL_NAME)} security report</title>
<style>
:root{{color-scheme:light dark;--bg:#fff;--panel:#fff;--inset:#f5f5f5;--line:#e5e5e5;--strong:#c4c4c4;--text:#0a0a0a;--muted:#666;--on:#fff}}
@media (prefers-color-scheme: dark){{:root{{--bg:#000;--panel:#0a0a0a;--inset:#141414;--line:#262626;--strong:#3d3d3d;--text:#fafafa;--muted:#a1a1a1;--on:#000}}}}
body{{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--text);background:var(--bg);margin:0;padding:24px}}
main{{max-width:920px;margin:0 auto}}
h1{{margin:0 0 4px;font-size:26px}} h3{{margin:0 0 6px;font-size:17px}} h4{{margin:14px 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}}
.meta{{color:var(--muted);margin:0 0 16px}}
.grade{{width:64px;height:64px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:34px;font-weight:700;margin-right:8px;background:var(--text);color:var(--on)}}
.grade.warn{{background:#c08400;color:#0a0a0a}} .grade.bad{{background:#d92d20;color:#fff}}
.top{{display:flex;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin-bottom:18px;flex-wrap:wrap;gap:8px}}
.chips{{margin-top:6px;display:flex;flex-wrap:wrap;gap:6px}}
.chip,.sev{{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--strong);border-radius:4px;padding:2px 8px;font-size:12px;white-space:nowrap}}
.sev{{font-weight:700;text-transform:uppercase;letter-spacing:.04em;font-size:11px;margin-right:6px;vertical-align:middle}}
.chip i,.sev i{{width:8px;height:8px;border-radius:2px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;margin-bottom:12px}}
.where,.tags,.ref{{color:var(--muted);font-size:13px;margin:0;word-break:break-all}}
pre{{background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-word;font-size:13px;margin:0}}
ul{{margin:4px 0;padding-left:20px;word-break:break-all}} footer{{color:var(--muted);font-size:13px;margin-top:20px}}
@media print{{:root{{--bg:#fff;--panel:#fff;--inset:#f5f5f5;--line:#e5e5e5;--strong:#c4c4c4;--text:#0a0a0a;--muted:#666;--on:#fff}}}}
</style></head><body><main>
<h1>{_e(TOOL_NAME)} security report</h1>
<p class="meta">{_e(report.finished_at)} · {_e(report.mode)} scan · {len(report.origins)} site(s) · {len(report.pages)} pages and {len(report.scripts)} scripts read · {report.requests_sent} requests · {report.duration_seconds}s</p>
<div class="top"><span class="grade {grade_class}">{grade}</span><div><div><b>Score {value}/100</b> · {counts['total']} findings</div><div class="chips">{chips}</div></div></div>
{body}
<footer>
<p><b>Scope.</b> Authorised domains: {scope}. Sites scanned: {", ".join(_e(origin) for origin in report.origins) or "none"}.</p>
<p><b>Checks run.</b> {", ".join(_e(name) for name in report.checks_run)}.</p>
<p><b>Login.</b> {_e(signed)}</p>{skipped_html}
{f"<p><b>Notes.</b></p><ul>{notes}</ul>" if notes else ""}
<p>This report lists what the selected checks found with read-only requests. A clean result is not proof that a site is secure. The score is a summary aid.</p>
<p>{_e(TOOL_NAME)} {_e(VERSION)} · {_e(VENDOR)}</p>
</footer></main></body></html>
"""


def session_sentence(session: dict | None) -> str:
    """One plain sentence about the login used, for reports. Never the credential."""

    if not session:
        return "Not signed in. Only what an anonymous visitor can reach was checked."
    names = ", ".join(session.get("cookie_names") or []) or session.get("header") or "a session"
    status = {
        "confirmed": "The session was confirmed to work",
        "rejected": "The signed-in text was not found on any page, so the session probably did not work",
        "unconfirmed": "No page needed a login, so Rift could not confirm the session worked",
        "api-missing": "The app loads its data from "
        + ", ".join(session.get("hosts_missing") or ["another host"])
        + ", which was not part of this scan, so the signed-in results are incomplete",
        "not-checked": "The signed-in check was not selected",
    }.get(str(session.get("status")), "")
    counts = f"{session.get('private_pages', 0)} private page(s) found." if session.get("status") == "confirmed" else ""
    skipped = session.get("skipped_addresses") or []
    if skipped:
        counts = (counts + " " if counts else "") + f"{len(skipped)} address(es) were not opened while signed in (listed in the JSON report)."
    if session.get("script_addresses"):
        counts = (counts + " " if counts else "") + (
            f"{session.get('script_answers', 0)} of {session['script_addresses']} API address(es) found in the app's JavaScript answered."
        )
    ended = session.get("session_end") or {}
    outcome = {
        "passed": "Signing out ended the session.",
        "failed": "Signing out did not end the session.",
        "inconclusive": "The sign-out check was inconclusive.",
    }.get(str(ended.get("result")), "")
    return " ".join(part for part in (f"Signed in with a test account ({session.get('method')}: {names}).", status + "." if status else "", counts, outcome) if part)


def report_from_dict(data: dict) -> AuditReport:
    """Rebuild a report from the dictionary to_json() produced, for a saved scan."""

    from rift.models import CheckNote

    finding_fields = set(Finding.__dataclass_fields__)
    findings = [
        Finding(**{key: value for key, value in item.items() if key in finding_fields})
        for item in data.get("findings", [])
        if isinstance(item, dict)
    ]
    notes = [
        CheckNote(check=str(item.get("check", "")), url=str(item.get("url", "")), detail=str(item.get("detail", "")))
        for item in data.get("notes", [])
        if isinstance(item, dict)
    ]
    return AuditReport(
        findings=findings,
        notes=notes,
        origins=list(data.get("origins", [])),
        pages=list(data.get("pages_read", [])),
        scripts=list(data.get("scripts_read", [])),
        checks_run=list(data.get("checks_run", [])),
        submitted_urls=list(data.get("submitted_urls", [])),
        requests_sent=int(data.get("requests_sent", 0)),
        mode=str(data.get("mode", "fast")),
        started_at=str(data.get("started_at", "")),
        finished_at=str(data.get("finished_at", "")),
        duration_seconds=float(data.get("duration_seconds", 0.0)),
        cancelled=bool(data.get("cancelled", False)),
        session=data.get("session") if isinstance(data.get("session"), dict) else None,
    )
