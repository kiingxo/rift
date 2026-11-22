"""End-to-end: the full audit, the CLI and every report format, over real local sockets."""

from __future__ import annotations

import io
import json
import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest

from rift.audit import run_audit
from rift.audit_report import score, to_csv, to_html, to_json, to_sarif
from rift.cli import main
from rift.config import ScanConfig
from rift.http_client import HttpxRequester
from rift.models import Finding
from tests.weak_site import EXAMPLE_AWS_KEY, HardenedSite, WeakSite


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def weak():
    server, thread = _serve(WeakSite)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def hardened():
    server, thread = _serve(HardenedSite)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def lab(mode="fast"):
    return ScanConfig(
        allowlist=("127.0.0.1",),
        allow_internal=True,
        min_interval_seconds=0,
        max_workers=2,
        timeout_seconds=3,
        connect_timeout_seconds=2,
        mode=mode,
    )


EXPECTED_ON_WEAK_SITE = {
    "security-headers": "Content-Security-Policy header is missing",
    "cookies": "Session cookie `sessionid` is readable by JavaScript",
    "page-content": "Password form submits with GET",
    "info-disclosure": "Python traceback shown in a response",
    "secrets": "AWS access key ID exposed in a public response",
    "jwt": "Site issues an unsigned JSON Web Token",
    "transport": "Site is served over plain HTTP",
    "cors": "CORS trusts any website and shares the visitor's session",
    "server-config": "Server advertises the TRACE method",
    "exposed-files": "Environment file is publicly accessible (/.env)",
    "api-surface": "Endpoint documented as authenticated answers without credentials",
}


def test_every_check_finds_its_planted_issue_on_the_weak_site(weak):
    report = run_audit([weak + "/", weak + "/go?next=/"], lab())
    found = {(item.check, item.title) for item in report.findings}
    for check, title in EXPECTED_ON_WEAK_SITE.items():
        assert (check, title) in found, f"{check} did not report: {title}"
    assert any(item.check == "open-redirect" for item in report.findings)
    assert report.findings == sorted(report.findings, key=lambda item: item.rank)
    assert report.requests_sent > 0 and report.origins == [weak]


def test_no_report_format_ever_contains_a_raw_secret(weak):
    report = run_audit([weak + "/"], lab(), checks=["secrets", "jwt", "exposed-files", "api-surface"])
    assert report.findings
    for rendered in (to_json(report), to_csv(report), to_html(report), to_sarif(report)):
        assert EXAMPLE_AWS_KEY not in rendered
        assert "Sup3rS3cretPw" not in rendered
        assert "not-a-real-password" not in rendered
        assert "$2b$12$" not in rendered


def test_hardened_site_that_answers_every_path_has_no_false_positives(hardened):
    report = run_audit([hardened + "/"], lab("deep"))
    # The only true statements about this fixture: it has no TLS, so its login form is unencrypted.
    assert {(item.check, item.title) for item in report.findings} == {
        ("transport", "Site is served over plain HTTP"),
        ("page-content", "Password form is sent over plain HTTP"),
    }


def test_selected_checks_only_and_scope_is_enforced(weak):
    report = run_audit([weak + "/", "https://not-authorised.example.org/"], lab(), checks=["cookies"])
    assert {item.check for item in report.findings} == {"cookies"}
    assert report.checks_run == ["cookies"]
    assert [note.url for note in report.notes if note.check == "scope"] == ["https://not-authorised.example.org/"]


def test_cancel_stops_the_audit(weak):
    cancel = threading.Event()
    cancel.set()
    report = run_audit([weak + "/"], lab(), cancel=cancel)
    assert report.cancelled and report.findings == []


def test_findings_are_streamed_to_the_callback(weak):
    seen: list[Finding] = []
    report = run_audit([weak + "/"], lab(), checks=["cookies", "security-headers"], on_finding=seen.append)
    assert {item.title for item in seen} == {item.title for item in report.findings}


def test_reports_are_well_formed(weak):
    report = run_audit([weak + "/"], lab(), checks=["security-headers", "cookies", "exposed-files"])
    data = json.loads(to_json(report))
    assert data["tool"] == "Rift" and data["summary"]["total"] == len(report.findings)
    assert data["grade"] == "F" and data["findings"][0]["severity"] == "critical"
    sarif = json.loads(to_sarif(report))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(report.findings)
    assert to_csv(report).splitlines()[0].startswith("severity,check,title")
    page = to_html(report)
    assert "<script" not in page and "Rift security report" in page


def test_html_report_escapes_server_controlled_text():
    from rift.audit import AuditReport

    hostile = Finding(
        check="x", title="<script>alert(1)</script>", severity="high", url="https://a.example/\"><img src=x>",
        evidence="=cmd|' /C calc'!A0 <b>", explanation="e", remediation="r",
    )
    report = AuditReport(findings=[hostile])
    assert "<script>alert(1)</script>" not in to_html(report) and "<img src=x>" not in to_html(report)
    assert "'=cmd" in to_csv(report)


def test_score_caps_the_grade_when_something_serious_is_present():
    def finding(severity):
        return Finding(check="x", title=severity, severity=severity, url="u", evidence="", explanation="", remediation="")

    assert score([]) == (100, "A")
    assert score([finding("critical")])[1] == "F"
    assert score([finding("high")])[1] == "C"
    assert score([finding("info")] * 30) == (100, "A")


def test_cli_requires_the_authorisation_flag(weak, monkeypatch, capsys):
    monkeypatch.setenv("RIFT_ALLOW_INTERNAL", "1")
    assert main([weak + "/", "--quiet"], stdout=io.StringIO()) == 2
    assert "--i-am-authorised" in capsys.readouterr().err


def test_cli_runs_writes_reports_and_fails_the_build(weak, monkeypatch, tmp_path):
    monkeypatch.setenv("RIFT_ALLOW_INTERNAL", "1")
    out = io.StringIO()
    code = main(
        [weak + "/", "--i-am-authorised", "--quiet", "--checks", "cookies,exposed-files", "--fail-on", "high",
         "--json", str(tmp_path / "r.json"), "--html", str(tmp_path / "r.html"), "--sarif", str(tmp_path / "r.sarif"), "--csv", str(tmp_path / "r.csv")],
        stdout=out,
    )
    assert code == 1
    assert "Grade F" in out.getvalue() and "[CRITICAL" in out.getvalue()
    saved = json.loads((tmp_path / "r.json").read_text())
    assert saved["authorization"]["acknowledged"] is True and saved["checks_run"] == ["cookies", "exposed-files"]
    assert all((tmp_path / name).stat().st_size > 0 for name in ("r.html", "r.sarif", "r.csv"))
    assert main([weak + "/", "--i-am-authorised", "--quiet", "--checks", "cookies", "--fail-on", "critical"], stdout=io.StringIO()) == 0


def test_cli_lists_checks_and_rejects_unknown_names(capsys):
    out = io.StringIO()
    assert main(["--list-checks"], stdout=out) == 0
    assert "security-headers" in out.getvalue() and "open-redirect" in out.getvalue()
    assert main(["https://example.com", "--checks", "nope"], stdout=io.StringIO()) == 2


# --- the scoped client --------------------------------------------------------


def _client(handler):
    config = ScanConfig(allowlist=("example.com",), min_interval_seconds=0)

    class Resolver:
        def resolve(self, hostname, port):
            return ["93.184.216.34"]

    return HttpxRequester(config, transport=httpx.MockTransport(handler), resolver=Resolver())


def test_client_keeps_headers_and_sends_only_allowed_request_headers():
    seen = {}

    def handler(request):
        seen["origin"] = request.headers.get("origin")
        seen["host"] = request.headers.get("host")
        return httpx.Response(200, headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("X-Test", "yes")], text="body")

    with _client(handler) as client:
        result = client.request("https://example.com/", headers={"Origin": "https://probe.invalid"}, include_body=True)
        assert result.header("x-test") == "yes" and result.header_all("set-cookie") == ["a=1", "b=2"]
        assert seen == {"origin": "https://probe.invalid", "host": "example.com"}
        for forbidden in ({"Host": "evil.example"}, {"Cookie": "a=b"}, {"Authorization": "x"}, {"Origin": "a\r\nX: y"}):
            blocked = client.request("https://example.com/", headers=forbidden)
            assert blocked.safety_block and blocked.status_code is None


def test_client_refuses_methods_that_change_state():
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(200)

    with _client(handler) as client:
        for method in ("POST", "PUT", "DELETE", "PATCH", "TRACE"):
            assert client.request("https://example.com/", method=method).safety_block
        assert client.request("https://example.com/", method="OPTIONS").status_code == 200
    assert calls == ["OPTIONS"]


def test_static_files_are_read_only_when_a_check_asks():
    with _client(lambda request: httpx.Response(200, text="x")) as client:
        assert client.request("https://example.com/backup.zip").safety_block
        assert client.request("https://example.com/backup.zip", allow_static=True).status_code == 200
        assert client.get("https://example.com/app.js", include_body=True).status_code == 200
        assert client.get("https://example.com/logo.png", include_body=True).safety_block
        # State-changing paths stay blocked even for checks.
        assert client.request("https://example.com/account/delete", allow_static=True).safety_block
