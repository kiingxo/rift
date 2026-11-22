"""Signed-in testing: the session, the client rules, the check, the console and the CLI."""

from __future__ import annotations

import io
import json
import threading
import time
from http.server import ThreadingHTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient

from rift.audit import run_audit
from rift.audit_report import to_csv, to_html, to_json, to_sarif
from rift.checks.session import session_end_finding
from rift.cli import main
from rift.config import ScanConfig
from rift.http_client import HttpxRequester, SystemResolver
from rift.server import create_app
from rift.session import SessionError, SignedInSession, looks_like_action
from tests.weak_site import ACTION_PATHS, TEST_EMAIL, TEST_SESSION, UNSIGNED_JWT, HardenedSite, WeakSite, _Base

COOKIE = f"acme_session={TEST_SESSION}"
SIGNED_CHECKS = ["signed-in", "secrets", "api-surface"]


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def weak():
    _Base.requested.clear()
    server, thread = _serve(WeakSite)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def hardened():
    _Base.requested.clear()
    HardenedSite.session_valid = True
    server, thread = _serve(HardenedSite)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    HardenedSite.session_valid = True
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


def session(cookie=COOKIE, marker=TEST_EMAIL, header=""):
    return SignedInSession.build(cookie=cookie, header=header, marker=marker, hosts=["127.0.0.1"])


def titles(report):
    return {(item.check, item.title) for item in report.findings}


def action_requests():
    return [path for path, _signed in _Base.requested if any(path.startswith(action) for action in ACTION_PATHS)]


# ---- the pasted session -----------------------------------------------------


def test_cookie_and_header_are_parsed_from_what_people_paste():
    built = SignedInSession.build(cookie="Cookie: a=1; sid=abcdefgh12345; Path=/; HttpOnly", hosts=["App.Example.com"])
    assert built.cookies == (("a", "1"), ("sid", "abcdefgh12345")) and built.hosts == ("app.example.com",)
    assert built.request_headers() == {"Cookie": "a=1; sid=abcdefgh12345"}
    bearer = SignedInSession.build(header="Bearer eyJabc.def.ghi", hosts=["x.test"])
    assert (bearer.header_name, bearer.header_value) == ("Authorization", "Bearer eyJabc.def.ghi")
    custom = SignedInSession.build(header="X-Api-Key: k_1234567890", hosts=["x.test"])
    assert custom.request_headers() == {"X-Api-Key": "k_1234567890"} and custom.method == "header"
    assert SignedInSession.build(hosts=["x.test"]) is None


@pytest.mark.parametrize(
    "fields",
    [
        {"cookie": "just-a-value"},
        {"cookie": "a=1\r\nX-Evil: 1"},
        {"header": "Host: evil.test"},
        {"header": "X-Forwarded-For: 1.2.3.4"},
        {"header": "no colon here"},
        {"cookie": "a=1", "marker": "ab"},
        {"marker": "alice@acme.test"},
    ],
)
def test_unusable_sessions_are_refused_with_a_reason(fields):
    with pytest.raises(SessionError):
        SignedInSession.build(hosts=["x.test"], **fields)


def test_the_session_value_never_shows_in_repr_description_or_scrubbed_text():
    built = session()
    assert TEST_SESSION not in repr(built) and TEST_SESSION not in json.dumps(built.describe())
    assert TEST_EMAIL not in repr(built)
    text = f"/a?sid={TEST_SESSION} and {TEST_SESSION.replace('-', '%2D')} and raw {TEST_SESSION}"
    assert TEST_SESSION not in built.scrub(text) and built.scrub(text).count("[session]") >= 2


@pytest.mark.parametrize(
    "url, action",
    [
        ("https://a.test/logout", True),
        ("https://a.test/users/sign-out", True),
        ("https://a.test/account/archive-all", True),
        ("https://a.test/export?action=delete", True),
        ("https://a.test/team/members/7/remove", True),
        ("https://a.test/api/v1/tokens/revoke", True),
        ("https://a.test/account/settings", False),
        ("https://a.test/orders/history", False),
        ("https://a.test/reports?status=cancelled", False),
        ("https://a.test/invoices/1042", False),
    ],
)
def test_action_links_are_recognised(url, action):
    assert looks_like_action(url) is action


# ---- the client --------------------------------------------------------------


def _requester(handler, built):
    config = ScanConfig(allowlist=("app.test", "other.test"), min_interval_seconds=0, max_workers=1)
    resolver = SystemResolver(config, lookup=lambda host, port: [(2, 1, 6, "", ("93.184.216.34", port))])
    return HttpxRequester(config, transport=httpx.MockTransport(handler), resolver=resolver, session=built)


def test_client_sends_the_session_only_when_asked_and_only_to_its_hosts():
    seen = []

    def handler(request):
        seen.append((request.headers["host"], request.url.path, request.headers.get("cookie")))
        return httpx.Response(200, headers={"Set-Cookie": "tracker=1; Path=/"}, text="ok")

    built = SignedInSession.build(cookie=COOKIE, hosts=["app.test"])
    requester = _requester(handler, built)
    assert requester.request("https://app.test/account", signed_in=True).signed_in is True
    assert requester.request("https://app.test/account").signed_in is False
    assert requester.request("https://other.test/account", signed_in=True).signed_in is False
    blocked = requester.request("https://app.test/team/7/archive", signed_in=True)
    assert requester.request("https://app.test/team/7/archive").signed_in is False
    assert blocked.safety_block and "action" in blocked.error
    requester.close()
    assert seen == [
        ("app.test", "/account", COOKIE),
        ("app.test", "/account", None),
        ("other.test", "/account", None),
        ("app.test", "/team/7/archive", None),
    ]


def test_client_never_keeps_cookies_a_site_sets():
    seen = []

    def handler(request):
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, headers={"Set-Cookie": "session=from-server; Path=/"})

    requester = _requester(handler, None)
    requester.request("https://app.test/one")
    requester.request("https://app.test/two")
    requester.close()
    assert seen == [None, None]


# ---- the signed-in scan -----------------------------------------------------


def test_signed_in_scan_finds_each_planted_issue_and_never_follows_an_action(weak):
    report = run_audit([weak + "/account"], lab(), checks=SIGNED_CHECKS, session=session())
    found = titles(report)
    assert ("signed-in", "Private data is shown without signing in") in found
    assert ("signed-in", "Private page is marked public for shared caches") in found
    assert ("signed-in", "Private page does not tell caches not to store it") in found
    assert ("signed-in", "Session token appears in a URL") in found
    assert ("signed-in", "Session cookie value is written into the page") in found
    leak = next(item for item in report.findings if item.title == "Private data is shown without signing in")
    assert leak.severity == "critical" and leak.url.endswith("/account/invoices/1042")
    assert action_requests() == []
    assert report.session["status"] == "confirmed" and report.session["private_pages"] >= 3
    assert report.session["signed_in_text_seen"] is True


def test_no_report_or_progress_line_contains_the_session(weak):
    lines = []
    report = run_audit(
        [weak + "/account"], lab(), checks=None, session=session(), on_progress=lambda done, total, detail: lines.append(detail)
    )
    for rendered in (to_json(report), to_html(report), to_csv(report), to_sarif(report), "\n".join(lines)):
        assert TEST_SESSION not in rendered
    assert "[session]" in to_json(report)
    assert "Signed in with a test account (cookie: acme_session)" in to_html(report)


def test_without_signed_in_text_a_public_looking_leak_is_not_guessed(weak):
    report = run_audit([weak + "/account"], lab(), checks=["signed-in"], session=session(marker=""))
    found = {title for _check, title in titles(report)}
    assert "Private data is shown without signing in" not in found
    assert "Private page is marked public for shared caches" in found
    assert report.session["status"] == "confirmed"


def test_a_wrong_session_is_reported_as_not_working(weak):
    report = run_audit([weak + "/account"], lab(), checks=["signed-in"], session=session(cookie="acme_session=expired-0000000000"))
    assert report.session["status"] == "rejected" and report.session["private_pages"] == 0
    unconfirmed = run_audit([weak + "/"], lab(), checks=["signed-in"], session=session(cookie="acme_session=expired-0000000000", marker=""))
    assert unconfirmed.session["status"] == "unconfirmed"


def test_hardened_site_signed_in_has_no_false_positives(hardened):
    report = run_audit([hardened + "/account"], lab("deep"), checks=None, session=session())
    # The one true statement about this fixture: it has no TLS.
    assert titles(report) == {("transport", "Site is served over plain HTTP")}
    assert report.session["status"] == "confirmed" and action_requests() == []


def test_a_jwt_session_token_is_judged(weak):
    report = run_audit([weak + "/"], lab(), checks=["signed-in"], session=session(cookie="", header=f"Bearer {UNSIGNED_JWT}", marker=""))
    found = {title for _check, title in titles(report)}
    assert "Session token is an unsigned JWT" in found and "Session token (JWT) has no expiry" in found
    assert UNSIGNED_JWT not in to_json(report)


def test_anonymous_scans_are_unchanged_by_the_signed_in_check(weak):
    report = run_audit([weak + "/"], lab(), checks=["signed-in", "cookies"])
    assert all(item.check != "signed-in" for item in report.findings) and report.session is None
    assert all(signed is False for _path, signed in _Base.requested)


# ---- signing out ------------------------------------------------------------


def _fetcher(built):
    requester = HttpxRequester(lab(), session=built)
    return requester, lambda url, signed: requester.request(url, include_body=True, signed_in=signed)


def test_session_that_survives_sign_out_is_reported(weak):
    requester, fetch = _fetcher(session())
    finding, outcome = session_end_finding(session(), weak + "/account/settings", fetch, "127.0.0.1")
    requester.close()
    assert finding is not None and finding.title == "Signing out does not end the session" and finding.severity == "high"
    assert outcome.startswith("Failed")


def test_session_that_ends_at_sign_out_passes(hardened):
    HardenedSite.session_valid = False
    requester, fetch = _fetcher(session())
    finding, outcome = session_end_finding(session(), hardened + "/account", fetch, "127.0.0.1")
    requester.close()
    assert finding is None and outcome.startswith("Passed")


# ---- console and command line ------------------------------------------------

TOKEN = "test-token"
AUTH = {"X-Rift-Token": TOKEN}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("RIFT_ALLOW_INTERNAL", "1")
    app = create_app(data_dir=tmp_path / "scans", token=TOKEN)
    with TestClient(app, base_url="http://127.0.0.1:8600") as test_client:
        test_client.data_dir = tmp_path / "scans"
        yield test_client


def _wait(client, scan_id):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}", headers=AUTH).json()
        if scan["state"] not in {"running", "paused"}:
            return scan
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def _start(client, base, **extra):
    body = {
        "targets": base + "/account",
        "authorised": True,
        "min_interval_seconds": 0.05,
        "checks": ["signed-in"],
        "session_cookie": COOKIE,
        "signed_in_text": TEST_EMAIL,
    }
    body.update(extra)
    return client.post("/api/scans", json=body, headers=AUTH)


def test_console_runs_a_signed_in_scan_and_the_sign_out_check_without_storing_the_session(client, weak):
    response = _start(client, weak)
    assert response.status_code == 201
    scan_id = response.json()["id"]
    scan = _wait(client, scan_id)
    assert scan["session"]["status"] == "confirmed" and scan["session_check_open"] is True
    assert any(item["title"] == "Private data is shown without signing in" for item in scan["findings"])
    assert client.get("/api/scans", headers=AUTH).json()["scans"][0]["signed_in"] is True

    checked = client.post(f"/api/scans/{scan_id}/session-end", headers=AUTH)
    assert checked.status_code == 200 and checked.json()["result"] == "failed"
    after = checked.json()["scan"]
    assert after["session_check_open"] is False and after["session"]["session_end"]["result"] == "failed"
    assert any(item["title"] == "Signing out does not end the session" for item in after["findings"])
    assert client.post(f"/api/scans/{scan_id}/session-end", headers=AUTH).status_code == 409

    saved = (client.data_dir / f"{scan_id}.json").read_text()
    assert TEST_SESSION not in saved and "Signing out does not end the session" in saved
    for kind in ("html", "json", "csv", "sarif"):
        assert TEST_SESSION not in client.get(f"/api/scans/{scan_id}/export/{kind}", headers=AUTH).text
    assert TEST_SESSION not in json.dumps(client.get(f"/api/scans/{scan_id}", headers=AUTH).json())


def test_console_refuses_an_unusable_session(client, weak):
    assert _start(client, weak, session_cookie="not a cookie").status_code == 400
    assert _start(client, weak, session_cookie="", signed_in_text=TEST_EMAIL).status_code == 400
    assert _start(client, weak, session_header="Host: evil.test", session_cookie="").status_code == 400


def test_cli_reads_the_session_from_the_environment(weak, monkeypatch, capsys):
    monkeypatch.setenv("RIFT_ALLOW_INTERNAL", "1")
    monkeypatch.setenv("RIFT_TEST_COOKIE", COOKIE)
    out = io.StringIO()
    code = main(
        [weak + "/account", "--i-am-authorised", "--checks", "signed-in", "--signed-in-text", TEST_EMAIL, "--fail-on", "critical"],
        stdout=out,
    )
    assert code == 1
    printed = out.getvalue() + capsys.readouterr().err
    assert "Private data is shown without signing in" in printed and "login: Signed in with a test account" in printed
    assert TEST_SESSION not in printed


# ---- single-page apps: API addresses in the JavaScript ------------------------

from rift.checks.base import CheckContext  # noqa: E402
from rift.checks.session import SignedInCheck  # noqa: E402
from rift.endpoints import chunk_scripts, find_api_hints, one_per_route, readable, resolve, shrink  # noqa: E402
from rift.models import Observation  # noqa: E402
from tests.weak_site import SPA_ADDRESSES_NEVER_READ, SPA_CHUNK, SPA_TOKEN, SpaApi, SpaFront, spa_bundle  # noqa: E402


@pytest.fixture
def spa():
    _Base.requested.clear()
    api, api_thread = _serve(SpaApi)
    SpaFront.api_port = api.server_address[1]
    front, front_thread = _serve(SpaFront)
    yield f"http://127.0.0.1:{front.server_address[1]}", f"http://127.0.0.1:{api.server_address[1]}"
    for server, thread in ((front, front_thread), (api, api_thread)):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def spa_session(token=SPA_TOKEN, marker=TEST_EMAIL):
    return SignedInSession.build(header=f"Authorization: {token}", marker=marker, hosts=["127.0.0.1"])


def test_api_addresses_are_read_from_bundle_text_without_placeholders_or_risky_words():
    hints = find_api_hints([spa_bundle(9999), SPA_CHUNK])
    assert hints.bases[0] == "http://127.0.0.1:9999/api/" and "https://api.acme-health.test/api/" in hints.bases
    assert hints.collections == ["patients", "invoices"] and hints.pocketbase == ["http://127.0.0.1:9999"]
    urls = {resolve(address, "http://127.0.0.1:1", hints.bases) for address in hints.addresses}
    readable_urls = set(one_per_route([shrink(url) for url in urls if readable(url, app_read=url in hints.app_reads)]))
    # PocketBase's own admin paths (/api/health, /api/collections/) are library code, not the app's.
    assert readable_urls == {
        "http://127.0.0.1:9999/api/me",
        "http://127.0.0.1:9999/api/auth/profile",
        "http://127.0.0.1:9999/api/visits?limit=1",
        "http://127.0.0.1:9999/api/hmo/claim?limit=1",
        "http://127.0.0.1:9999/api/collections/patients/records?perPage=1",
        "http://127.0.0.1:9999/api/collections/invoices/records?perPage=1",
    }
    assert not any("${" in url or "/patients/" in url and "records" not in url for url in urls)
    assert all(not readable(f"http://127.0.0.1:9999{path}") for path in SPA_ADDRESSES_NEVER_READ)


def test_chunks_named_inside_a_bundle_are_found_on_the_same_site():
    bundle = 'import("./Invoices-Zx90Yw87.js");x="assets/Chart-a1b2c3d4.js";y="https://cdn.test/lib-a1b2c3d4.js";z="./plain.js"'
    assert chunk_scripts("https://app.test/assets/index-Q1w2E3r4.js", bundle) == [
        "https://app.test/assets/Invoices-Zx90Yw87.js",
        "https://app.test/assets/Chart-a1b2c3d4.js",
    ]


def test_a_javascript_app_is_tested_through_the_api_its_bundle_calls(spa):
    front, api = spa
    report = run_audit([front + "/"], lab(), checks=["signed-in"], session=spa_session())
    found = {(item.title, item.url) for item in report.findings}
    # Invoices are readable by anyone; the collection call was only in a chunk loaded later.
    assert ("Private data is shown without signing in", api + "/api/collections/invoices/records?perPage=1") in found
    # Patients sit past the first 200 KB of the bundle; signed out, the list comes back empty.
    private = set(report.session["private_examples"])
    assert {api + "/api/me", api + "/api/collections/patients/records?perPage=1"} <= private
    # Calls made through an HTTP client against the declared base: lists are read one record at a time.
    assert {api + "/api/auth/profile", api + "/api/visits?limit=1"} <= private
    # "claim" would stop a guessed address; the app reads this one itself with GET, so it is read.
    assert api + "/api/hmo/claim?limit=1" in private
    skipped = {item["url"]: item["reason"] for item in report.session["skipped_addresses"]}
    assert "cancel" in skipped[api + "/api/orders/cancel"] and "send" in skipped[api + "/api/auth/sendPhoneNumberOTP"]
    assert "/api/orders/cancel" in to_html(report)
    assert report.session["status"] == "confirmed" and report.session["script_answers"] >= 5
    assert front + "/assets/Invoices-Zx90Yw87.js" in report.scripts
    read = [path for path, _signed in _Base.requested]
    assert not [path for path in read if any(path.startswith(risky) for risky in SPA_ADDRESSES_NEVER_READ)]
    assert not [path for path in read if "/api/patients/" in path]
    assert "/api/visits?limit=All" not in read and "/api/collections/" not in read
    assert not [path for path in read if path.startswith("/api/visits/")]
    assert SPA_TOKEN not in to_json(report)


def test_a_wrong_token_on_a_javascript_app_is_reported_as_not_working(spa):
    front, _api = spa
    report = run_audit([front + "/"], lab(), checks=["signed-in"], session=spa_session(token="spa-expired-0000000000"))
    assert report.session["status"] == "rejected" and report.session["private_pages"] == 0
    assert "Private data is shown without signing in" in {item.title for item in report.findings}


def test_addresses_that_do_not_exist_do_not_make_a_working_session_look_dead():
    """Only a refusal (401, 403, redirect to sign in) says the session is dead; a 404 says nothing."""

    sent = []

    def fetcher(url, **options):
        sent.append(url)
        return Observation(status_code=404, url=url, signed_in=bool(options.get("signed_in")))

    bundle = Observation(
        status_code=200,
        url="https://app.acme.test/assets/index-Q1w2E3r4.js",
        body='const r=rg({baseUrl:"https://app.acme.test/api/"});x=http.get("auth/profile");',
    )
    session_ = SignedInSession.build(header="Authorization: Bearer abcdefgh12345", marker="alice@acme.test", hosts=["app.acme.test"])
    ctx = CheckContext(origin="https://app.acme.test", config=ScanConfig(), pages=[], scripts=[bundle], fetcher=fetcher, session=session_)
    SignedInCheck().run(ctx)
    from rift.audit import _session_summary

    summary = _session_summary(session_, ctx.shared, ["signed-in"], session_.scrub)
    assert "https://app.acme.test/api/auth/profile" in sent
    assert summary["status"] == "unconfirmed" and summary["script_addresses"] >= 1


def test_an_api_host_outside_the_scan_is_named_and_never_contacted():
    sent = []

    def fetcher(url, **options):
        sent.append(url)
        return Observation(status_code=404, url=url)

    bundle = Observation(
        status_code=200,
        url="https://app.acme.test/assets/index-Q1w2E3r4.js",
        body='const pb=new PocketBase("https://auth-uat.acme.test");const b="https://auth-uat.acme.test/api/";'
        'x="/api/collections/";pb.collection("patients");y="https://www.acme.test/";z="https://api.stripe.com/v1/"',
    )
    ctx = CheckContext(
        origin="https://app.acme.test",
        config=ScanConfig(),
        pages=[],
        scripts=[bundle],
        fetcher=fetcher,
        session=SignedInSession.build(header="Authorization: abcdefgh12345", hosts=["app.acme.test"]),
    )
    SignedInCheck().run(ctx)
    assert not [url for url in sent if "auth-uat" in url or "stripe" in url]
    assert ctx.shared["signed-in-state"]["hosts_missing"] == ["auth-uat.acme.test"]
    assert any("auth-uat.acme.test" in note.detail for note in ctx.notes)
