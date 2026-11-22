"""The web console's API: session token, host check, scan lifecycle, exports, saved history."""

from __future__ import annotations

import threading
import time
from http.server import ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from rift.server import create_app
from tests.weak_site import EXAMPLE_AWS_KEY, WeakSite

TOKEN = "test-token"
AUTH = {"X-Rift-Token": TOKEN}


@pytest.fixture
def weak():
    server = ThreadingHTTPServer(("127.0.0.1", 0), WeakSite)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("RIFT_ALLOW_INTERNAL", "1")
    app = create_app(data_dir=tmp_path / "scans", token=TOKEN)
    with TestClient(app, base_url="http://127.0.0.1:8600") as test_client:
        test_client.data_dir = tmp_path / "scans"
        yield test_client


def wait_until_done(client, scan_id, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}", headers=AUTH).json()
        if scan["state"] not in {"running", "paused"}:
            return scan
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def start(client, base, **extra):
    body = {"targets": base + "/", "authorised": True, "min_interval_seconds": 0.05, "checks": ["cookies", "secrets", "exposed-files"]}
    body.update(extra)
    return client.post("/api/scans", json=body, headers=AUTH)


def test_page_carries_the_token_and_a_strict_content_security_policy(client):
    page = client.get("/")
    assert page.status_code == 200 and TOKEN in page.text and "__RIFT_TOKEN__" not in page.text
    policy = page.headers["content-security-policy"]
    assert "default-src 'none'" in policy and "script-src 'self'" in policy and "unsafe-inline" not in policy
    assert page.headers["x-frame-options"] == "DENY" and page.headers["x-content-type-options"] == "nosniff"
    assert "<script src=" in page.text and "style=" not in page.text
    for asset in ("/app.js", "/theme.js", "/app.css", "/favicon.svg"):
        assert client.get(asset).status_code == 200


def test_api_refuses_requests_without_the_session_token(client):
    assert client.get("/api/meta").status_code == 401
    assert client.get("/api/meta", headers={"X-Rift-Token": "wrong"}).status_code == 401
    assert client.post("/api/scans", json={"targets": "https://example.com", "authorised": True}).status_code == 401
    assert client.get("/api/meta", headers=AUTH).status_code == 200


def test_requests_for_another_host_name_are_refused(client):
    # A hostile domain that resolves to 127.0.0.1 still sends its own name in Host.
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 421
    assert client.get("/api/meta", headers={**AUTH, "Host": "attacker.example:8600"}).status_code == 421
    assert client.get("/", headers={"Host": "localhost:8600"}).status_code == 200


def test_meta_lists_every_check(client):
    meta = client.get("/api/meta", headers=AUTH).json()
    assert meta["name"] == "Rift" and meta["lab_mode"] is True
    assert {"security-headers", "open-redirect"} <= {check["id"] for check in meta["checks"]}


def test_preview_reports_scope_and_exclusions(client, weak):
    data = client.post("/api/preview", json={"targets": f"{weak}/\nhttp://169.254.169.254/latest\nnot a url"}, headers=AUTH).json()
    assert data["urls"] == [weak + "/"] and data["domains"] == ["127.0.0.1"]
    assert len(data["excluded"]) == 2


def test_a_scan_needs_authorisation_valid_targets_and_known_checks(client, weak):
    assert start(client, weak, authorised=False).status_code == 400
    assert start(client, weak, checks=["nope"]).status_code == 400
    assert start(client, weak, checks=[]).status_code == 400
    assert start(client, weak, targets="http://169.254.169.254/").status_code == 400
    assert start(client, weak, min_interval_seconds=0).status_code == 422


def test_scan_runs_is_saved_and_exports_without_raw_secrets(client, weak):
    response = start(client, weak)
    assert response.status_code == 201
    scan_id = response.json()["id"]
    scan = wait_until_done(client, scan_id)
    assert scan["state"] == "finished" and scan["grade"] == "F"
    assert scan["summary"]["critical"] >= 1 and scan["checks"] == ["cookies", "secrets", "exposed-files"]
    assert scan["findings"][0]["severity"] == "critical" and scan["authorization"]["domains"] == ["127.0.0.1"]
    assert (client.data_dir / f"{scan_id}.json").is_file()

    for kind, marker in (("html", "Rift security report"), ("json", '"findings"'), ("csv", "severity,check,title"), ("sarif", '"2.1.0"')):
        export = client.get(f"/api/scans/{scan_id}/export/{kind}", headers=AUTH)
        assert export.status_code == 200 and marker in export.text
        assert "attachment" in export.headers["content-disposition"]
        assert EXAMPLE_AWS_KEY not in export.text and "Sup3rS3cretPw" not in export.text
    assert client.get(f"/api/scans/{scan_id}/export/exe", headers=AUTH).status_code == 404

    listed = client.get("/api/scans", headers=AUTH).json()["scans"]
    assert [item["id"] for item in listed] == [scan_id]


def test_saved_scans_survive_a_restart_and_can_be_deleted(client, weak, tmp_path):
    scan_id = start(client, weak).json()["id"]
    wait_until_done(client, scan_id)
    fresh = create_app(data_dir=client.data_dir, token=TOKEN)
    with TestClient(fresh, base_url="http://127.0.0.1:8600") as second:
        restored = second.get(f"/api/scans/{scan_id}", headers=AUTH).json()
        assert restored["state"] == "finished" and restored["summary"]["total"] > 0
        assert second.get(f"/api/scans/{scan_id}/export/html", headers=AUTH).status_code == 200
        assert second.delete(f"/api/scans/{scan_id}", headers=AUTH).status_code == 200
        assert second.get(f"/api/scans/{scan_id}", headers=AUTH).status_code == 404
    assert not (client.data_dir / f"{scan_id}.json").exists()


def test_cancel_and_bad_identifiers(client, weak):
    scan_id = start(client, weak, checks=None, min_interval_seconds=0.5).json()["id"]
    assert client.post(f"/api/scans/{scan_id}/pause", headers=AUTH).json()["state"] == "paused"
    assert client.post(f"/api/scans/{scan_id}/resume", headers=AUTH).json()["state"] == "running"
    assert client.delete(f"/api/scans/{scan_id}", headers=AUTH).status_code == 409
    client.post(f"/api/scans/{scan_id}/cancel", headers=AUTH)
    assert wait_until_done(client, scan_id)["state"] == "cancelled"
    for bad in ("..%2F..%2Fetc%2Fpasswd", "20260101-000000-zzzzzz", "x"):
        assert client.get(f"/api/scans/{bad}", headers=AUTH).status_code == 404
    assert client.post(f"/api/scans/{scan_id}/explode", headers=AUTH).status_code == 404
