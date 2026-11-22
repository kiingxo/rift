import threading
from http.server import ThreadingHTTPServer
from urllib.parse import quote, urlsplit

import pytest

from rift.config import TEST_DESTINATION, ScanConfig
from rift.engine import scan_urls
from rift.models import Verdict
from tests.fixture_server import RedirectFixtureHandler


@pytest.fixture
def redirect_fixture():
    RedirectFixtureHandler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_http_distinguishes_vulnerable_internal_and_inconclusive(redirect_fixture):
    port = redirect_fixture
    config = ScanConfig(
        allowlist=("127.0.0.1",),
        allow_internal=True,
        min_interval_seconds=0,
        max_workers=1,
        timeout_seconds=3,
        connect_timeout_seconds=2,
        mode="quick",
    )
    base = f"http://127.0.0.1:{port}"
    results = scan_urls(
        [
            f"{base}/login",
            f"{base}/floor",
            f"{base}/oauth/start",
            "https://example.com/login",
        ],
        config,
    )

    def one(path: str, parameter: str):
        marker = quote(TEST_DESTINATION, safe="")
        found = [
            result
            for result in results
            if urlsplit(result.original_url).path == path
            and result.tested_parameter == parameter
            and urlsplit(result.original_url).hostname == "127.0.0.1"
            and marker in result.test_url
        ]
        assert len(found) == 1
        return found[0]

    login = one("/login", "next")
    assert login.result == Verdict.POTENTIAL.value
    assert login.http_status == 302
    assert login.location_header == "https://www.google.com"
    assert urlsplit(login.redirect_destination).hostname == "www.google.com"

    floor = one("/floor", "next")
    assert floor.result == Verdict.NO_ISSUE.value
    assert floor.http_status == 302
    assert urlsplit(floor.redirect_destination).hostname == "127.0.0.1"
    assert "google.com" in (floor.location_header or "")

    oauth = one("/oauth/start", "next")
    assert oauth.result == Verdict.INCONCLUSIVE.value
    assert "does not depend" in oauth.explanation

    blocked = [result for result in results if "example.com" in result.original_url]
    assert len(blocked) == 1
    assert blocked[0].result == Verdict.INCONCLUSIVE.value
    assert blocked[0].test_url == ""
    assert all(path.startswith("/") for path in RedirectFixtureHandler.seen)


def test_fixture_flags_encoded_tracking_and_a_same_origin_chain(redirect_fixture):
    port = redirect_fixture
    config = ScanConfig(
        allowlist=("127.0.0.1",),
        allow_internal=True,
        min_interval_seconds=0,
        max_workers=1,
        timeout_seconds=3,
        connect_timeout_seconds=2,
        mode="standard",
    )
    base = f"http://127.0.0.1:{port}"
    results = scan_urls([f"{base}/newsletter/tracking.php", f"{base}/chain"], config)
    tracking = [
        result
        for result in results
        if result.tested_parameter == "url" and result.result == Verdict.POTENTIAL.value
    ]
    chain = [
        result
        for result in results
        if urlsplit(result.original_url).path == "/chain"
        and result.tested_parameter == "next"
        and result.result == Verdict.POTENTIAL.value
    ]
    assert tracking
    assert tracking[0].payload.startswith("//google.com/")
    assert urlsplit(tracking[0].redirect_destination).hostname == "google.com"
    assert chain
    assert "/chain/hop" in chain[0].redirect_chain
    assert all(path.startswith("/") for path in RedirectFixtureHandler.seen)
    assert not any("google.com" in path and path.startswith("http") for path in RedirectFixtureHandler.seen)
