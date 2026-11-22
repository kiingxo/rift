"""Worked examples for the three verdicts.

Vulnerable: /login?next=https://www.google.com redirects to Google, and a
same-site control value does not.
Safe: /floor?next=https://www.google.com redirects to /office on the same host.
Inconclusive: the endpoint redirects to Google for the external value and the
same-site control value, so the parameter is not shown to control it.
"""

from urllib.parse import parse_qs, quote, urlsplit

from rift.config import ScanConfig, TEST_DESTINATION
from rift.engine import scan_urls
from rift.models import Observation, Verdict
from tests.fakes import ScriptedRequester

HOST = "app.example.com"
CONFIG = ScanConfig(allowlist=(HOST,), max_workers=1, min_interval_seconds=0, mode="quick")


def _app(url: str) -> Observation:
    parts = urlsplit(url)
    params = parse_qs(parts.query)
    if parts.path == "/login":
        target = params.get("next", [None])[0]
        if target:
            return Observation(status_code=302, location_header=target)
        return Observation(status_code=200)
    if parts.path == "/floor":
        target = params.get("next", [""])[0]
        return Observation(status_code=302, location_header=f"/office?next={target}")
    if parts.path == "/oauth/start":
        return Observation(status_code=302, location_header=TEST_DESTINATION)
    return Observation(status_code=404)


def _by_param(results, path, parameter):
    marker = quote(TEST_DESTINATION, safe="")
    found = [
        result
        for result in results
        if urlsplit(result.original_url).path == path
        and result.tested_parameter == parameter
        and marker in result.test_url
    ]
    assert len(found) == 1
    return found[0]


def test_login_next_to_google_is_a_potential_vulnerability():
    requester = ScriptedRequester(_app)
    results = scan_urls([f"https://{HOST}/login"], CONFIG, requester)
    finding = _by_param(results, "/login", "next")
    assert finding.result == Verdict.POTENTIAL.value
    assert urlsplit(finding.redirect_destination).hostname == "www.google.com"
    assert finding.http_status == 302
    assert "next" in finding.explanation
    others = [result for result in results if result.tested_parameter != "next"]
    assert others
    assert all(result.result == Verdict.NO_ISSUE.value for result in others)
    assert all(urlsplit(url).hostname == HOST for url in requester.calls)


def test_floor_keeps_the_google_value_on_an_internal_redirect():
    requester = ScriptedRequester(_app)
    results = scan_urls([f"https://{HOST}/floor?next=/desk"], CONFIG, requester)
    finding = _by_param(results, "/floor", "next")
    assert finding.result == Verdict.NO_ISSUE.value
    assert urlsplit(finding.redirect_destination).hostname == HOST
    assert finding.location_header.startswith("/office?next=")
    assert "google.com" in finding.location_header
    assert "was not flagged" in finding.explanation
    assert all(urlsplit(url).hostname == HOST for url in requester.calls)


def test_redirect_to_google_for_every_value_is_inconclusive():
    requester = ScriptedRequester(_app)
    results = scan_urls([f"https://{HOST}/oauth/start"], CONFIG, requester)
    finding = _by_param(results, "/oauth/start", "next")
    assert finding.result == Verdict.INCONCLUSIVE.value
    assert "does not depend" in finding.explanation
    assert finding.control_http_status == 302
    assert urlsplit(finding.control_redirect_destination).hostname == "www.google.com"
