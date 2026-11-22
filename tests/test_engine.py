import pytest

from rift.catalog import profile_for
from rift.config import ScanConfig
from rift.engine import scan_urls
from rift.models import Observation, Verdict
from rift.safety import ScopeError
from tests.fakes import ScriptedRequester

HOST = "app.example.com"
CONFIG = ScanConfig(allowlist=(HOST,), max_workers=1, min_interval_seconds=0, mode="quick")


def _ok(_url: str) -> Observation:
    return Observation(status_code=204)


def test_off_allowlist_url_is_not_requested():
    requester = ScriptedRequester(_ok)
    results = scan_urls(["https://example.com/login"], CONFIG, requester)
    assert requester.calls == []
    assert results[0].result == Verdict.INCONCLUSIVE.value
    assert "allowlist" in results[0].explanation


def test_sensitive_and_static_paths_are_not_requested():
    requester = ScriptedRequester(_ok)
    results = scan_urls(
        [f"https://{HOST}/api/orders", f"https://{HOST}/assets/app.js"],
        CONFIG,
        requester,
    )
    assert requester.calls == []
    assert len(results) == 2
    assert all(result.result == Verdict.INCONCLUSIVE.value for result in results)


def test_credentials_are_not_sent():
    requester = ScriptedRequester(_ok)
    results = scan_urls([f"https://user:secret@{HOST}/login"], CONFIG, requester)
    assert requester.calls == []
    assert "credentials" in results[0].explanation


def test_scan_refuses_more_than_the_configured_url_budget():
    urls = [f"https://{HOST}/page-{index}" for index in range(3)]
    config = ScanConfig(allowlist=(HOST,), max_urls=2, max_workers=1, min_interval_seconds=0)
    with pytest.raises(ScopeError):
        scan_urls(urls, config, ScriptedRequester(_ok))


def test_results_stay_grouped_by_the_submitted_url_order():
    requester = ScriptedRequester(_ok)
    urls = [f"https://{HOST}/first", f"https://{HOST}/second"]
    config = ScanConfig(allowlist=(HOST,), max_workers=2, min_interval_seconds=0)
    results = scan_urls(urls, config, requester)
    paths = []
    for result in results:
        if result.original_url not in paths:
            paths.append(result.original_url)
    assert paths == [f"https://{HOST}/first", f"https://{HOST}/second"]


def test_a_normal_response_does_not_send_a_control_request():
    requester = ScriptedRequester(_ok)
    results = scan_urls([f"https://{HOST}/login"], CONFIG, requester)
    profile = profile_for("quick")
    payload_calls = [call for call in requester.calls if "google.com" in call]
    assert len(payload_calls) == len(profile.parameters) * len(profile.payloads)
    assert not any("__blueprint_redirect_control__" in call for call in requester.calls)
    assert all(result.result == Verdict.NO_ISSUE.value for result in results)
    assert all("secure" not in result.result.lower() for result in results)
