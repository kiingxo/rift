"""Fast Scan stays small. Deep Scan keeps the wider checks. Domains run together."""

import threading
import time
from urllib.parse import parse_qs, urlsplit

from rift.catalog import profile_for
from rift.config import ScanConfig
from rift.engine import scan_urls
from rift.models import Observation, Verdict
from tests.fakes import ScriptedRequester

HOST = "app.example.com"


def _config(mode: str, **kwargs) -> ScanConfig:
    base = dict(allowlist=(HOST,), max_workers=1, min_interval_seconds=0, mode=mode)
    base.update(kwargs)
    return ScanConfig(**base)


def test_fast_scan_finds_an_https_redirect_on_a_submitted_endpoint():
    def app(url: str, include_body: bool = False) -> Observation:
        if "www.google.com" in url:
            return Observation(status_code=302, location_header="https://www.google.com")
        return Observation(status_code=204)

    requester = ScriptedRequester(app)
    fast = scan_urls(
        [f"https://{HOST}/pt-br/redirect?url=https://www.google.com"],
        _config("fast"),
        requester,
    )
    assert any(result.result == Verdict.POTENTIAL.value and result.tested_parameter == "url" for result in fast)
    assert all(urlsplit(call).hostname == HOST for call in requester.calls)


def test_many_domains_overlap_instead_of_waiting_in_one_line():
    seen: set[str] = set()
    lock = threading.Lock()

    def app(url: str, include_body: bool = False) -> Observation:
        host = urlsplit(url).hostname or ""
        with lock:
            first = host not in seen
            seen.add(host)
        if first:
            time.sleep(0.2)
        return Observation(status_code=204)

    urls = [f"https://scan-{index}.example.com/login" for index in range(4)]
    config = ScanConfig(
        allowlist=("example.com",),
        max_workers=4,
        per_domain_concurrency=1,
        min_interval_seconds=0,
        mode="fast",
    )
    requester = ScriptedRequester(app)
    started_at = time.monotonic()
    scan_urls(urls, config, requester)
    elapsed = time.monotonic() - started_at
    assert elapsed < 0.6
    assert len({urlsplit(call).hostname for call in requester.calls}) == 4


def test_pause_holds_requests_until_resume():
    pause = threading.Event()
    pause.set()
    calls = []

    def app(url: str, include_body: bool = False) -> Observation:
        calls.append(url)
        return Observation(status_code=204)

    held: list[int] = []

    def resume() -> None:
        time.sleep(0.35)
        held.append(len(calls))
        pause.clear()

    threading.Thread(target=resume, daemon=True).start()
    results = scan_urls(
        [f"https://{HOST}/login"],
        _config("fast"),
        ScriptedRequester(app),
        pause=pause,
    )
    assert held == [0]
    assert calls
    assert results


def test_cancel_keeps_completed_rows():
    cancel = threading.Event()
    calls = []

    def app(url: str, include_body: bool = False) -> Observation:
        calls.append(url)
        if len(calls) >= 3:
            cancel.set()
        return Observation(status_code=204)

    results = scan_urls([f"https://{HOST}/login"], _config("fast"), ScriptedRequester(app), cancel=cancel)
    assert results
    assert len(calls) < 1 + len(profile_for("fast").parameters) * len(profile_for("fast").payloads)


def test_fast_scan_flags_a_locale_redirect_found_from_the_homepage():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path == "/":
            return Observation(status_code=200, body='<a href="/pt-br">BR</a>' if include_body else None)
        if parts.path == "/pt-br":
            return Observation(status_code=200, body="<html></html>" if include_body else None)
        if parts.path == "/pt-br/redirect":
            target = parse_qs(parts.query).get("url", [""])[0]
            if "google.com" in target:
                return Observation(status_code=302, location_header="https://www.google.com/")
            return Observation(status_code=302, location_header=f"https://{HOST}/")
        return Observation(status_code=404, body="missing" if include_body else None)

    requester = ScriptedRequester(app)
    flagged_at = []

    def on_finding(result) -> None:
        flagged_at.append(len(requester.calls))

    results = scan_urls(
        [f"https://{HOST}/"],
        _config("fast"),
        requester,
        on_finding=on_finding,
    )
    assert f"https://{HOST}/pt-br/redirect" in results.endpoints
    assert flagged_at
    assert flagged_at[0] < len(requester.calls)
    assert any(
        result.result == Verdict.POTENTIAL.value and result.tested_parameter == "url"
        for result in results
    )
    assert all(urlsplit(call).hostname == HOST for call in requester.calls)
    assert not any(urlsplit(call).path == "/sitemap.xml" for call in requester.calls)


def test_fast_scan_follows_a_linked_folder_and_probes_redirect_filenames():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path == "/":
            return Observation(status_code=200, body='<a href="/offers">Offers</a>' if include_body else None)
        if parts.path == "/offers":
            return Observation(status_code=200, body="<html></html>" if include_body else None)
        if parts.path == "/offers/tracking.php":
            target = parse_qs(parts.query).get("url", [""])[0]
            if target.startswith("//google.com/") or "%2e%2e" in target:
                return Observation(status_code=302, location_header=target)
            return Observation(status_code=302, location_header=f"https://{HOST}/offers")
        return Observation(status_code=404, body="missing" if include_body else None)

    results = scan_urls([f"https://{HOST}/"], _config("fast"), ScriptedRequester(app))
    assert any(
        result.original_url.endswith("/offers/tracking.php")
        and result.result == Verdict.POTENTIAL.value
        and result.tested_parameter == "url"
        and result.payload.startswith("//google.com/")
        for result in results
    )


def test_a_linked_url_teaches_the_scanner_an_unknown_parameter():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path == "/":
            body = '<a href="/widget/9/open?hop=https%3A%2F%2Fshop.example%2Fitem">go</a>'
            return Observation(status_code=200, body=body if include_body else None)
        target = parse_qs(parts.query).get("hop", [""])[0]
        if "google.com" in target:
            return Observation(status_code=302, location_header="https://www.google.com/")
        return Observation(status_code=404, body="missing" if include_body else None)

    results = scan_urls([f"https://{HOST}/"], _config("fast"), ScriptedRequester(app))
    assert any(result.result == Verdict.POTENTIAL.value and result.tested_parameter == "hop" for result in results)


def test_fast_scan_makes_fewer_payload_requests_than_the_old_full_matrix():
    def app(url: str, include_body: bool = False) -> Observation:
        return Observation(status_code=204)

    requester = ScriptedRequester(app)
    scan_urls([f"https://{HOST}/login"], _config("fast"), requester)
    fast_profile = profile_for("fast")
    old_matrix = len(fast_profile.parameters) * 6
    payload_calls = [call for call in requester.calls if "google" in call.lower() or "%2F" in call or "%2f" in call]
    assert len(payload_calls) <= len(fast_profile.parameters) * len(fast_profile.payloads)
    assert len(payload_calls) < old_matrix
