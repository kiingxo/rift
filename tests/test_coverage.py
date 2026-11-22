"""Payload bypasses, discovery, chains, and false-positive regressions."""

import json
from urllib.parse import parse_qs, quote, urlsplit

from rift.body_redirects import extract_client_redirect
from rift.catalog import is_signal_payload, profile_for
from rift.config import ScanConfig, TEST_DESTINATION
from rift.engine import scan_urls
from rift.models import Observation, Verdict
from rift.parameters import build_plans
from tests.fakes import ScriptedRequester

HOST = "app.example.com"


def _config(mode: str) -> ScanConfig:
    return ScanConfig(allowlist=(HOST,), max_workers=1, min_interval_seconds=0, mode=mode)


def test_an_unchanged_page_stops_after_the_signal_payloads():
    notes: list[str] = []
    requester = ScriptedRequester(lambda url, include_body=False: Observation(status_code=204))

    def record(done: int, total: int, detail: str) -> None:
        notes.append(detail)

    scan_urls([f"https://{HOST}/login"], _config("standard"), requester, on_progress=record)
    assert any(note.startswith("Checking ") and " · parameter " in note for note in notes)
    assert any("https%3A%2F%2Fwww.google.com" in call for call in requester.calls)
    assert not any("http%3A%2F%2Fwww.google.com" in call for call in requester.calls)
    profile = profile_for("standard")
    assert sum(1 for item in profile.payloads if is_signal_payload(item.value)) < len(profile.payloads)


def test_catalog_modes_grow_without_dropping_the_canary():
    fast = profile_for("fast")
    deep = profile_for("deep")
    assert fast.name == "fast" and deep.name == "deep"
    assert profile_for("quick").name == "fast"
    assert profile_for("standard").name == "deep"
    assert {item.id for item in fast.payloads} <= {item.id for item in deep.payloads}
    assert "purl" in fast.parameters
    assert "image_url" in deep.parameters
    assert "image_url" not in fast.parameters
    assert any(item.value == "//google.com/%2e%2e%2f" for item in deep.payloads)
    assert any(item.value == "https://www.google.com" for item in fast.payloads)
    assert fast.discover is True
    assert fast.probes == ()
    assert fast.fetch_scripts is False
    assert deep.discover is True
    assert deep.fetch_scripts is True
    assert deep.inspect_documents is True


def test_an_existing_bypass_value_is_sent_as_well_as_the_catalog():
    plans = build_plans(
        f"https://{HOST}/newsletter/tracking.php?url=//google.com/%2e%2e%2f",
        parameters=("url",),
        payloads=(TEST_DESTINATION,),
    )
    payloads = [plan.payload for plan in plans]
    assert TEST_DESTINATION in payloads
    assert any(item.startswith("//google.com/") for item in payloads)


def test_encoded_dot_segment_is_a_finding_when_absolute_urls_stay_inside():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        target = parse_qs(parts.query).get("url", [""])[0]
        if target.startswith("//google.com/") or "%2e%2e" in target:
            return Observation(status_code=302, location_header=target)
        return Observation(status_code=302, location_header="/")

    requester = ScriptedRequester(app)
    results = scan_urls(
        [f"https://{HOST}/newsletter/tracking.php"],
        _config("standard"),
        requester,
    )
    findings = [
        result
        for result in results
        if result.result == Verdict.POTENTIAL.value and result.tested_parameter == "url"
    ]
    assert findings
    assert findings[0].payload.startswith("//google.com/")
    assert urlsplit(findings[0].redirect_destination).hostname == "google.com"
    assert all(urlsplit(call).hostname == HOST for call in requester.calls)


def test_same_origin_chain_is_a_finding_and_external_hops_are_not_requested():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        if parts.path == "/chain":
            target = params.get("next", [""])[0]
            return Observation(status_code=302, location_header=f"/chain/hop?next={quote(target, safe='')}")
        if parts.path == "/chain/hop":
            target = params.get("next", [""])[0]
            if target.startswith("//") or target.startswith("https://www.google.com") or target.startswith("http://www.google.com"):
                return Observation(status_code=302, location_header=target)
            return Observation(status_code=200)
        return Observation(status_code=404)

    requester = ScriptedRequester(app)
    results = scan_urls([f"https://{HOST}/chain"], _config("standard"), requester)
    finding = next(result for result in results if result.result == Verdict.POTENTIAL.value and result.tested_parameter == "next")
    assert "/chain/hop" in finding.redirect_chain
    assert urlsplit(finding.redirect_destination).hostname == "www.google.com"
    assert all(urlsplit(call).hostname == HOST for call in requester.calls)
    assert any("/chain/hop" in call for call in requester.calls)


def test_a_canonical_www_hop_still_flags_the_bypass_payload():
    www = f"www.{HOST}"

    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        target = parse_qs(parts.query).get("dest", [""])[0]
        if parts.hostname == HOST:
            query = f"?{parts.query}" if parts.query else ""
            return Observation(status_code=302, location_header=f"https://{www}{parts.path or '/'}{query}")
        if parts.hostname == www and target.startswith("//google.com/"):
            return Observation(status_code=302, location_header=target)
        return Observation(status_code=204, body="<html></html>" if include_body else None)

    requester = ScriptedRequester(app)
    results = scan_urls([f"https://{HOST}/"], _config("standard"), requester)
    assert f"https://{www}/" in results.endpoints
    finding = next(result for result in results if result.result == Verdict.POTENTIAL.value and result.tested_parameter == "dest")
    assert finding.payload.startswith("//google.com/")
    assert urlsplit(finding.redirect_destination).hostname == "google.com"
    assert all(urlsplit(call).hostname in {HOST, www} for call in requester.calls)


def test_an_off_site_redirect_from_the_apex_is_not_requested():
    def app(url: str, include_body: bool = False) -> Observation:
        if urlsplit(url).hostname == HOST:
            return Observation(status_code=302, location_header="https://evil.example/steal")
        return Observation(status_code=200)

    requester = ScriptedRequester(app)
    results = scan_urls([f"https://{HOST}/login"], _config("standard"), requester)
    assert all(urlsplit(call).hostname == HOST for call in requester.calls)
    assert all(result.result != Verdict.POTENTIAL.value for result in results)


def test_an_internal_redirect_that_only_reflects_google_is_not_a_finding():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path == "/floor":
            target = parse_qs(parts.query).get("next", [""])[0]
            return Observation(status_code=302, location_header=f"/office?next={quote(target, safe='')}")
        return Observation(status_code=200)

    results = scan_urls([f"https://{HOST}/floor"], _config("standard"), ScriptedRequester(app))
    assert results
    assert all(result.result in {Verdict.NO_ISSUE.value, Verdict.SKIPPED.value} for result in results)


def test_document_text_that_mentions_google_is_not_a_redirect():
    prose = "<p>Read more at https://www.google.com/search</p>"
    assert extract_client_redirect(prose) is None
    page = '<html><meta http-equiv="refresh" content="0;url=//www.google.com/"></html>'
    assert extract_client_redirect(page) == "//www.google.com/"

    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path != "/meta":
            return Observation(status_code=200, body=prose if include_body else None)
        target = parse_qs(parts.query).get("url", [""])[0]
        if target.startswith("//") or target.startswith("http"):
            body = f'<html><meta http-equiv="refresh" content="0;url={target}"></html>'
            return Observation(status_code=200, body=body if include_body else None)
        return Observation(status_code=200, body=prose if include_body else None)

    article = scan_urls([f"https://{HOST}/article"], _config("deep"), ScriptedRequester(app))
    assert all(result.result in {Verdict.NO_ISSUE.value, Verdict.SKIPPED.value} for result in article)
    meta = scan_urls([f"https://{HOST}/meta"], _config("deep"), ScriptedRequester(app))
    finding = next(result for result in meta if result.result == Verdict.POTENTIAL.value and result.tested_parameter == "url")
    assert finding.http_status == 200
    assert "client-side" in finding.explanation
    assert urlsplit(finding.redirect_destination).hostname == "www.google.com"


def test_the_redirect_path_with_an_existing_google_url_is_a_finding():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path != "/pt-br/redirect":
            return Observation(status_code=404, body="missing" if include_body else None)
        target = parse_qs(parts.query).get("url", [""])[0]
        if target.startswith(("http://", "https://", "//")):
            return Observation(status_code=302, location_header=target)
        return Observation(status_code=302, location_header=f"https://{HOST}/")

    results = scan_urls(
        [f"https://{HOST}/pt-br/redirect?url=https://www.google.com"],
        _config("standard"),
        ScriptedRequester(app),
    )
    finding = next(
        result
        for result in results
        if result.result == Verdict.POTENTIAL.value and result.tested_parameter == "url"
    )
    assert urlsplit(finding.redirect_destination).hostname == "www.google.com"


def test_a_homepage_scan_finds_the_locale_redirect_endpoint():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path == "/":
            return Observation(status_code=200, body='<a href="/pt-br">BR</a>' if include_body else None)
        if parts.path == "/pt-br":
            return Observation(status_code=200, body="<html></html>" if include_body else None)
        if parts.path == "/pt-br/redirect":
            target = parse_qs(parts.query).get("url", [""])[0]
            if target.startswith(("http://", "https://", "//")):
                return Observation(status_code=302, location_header=target)
            return Observation(status_code=200, body="<html>redirect form</html>" if include_body else None)
        return Observation(status_code=404, body="missing" if include_body else None)

    requester = ScriptedRequester(app)
    results = scan_urls([f"https://{HOST}/"], _config("standard"), requester)
    assert f"https://{HOST}/pt-br" not in results.endpoints
    assert f"https://{HOST}/pt-br/redirect" in results.endpoints
    finding = next(
        result
        for result in results
        if result.original_url.endswith("/pt-br/redirect")
        and result.result == Verdict.POTENTIAL.value
        and result.tested_parameter == "url"
    )
    assert urlsplit(finding.redirect_destination).hostname == "www.google.com"
    assert all(urlsplit(call).hostname == HOST for call in requester.calls)


def test_discovery_keeps_the_seed_and_prioritises_redirect_like_paths():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        if parts.path == "/":
            body = '<a href="/about">About</a><a href="/newsletter/tracking.php">Track</a>'
            return Observation(status_code=200, body=body if include_body else None)
        if parts.path == "/sitemap.xml":
            body = f"<urlset><url><loc>https://{HOST}/login</loc></url></urlset>"
            return Observation(status_code=200, body=body if include_body else None)
        if parts.path == "/openapi.json":
            body = json.dumps({"paths": {"/callback": {"get": {"parameters": [{"name": "url", "in": "query"}]}}}})
            return Observation(status_code=200, body=body if include_body else None)
        return Observation(status_code=404)

    results = scan_urls([f"https://{HOST}/"], _config("standard"), ScriptedRequester(app))
    endpoints = results.endpoints
    assert endpoints[0] == f"https://{HOST}/"
    assert f"https://{HOST}/newsletter/tracking.php" in endpoints
    assert f"https://{HOST}/login" in endpoints
    assert f"https://{HOST}/callback?url=1" in endpoints
    assert f"https://{HOST}/about" not in endpoints
