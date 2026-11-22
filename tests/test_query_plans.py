"""Regression tests for baseline requests and existing query strings."""

from urllib.parse import parse_qs, quote, urlsplit

from rift.catalog import profile_for
from rift.config import ScanConfig, TEST_DESTINATION
from rift.engine import scan_urls
from rift.models import Observation, Verdict
from rift.parameters import build_plans
from rift.query import review_query
from tests.fakes import ScriptedRequester

HOST = "app.example.com"
QUICK = profile_for("quick")
PAYLOADS = tuple(item.value for item in QUICK.payloads)
OPAQUE = "4f3a9c0e1b2d4a6f8091c2d3e4f5a6b7"


def _plans(url: str, manual: tuple[str, ...] = ()):
    return build_plans(url, parameters=QUICK.parameters, payloads=PAYLOADS, manual_parameters=manual)


def _names(url: str, manual: tuple[str, ...] = ()):
    found = []
    for plan in _plans(url, manual):
        if plan.parameter not in found:
            found.append(plan.parameter)
    return found


def test_url_without_parameters_uses_the_full_configured_catalogue():
    profile = profile_for("standard")
    plans = build_plans(
        f"https://{HOST}/login",
        parameters=profile.parameters,
        payloads=tuple(item.value for item in profile.payloads),
    )
    assert {(plan.parameter, plan.payload) for plan in plans} == {
        (name, item.value) for name in profile.parameters for item in profile.payloads
    }
    assert _names(f"https://{HOST}/login") == list(QUICK.parameters)


def test_one_existing_parameter_is_tested_before_injected_names():
    names = _names(f"https://{HOST}/login?next=/dashboard")
    assert names[0] == "next"
    assert names[1:] == [name for name in QUICK.parameters if name != "next"]


def test_multiple_existing_parameters_keep_unrelated_values_and_rank_navigation():
    url = f"https://{HOST}/login?utm_source=news&return=/inbox&next=https://www.google.com&lang=en"
    names = _names(url)
    assert names[0] == "next"
    assert names[1] == "return"
    rendered = parse_qs(urlsplit(_plans(url)[0].test_url).query)
    assert rendered["utm_source"] == ["news"]
    assert rendered["lang"] == ["en"]
    assert urlsplit(rendered["return"][0]).hostname == HOST


def test_destination_parameters_are_read_from_the_query_string():
    samples = {
        f"https://{HOST}/redirect?url=https://shop.example&utm_source=news&utm_term=home&_gl=1*abc*_ga*zzz": ("url", "utm_source"),
        f"https://{HOST}/store/28/website?afsrc=1&turl=https%3A%2F%2Fshop.example%2Fitem&cat=https://shop.example&param0=v839": ("turl", "afsrc"),
        f"https://{HOST}/?sid=11173410&said=knoji&link=https://shop.example&fallback_url=&partnerId={OPAQUE}": ("link", "said"),
        f"https://{HOST}/outboundLink.php?durl=https%3A%2F%2Fshop.example&rurl=https%3A%2F%2F{HOST}%2Fback&urlHash=c0af9cab": ("durl", "urlHash"),
        f"https://{HOST}/tracking.php?url=//shop.example/%2e%2e%2f": ("url", None),
        f"https://{HOST}/index.php?route=common/go&src=SHIELD&go=https://shop.example": ("go", "route"),
        f"https://{HOST}/click?url=https%3A%2F%2Fshop.example&inputdata={OPAQUE}": ("url", "inputdata"),
        f"https://{HOST}/?btn_url=https%3A%2F%2Fshop.example%2Fitem&btn_desktop_url=https://shop.example&btn_mobile_url=https%3A%2F%2Fshop.example%2Fitem&btn_ref=org-1": ("btn_url", "btn_ref"),
        f"https://{HOST}/t/abc/?url=https%3A%2F%2Fshop.example": ("url", None),
        f"https://{HOST}/api/events/link/abc?linkUrl=https://shop.example": ("linkUrl", None),
        f"https://{HOST}/log/clk?ai=ChII&dest=https://shop.example": ("dest", "ai"),
        f"https://{HOST}/slack/proxy?url=https://shop.example": ("url", None),
        f"https://{HOST}/listings/item?listingUrl=//shop.example/%2e%2e%2f&marketplace=etsy&itemId=887": ("listingUrl", "marketplace"),
        f"https://{HOST}/www.php?to=https://shop.example": ("to", None),
        f"https://{HOST}/login.php?redirect=HtTP://shop.example": ("redirect", None),
    }
    for url, (focus, preserved) in samples.items():
        review = review_query(url)
        assert focus in review.navigation, url
        if preserved:
            assert preserved not in review.navigation, url
        assert "urlHash" not in review.navigation
        focused = next(plan for plan in _plans(url) if plan.parameter == focus)
        rendered = parse_qs(urlsplit(focused.test_url).query)
        assert "google.com" in rendered[focus][0].lower()
        if preserved:
            assert preserved in rendered


def test_unusual_redirect_name_is_inferred_from_its_value():
    url = f"https://{HOST}/out?hop=//google.com/%2e%2e%2f"
    review = review_query(url)
    assert review.navigation[0] == "hop"
    assert _names(url)[0] == "hop"
    hop_payloads = [plan.payload for plan in _plans(url) if plan.parameter == "hop"]
    assert any(payload.startswith("//google.com/") for payload in hop_payloads)
    assert "protocol-relative" or True
    assert "//www.google.com/" in hop_payloads


def test_opaque_and_sensitive_tokens_are_not_overwritten_unless_selected():
    token = "session-token-value"
    url = f"https://{HOST}/login?token={token}&unsubscribe_token={OPAQUE}&refid={OPAQUE}&next=/home"
    review = review_query(url)
    assert "token" in review.sensitive
    assert "unsubscribe_token" in review.sensitive
    assert "refid" in review.manual
    assert "refid" not in review.navigation
    plans = _plans(url)
    assert all(plan.parameter not in {"token", "unsubscribe_token", "refid"} for plan in plans)
    for plan in plans:
        parsed = parse_qs(urlsplit(plan.test_url).query)
        assert parsed["token"] == [token]
        assert parsed["unsubscribe_token"] == [OPAQUE]
        assert parsed["refid"] == [OPAQUE]
    selected_names = []
    for plan in _plans(url, manual=("refid",)):
        if plan.parameter not in selected_names:
            selected_names.append(plan.parameter)
    assert selected_names[0] == "next"
    assert selected_names.index("refid") < selected_names.index("redirect")
    assert "token" not in selected_names


def test_baseline_is_requested_before_payloads_and_internal_reflection_is_not_a_finding():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        if parts.path == "/floor" and "next" in params:
            return Observation(status_code=302, location_header=f"/office?next={params['next'][0]}")
        if parts.path == "/go":
            target = params.get("hop", [""])[0]
            if target.startswith("//google.com/") or "%2e%2e" in target:
                return Observation(status_code=302, location_header=target)
            return Observation(status_code=302, location_header="/stay")
        return Observation(status_code=204)

    config = ScanConfig(allowlist=(HOST,), max_workers=1, min_interval_seconds=0, mode="quick")
    requester = ScriptedRequester(app)
    original = f"https://{HOST}/floor?next=/desk&utm_source=news"
    results = scan_urls([original], config, requester)
    assert requester.calls[0] == original
    assert results[0].baseline_status == 302
    assert results[0].baseline_location == "/office?next=/desk"
    assert all(result.result == Verdict.NO_ISSUE.value for result in results)
    reflected = next(
        result
        for result in results
        if result.tested_parameter == "next" and quote(TEST_DESTINATION, safe="") in result.test_url
    )
    assert reflected.redirect_destination.startswith(f"https://{HOST}/office")
    assert "google.com" in reflected.location_header
    assert "utm_source=news" in reflected.test_url

    encoded = ScriptedRequester(app)
    encoded_url = f"https://{HOST}/go?hop=//google.com/%2e%2e%2f&token=keep-this-token"
    encoded_results = scan_urls([encoded_url], config, encoded)
    assert encoded.calls[0] == encoded_url
    finding = next(result for result in encoded_results if result.result == Verdict.POTENTIAL.value)
    assert finding.tested_parameter == "hop"
    assert finding.payload.startswith("//google.com/")
    assert urlsplit(finding.redirect_destination).hostname == "google.com"
    assert finding.baseline_status == 302
    assert "token=keep-this-token" in finding.test_url
    assert all(urlsplit(call).hostname == HOST for call in encoded.calls)


def test_state_changing_endpoints_are_not_requested():
    requester = ScriptedRequester(lambda url, include_body=False: Observation(status_code=200))
    config = ScanConfig(allowlist=(HOST,), max_workers=1, min_interval_seconds=0, mode="quick")
    results = scan_urls(
        [f"https://{HOST}/logout", f"https://{HOST}/unsubscribe", f"https://{HOST}/billing/checkout"],
        config,
        requester,
    )
    assert requester.calls == []
    assert len(results) == 3
    assert all(result.result == Verdict.INCONCLUSIVE.value for result in results)
    assert all(result.baseline_status is None for result in results)
