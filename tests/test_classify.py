from __future__ import annotations

import pytest

from rift.config import TEST_DESTINATION
from rift.classify import judge, resolve_redirect
from rift.models import Observation, Verdict

HOST = "app.example.com"
ORIGINAL = f"https://{HOST}/login"
TEST_URL = f"{ORIGINAL}?next={TEST_DESTINATION}"
CONTROL_URL = f"{ORIGINAL}?next=https://{HOST}/__blueprint_redirect_control__"
ALLOW = (HOST,)


def _judge(test: Observation, control: Observation | None = None, allowlist=ALLOW):
    return judge(
        original_url=ORIGINAL,
        parameter="next",
        test_url=TEST_URL,
        control_url=CONTROL_URL,
        test=test,
        control=control,
        allowlist=allowlist,
    )


def test_relative_location_stays_on_the_scanned_host():
    absolute, problem = resolve_redirect(
        f"https://{HOST}/floor",
        "/office?next=https://www.google.com",
    )
    assert problem is None
    assert absolute == f"https://{HOST}/office?next=https://www.google.com"


def test_protocol_relative_location_resolves_to_google():
    absolute, problem = resolve_redirect(f"https://{HOST}/login", "//www.google.com")
    assert problem is None
    assert absolute == "https://www.google.com"


def test_encoded_and_backslash_locations_resolve_to_google():
    base = f"https://{HOST}/newsletter/tracking.php"
    encoded, problem = resolve_redirect(base, "//google.com/%2e%2e%2f")
    assert problem is None
    assert encoded.startswith("https://google.com/")
    slashes, problem = resolve_redirect(base, "/\\www.google.com/")
    assert problem is None
    assert slashes.startswith("https://www.google.com/")
    double, problem = resolve_redirect(base, "%252f%252fwww.google.com/")
    assert problem is None
    assert double.startswith("https://www.google.com/")


def test_internal_query_is_not_reclassified_by_decoding():
    absolute, problem = resolve_redirect(
        f"https://{HOST}/floor",
        "/office?next=%2f%2fwww.google.com",
    )
    assert problem is None
    assert absolute.startswith(f"https://{HOST}/office")


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_to_google_is_a_potential_vulnerability_when_control_stays_inside(status):
    result = _judge(
        Observation(status_code=status, location_header="https://www.google.com"),
        Observation(status_code=302, location_header=f"https://{HOST}/__blueprint_redirect_control__"),
    )
    assert result.result == Verdict.POTENTIAL.value
    assert result.tested_parameter == "next"
    assert "CWE-601" in result.explanation
    assert result.redirect_destination == "https://www.google.com"


def test_google_canary_is_still_flagged_if_google_was_added_to_the_allowlist():
    result = _judge(
        Observation(status_code=302, location_header="https://www.google.com/search"),
        Observation(status_code=200),
        allowlist=(HOST, "www.google.com"),
    )
    assert result.result == Verdict.POTENTIAL.value


def test_internal_reflection_of_google_is_not_a_vulnerability():
    result = _judge(
        Observation(status_code=302, location_header="/office?next=https://www.google.com"),
    )
    assert result.result == Verdict.NO_ISSUE.value
    assert result.redirect_destination == f"https://{HOST}/office?next=https://www.google.com"
    assert "authorised URL" in result.explanation
    assert "secure" in result.remediation.lower() or "not a verdict" in result.remediation


def test_userinfo_redirect_to_google_is_a_vulnerability():
    result = _judge(
        Observation(status_code=302, location_header=f"https://{HOST}@www.google.com/"),
        Observation(status_code=302, location_header=f"https://{HOST}/home"),
    )
    assert result.result == Verdict.POTENTIAL.value


def test_userinfo_that_stays_on_the_site_is_not_a_vulnerability():
    result = _judge(
        Observation(status_code=302, location_header=f"https://www.google.com@{HOST}/home"),
    )
    assert result.result == Verdict.NO_ISSUE.value


def test_trailing_dot_google_host_is_a_vulnerability():
    result = _judge(
        Observation(status_code=302, location_header="https://www.google.com."),
        Observation(status_code=302, location_header=f"https://{HOST}/home"),
    )
    assert result.result == Verdict.POTENTIAL.value


def test_both_values_redirecting_to_google_are_inconclusive():
    result = _judge(
        Observation(status_code=302, location_header="https://www.google.com"),
        Observation(status_code=302, location_header="https://google.com"),
    )
    assert result.result == Verdict.INCONCLUSIVE.value
    assert "does not depend" in result.explanation


def test_control_failure_is_inconclusive():
    result = _judge(
        Observation(status_code=302, location_header="https://www.google.com"),
        Observation(error="Request timed out"),
    )
    assert result.result == Verdict.INCONCLUSIVE.value


def test_timeout_is_inconclusive():
    result = _judge(Observation(error="Request timed out"))
    assert result.result == Verdict.INCONCLUSIVE.value
    assert result.http_status is None


def test_redirect_without_location_is_inconclusive():
    result = _judge(Observation(status_code=302, location_header=None))
    assert result.result == Verdict.INCONCLUSIVE.value


def test_ordinary_response_is_not_a_finding():
    result = _judge(Observation(status_code=200))
    assert result.result == Verdict.NO_ISSUE.value
    assert result.redirect_destination is None


def test_unexpected_external_host_is_inconclusive():
    result = _judge(Observation(status_code=302, location_header="https://cdn.example.net/app"))
    assert result.result == Verdict.INCONCLUSIVE.value
    assert "www.google.com" in result.explanation


def test_non_redirect_status_with_a_google_location_is_not_flagged():
    result = _judge(Observation(status_code=200, location_header="https://www.google.com"))
    assert result.result == Verdict.NO_ISSUE.value
