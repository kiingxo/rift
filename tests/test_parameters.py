from urllib.parse import parse_qs, urlsplit

from rift.catalog import profile_for
from rift.config import TEST_DESTINATION
from rift.parameters import build_plans

HOST = "app.example.com"


def _query(url: str) -> dict:
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


def test_every_candidate_is_planned_and_existing_names_come_first():
    profile = profile_for("standard")
    plans = build_plans(
        f"https://{HOST}/login?utm=newsletter&next=/home",
        parameters=profile.parameters,
        payloads=tuple(item.value for item in profile.payloads),
    )
    ordered = []
    for plan in plans:
        if plan.parameter.lower() not in ordered:
            ordered.append(plan.parameter.lower())
    assert ordered[0] == "next"
    assert ordered == ["next"] + [name.lower() for name in profile.parameters if name.lower() != "next"]
    next_payloads = [plan.payload for plan in plans if plan.parameter == "next"]
    assert next_payloads[:2] == [item.value for item in profile.payloads[:2]]


def test_unrelated_parameters_are_preserved_and_other_redirects_are_neutralized():
    profile = profile_for("quick")
    plans = build_plans(
        f"https://{HOST}/login?utm=a&next=https://evil.example/phish",
        parameters=profile.parameters,
        payloads=tuple(item.value for item in profile.payloads),
    )
    by_name = {plan.parameter.lower(): plan for plan in plans if plan.payload == TEST_DESTINATION}
    next_test = _query(by_name["next"].test_url)
    assert next_test["utm"] == ["a"]
    assert next_test["next"] == [TEST_DESTINATION]
    assert "evil.example" not in by_name["next"].test_url

    injected = _query(by_name["redirect"].test_url)
    assert injected["utm"] == ["a"]
    assert injected["redirect"] == [TEST_DESTINATION]
    assert urlsplit(injected["next"][0]).hostname == HOST
    assert "evil.example" not in by_name["redirect"].test_url

    control = _query(by_name["next"].control_url)
    assert urlsplit(control["next"][0]).hostname == HOST
    assert TEST_DESTINATION not in by_name["next"].control_url
