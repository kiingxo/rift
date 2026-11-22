import csv
import json

from rift.config import TEST_DESTINATION
from rift.models import ScanResult, Verdict
from rift.report import summarize, to_csv, to_json


def _sample() -> ScanResult:
    return ScanResult(
        original_url="https://app.example.com/login",
        tested_parameter="next",
        test_url="https://app.example.com/login?next=https%3A%2F%2Fwww.google.com",
        http_status=302,
        location_header="https://www.google.com",
        redirect_destination="https://www.google.com",
        result=Verdict.POTENTIAL.value,
        explanation='The parameter "next" left the site.',
        remediation="Allow only relative paths.",
        control_url="https://app.example.com/login?next=https%3A%2F%2Fapp.example.com%2F",
        control_http_status=302,
        control_location="https://app.example.com/home",
        control_redirect_destination="https://app.example.com/home",
    )


def test_csv_contains_the_evidence_and_escapes_quotes():
    text = to_csv([_sample()])
    rows = list(csv.DictReader(text.splitlines()))
    assert rows[0]["tested_parameter"] == "next"
    assert rows[0]["result"] == "Potential Vulnerability"
    assert rows[0]["http_status"] == "302"
    assert "relative paths" in rows[0]["remediation"]
    assert "next" in rows[0]["explanation"]


def test_json_report_names_the_tool_and_preserves_nulls():
    missing = ScanResult(
        original_url="https://example.com",
        tested_parameter="",
        test_url="",
        http_status=None,
        location_header=None,
        redirect_destination=None,
        result=Verdict.INCONCLUSIVE.value,
        explanation="Not scanned.",
        remediation="Add the domain only if authorised.",
    )
    payload = json.loads(to_json([_sample(), missing], allowlist=["app.example.com"]))
    assert payload["tool"] == "Rift"
    assert "vendor" not in payload
    assert payload["check"] == "CWE-601"
    assert payload["test_destination"] == TEST_DESTINATION
    assert payload["results"][1]["http_status"] is None
    assert summarize(payload and [_sample(), missing])["Potential Vulnerability"] == 1
