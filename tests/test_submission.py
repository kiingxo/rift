"""Uploaded and pasted URL lists define the scope of one scan."""

from urllib.parse import urlsplit

from rift.config import ScanConfig
from rift.engine import scan_urls
from rift.models import Observation
from rift.report import AUTHORIZATION_STATEMENT, to_csv, to_json
from rift.targets import parse_url_lines, prepare_submission
from tests.fakes import ScriptedRequester

TEXT = """
# ignored
https://Example.com/login
https://example.com/login
https://other.example/floor
http://127.0.0.1/login
http://169.254.169.254/latest/meta-data
https://example.com/logout
https://example.com/login
"""


def test_a_mixed_file_keeps_public_domains_and_drops_unsafe_urls():
    submission = prepare_submission(parse_url_lines(TEXT))
    assert submission.urls == (
        "https://example.com/login",
        "https://other.example/floor",
    )
    assert submission.domains == ("example.com", "other.example")
    excluded = dict(submission.excluded)
    assert "local" in excluded["http://127.0.0.1/login"].lower() or "IP" in excluded["http://127.0.0.1/login"]
    assert any("169.254.169.254" in url for url in excluded)
    assert "state-changing" in excluded["https://example.com/logout"]


def test_confirmed_domains_are_scanned_without_the_saved_allowlist():
    submission = prepare_submission(parse_url_lines(TEXT))
    requester = ScriptedRequester(lambda url, include_body=False: Observation(status_code=204))
    config = ScanConfig(
        allowlist=submission.domains,
        allow_internal=False,
        max_workers=1,
        min_interval_seconds=0,
        mode="quick",
    )
    scan_urls(list(submission.urls), config, requester)
    hosts = {urlsplit(url).hostname for url in requester.calls}
    assert hosts == {"example.com", "other.example"}


def test_report_records_the_authorisation_acknowledgement():
    authorization = {
        "acknowledged": True,
        "statement": AUTHORIZATION_STATEMENT,
        "acknowledged_at": "2026-10-10T10:00:00+00:00",
        "domains": ["example.com", "other.example"],
    }
    from rift.models import ScanResult, Verdict

    result = ScanResult(
        original_url="https://example.com/login",
        tested_parameter="next",
        test_url="https://example.com/login?next=1",
        http_status=204,
        location_header=None,
        redirect_destination=None,
        result=Verdict.NO_ISSUE.value,
        explanation="No redirect.",
        remediation="Review the parameter.",
    )
    document = to_json([result], allowlist=authorization["domains"], authorization=authorization)
    assert AUTHORIZATION_STATEMENT in document
    assert "2026-10-10T10:00:00+00:00" in document
    assert '"acknowledged": true' in document
    csv_text = to_csv([result], authorization=authorization)
    assert AUTHORIZATION_STATEMENT in csv_text
    assert "example.com;other.example" in csv_text
