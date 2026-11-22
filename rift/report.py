"""CSV and JSON reports for a completed scan."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Sequence

from rift.config import TEST_DESTINATION, TOOL_NAME, VERSION
from rift.models import ScanResult, Verdict

AUTHORIZATION_STATEMENT = (
    "I confirm that I own or have explicit authorisation to perform security testing "
    "on all domains and URLs included in this scan."
)

CSV_FIELDS = (
    "original_url",
    "tested_parameter",
    "payload",
    "test_url",
    "http_status",
    "location_header",
    "redirect_destination",
    "result",
    "explanation",
    "remediation",
    "control_url",
    "control_http_status",
    "control_location",
    "control_redirect_destination",
    "check",
    "redirect_chain",
    "baseline_status",
    "baseline_location",
    "baseline_error",
    "domain",
    "confidence",
    "detection_method",
    "authorization_acknowledged",
    "authorization_statement",
    "authorization_acknowledged_at",
    "authorized_domains",
)


def summarize(results: Sequence[ScanResult]) -> dict[str, int]:
    counts = {verdict.value: 0 for verdict in Verdict}
    for result in results:
        counts[result.result] = counts.get(result.result, 0) + 1
    counts["total"] = len(results)
    return counts


def to_csv(results: Sequence[ScanResult], *, authorization: dict[str, object] | None = None) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    acknowledgement = _authorization_fields(authorization)
    for result in results:
        row = result.as_dict()
        row.update(acknowledgement)
        writer.writerow({field: "" if row.get(field) is None else row.get(field) for field in CSV_FIELDS})
    return buffer.getvalue()


def _authorization_fields(authorization: dict[str, object] | None) -> dict[str, object]:
    if not authorization:
        return {
            "authorization_acknowledged": "",
            "authorization_statement": "",
            "authorization_acknowledged_at": "",
            "authorized_domains": "",
        }
    domains = authorization.get("domains") or []
    joined = ";".join(str(domain) for domain in domains)
    return {
        "authorization_acknowledged": "yes" if authorization.get("acknowledged") else "no",
        "authorization_statement": authorization.get("statement") or "",
        "authorization_acknowledged_at": authorization.get("acknowledged_at") or "",
        "authorized_domains": joined,
    }


def to_json(
    results: Sequence[ScanResult],
    *,
    allowlist: Sequence[str],
    generated_at: str | None = None,
    authorization: dict[str, object] | None = None,
) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "check": "CWE-601",
        "generated_at": generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "test_destination": TEST_DESTINATION,
        "allowlist": list(allowlist),
        "authorization": authorization
        or {
            "acknowledged": False,
            "statement": AUTHORIZATION_STATEMENT,
            "acknowledged_at": "",
            "domains": [],
        },
        "summary": summarize(results),
        "results": [result.as_dict() for result in results],
    }
    return json.dumps(payload, indent=2) + "\n"
