"""Shared records for scan evidence and verdicts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Verdict(str, Enum):
    POTENTIAL = "Potential Vulnerability"
    NO_ISSUE = "No Issue Detected"
    INCONCLUSIVE = "Inconclusive"
    SKIPPED = "Skipped"


@dataclass
class Observation:
    """One GET that was not followed past the first response."""

    status_code: int | None = None
    location_header: str | None = None
    error: str | None = None
    safety_block: bool = False
    body: str | None = None
    body_redirect: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    url: str = ""
    # True when the request carried the test account's session.
    signed_in: bool = False

    def header(self, name: str) -> str | None:
        """First value of a response header, matched case-insensitively."""

        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";", 1)[0].strip().lower()


@dataclass
class ScanResult:
    original_url: str
    tested_parameter: str
    test_url: str
    http_status: int | None
    location_header: str | None
    redirect_destination: str | None
    result: str
    explanation: str
    remediation: str
    control_url: str = ""
    control_http_status: int | None = None
    control_location: str | None = None
    control_redirect_destination: str | None = None
    check: str = "open-redirect"
    payload: str = ""
    redirect_chain: str = ""
    baseline_status: int | None = None
    baseline_location: str | None = None
    baseline_error: str = ""
    domain: str = ""
    confidence: str = ""
    detection_method: str = ""

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


@dataclass
class Finding:
    """One issue reported by any check, in a shape every report can print."""

    check: str
    title: str
    severity: str
    url: str
    evidence: str
    explanation: str
    remediation: str
    cwe: str = ""
    owasp: str = ""
    confidence: str = "high"
    domain: str = ""
    reference: str = ""
    affected_urls: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 9)


@dataclass
class CheckNote:
    """A check that could not run, or ran with reduced coverage."""

    check: str
    url: str
    detail: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)
