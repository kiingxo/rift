"""Extension points for later scanners and explanation providers.

AI explanations are intentionally not implemented. A later provider can
implement ExplanationProvider and read ScanResult records; it should not
change which verdict the HTTP evidence produced.
"""

from __future__ import annotations

from typing import Protocol, Sequence

from rift.config import ScanConfig
from rift.models import ScanResult


class ExplanationProvider(Protocol):
    def explain(self, result: ScanResult) -> str:
        """Return a narrative for one finding."""


class RemediationProvider(Protocol):
    def suggest(self, result: ScanResult) -> str:
        """Return remediation text for one finding."""


class VulnerabilityScanner(Protocol):
    check_id: str
    title: str

    def run(self, urls: Sequence[str], config: ScanConfig) -> list[ScanResult]:
        """Scan authorised URLs and return structured results."""
