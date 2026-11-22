"""Scan limits, identity, and the default authorised-domain list."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

TOOL_NAME = "Rift"
VENDOR = "Blueprint Labs"
VERSION = "2.0.0"
PROJECT_URL = "https://github.com/kiingxo/rift"
# Sites see who is scanning them and where to read about it.
USER_AGENT = f"RiftScanner/{VERSION} (+{PROJECT_URL})"

TEST_DESTINATION = "https://www.google.com"
GOOGLE_HOSTS = frozenset({"google.com", "www.google.com"})
CONTROL_PATH = "/__blueprint_redirect_control__"
MAX_DOCUMENT_BYTES = 200_000
# A JavaScript bundle is read further: single-page apps ship one or two large files.
MAX_SCRIPT_BYTES = 4_000_000


def tool_root() -> Path:
    return Path(__file__).resolve().parent.parent


def local_allowlist_path() -> Path:
    return tool_root() / "allowlist.local.txt"


def allow_internal_from_env() -> bool:
    """Lab switch for loopback and private addresses.

    Metadata addresses stay blocked even when this is enabled. Set
    RIFT_ALLOW_INTERNAL=1 before starting the process. The older name
    REDIRECT_SCANNER_ALLOW_INTERNAL is still read.
    """

    return env_setting("ALLOW_INTERNAL").strip().lower() in {"1", "true", "yes", "on"}


def env_setting(name: str) -> str:
    """Read RIFT_<name>, falling back to the pre-rename REDIRECT_SCANNER_<name>."""

    return os.environ.get(f"RIFT_{name}") or os.environ.get(f"REDIRECT_SCANNER_{name}", "")


@dataclass(frozen=True)
class ScanConfig:
    allowlist: tuple[str, ...] = ()
    allow_internal: bool = False
    timeout_seconds: float = 8.0
    connect_timeout_seconds: float = 4.0
    dns_timeout_seconds: float = 5.0
    max_workers: int = 8
    per_domain_concurrency: int = 2
    min_interval_seconds: float = 0.25
    max_urls: int = 1000
    max_requests_per_domain: int = 500
    max_endpoints_per_domain: int = 15
    discovery_depth: int = 1
    max_duration_seconds: float = 0
    inspect_documents: bool | None = None
    user_agent: str = USER_AGENT
    mode: str = "standard"
    manual_parameters: tuple[str, ...] = ()
    extra_parameter_names: tuple[str, ...] = ()
    historical_urls: str = ""
    source_root: str = ""
