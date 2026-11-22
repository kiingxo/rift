"""CWE-601 open-redirect scanner."""

from __future__ import annotations

import threading
from typing import Callable, Sequence

from rift.config import ScanConfig
from rift.engine import ProgressCallback, Requester, scan_urls
from rift.models import ScanResult


class OpenRedirectScanner:
    check_id = "open-redirect"
    title = "Open redirect (CWE-601)"

    def run(
        self,
        urls: Sequence[str],
        config: ScanConfig,
        requester: Requester | None = None,
        on_progress: ProgressCallback | None = None,
        on_finding: Callable[[ScanResult], None] | None = None,
        cancel: threading.Event | None = None,
        pause: threading.Event | None = None,
    ) -> list[ScanResult]:
        return scan_urls(
            list(urls),
            config,
            requester=requester,
            on_progress=on_progress,
            on_finding=on_finding,
            cancel=cancel,
            pause=pause,
        )
