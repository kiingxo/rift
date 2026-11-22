"""Shared plumbing for checks: what a check receives and how it reports."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import urlsplit

from rift.config import ScanConfig
from rift.models import CheckNote, Finding, Observation

# A check that reads responses the scan already has.
PASSIVE = "passive"
# A check that sends a small number of extra read-only requests.
PROBE = "probe"


@dataclass
class CheckContext:
    """Everything one check needs for one origin."""

    origin: str
    config: ScanConfig
    pages: list[Observation]
    scripts: list[Observation]
    fetcher: Callable[..., Observation]
    deep: bool = False
    resolver: Callable[[str, int], list[str]] | None = None
    notes: list[CheckNote] = field(default_factory=list)
    shared: dict[str, object] = field(default_factory=dict)
    # The test account's session (rift.session.SignedInSession) for a signed-in scan.
    session: object = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def host(self) -> str:
        return urlsplit(self.origin).hostname or ""

    @property
    def is_https(self) -> bool:
        return self.origin.startswith("https://")

    @property
    def documents(self) -> list[Observation]:
        """Pages that returned an HTML document."""

        return [page for page in self.pages if page.status_code == 200 and is_html(page)]

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        include_body: bool = True,
        signed_in: bool = False,
        app_read: bool = False,
    ) -> Observation:
        """A read-only request. Anonymous unless signed_in is set and the scan has a session.

        app_read marks an address the app's own JavaScript reads with GET (see rift.endpoints).
        """

        if signed_in and app_read:
            return self.fetcher(url, method=method, headers=headers, include_body=include_body, signed_in=True, app_read=True)
        if signed_in:
            return self.fetcher(url, method=method, headers=headers, include_body=include_body, signed_in=True)
        return self.fetcher(url, method=method, headers=headers, include_body=include_body)

    def note(self, check: str, detail: str, url: str = "") -> None:
        with self._lock:
            self.notes.append(CheckNote(check=check, url=url or self.origin, detail=detail))


class Check:
    """Base class. A check looks at one origin and returns findings.

    A check must never raise for a hostile or broken response. It must not send
    anything other than the read-only requests available through ctx.fetch.
    """

    id = ""
    title = ""
    summary = ""
    kind = PASSIVE
    default = True
    # False for checks that still have something to say about a host that did not answer.
    needs_pages = True

    def run(self, ctx: CheckContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def finding(self, ctx: CheckContext, **fields) -> Finding:
        url = fields.pop("url", "") or ctx.origin
        return Finding(check=self.id, url=url, domain=ctx.host, **fields)


def is_html(page: Observation) -> bool:
    kind = page.content_type
    if kind:
        return kind in {"text/html", "application/xhtml+xml"}
    body = (page.body or "")[:400].lower()
    return "<html" in body or "<!doctype html" in body


def is_json(page: Observation) -> bool:
    kind = page.content_type
    return kind == "application/json" or kind.endswith("+json")


def clip(text: str, limit: int = 300) -> str:
    cleaned = " ".join(str(text).split())
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def redact(secret: str, keep_start: int = 6, keep_end: int = 2) -> str:
    """Show enough of a secret to find it, never enough to use it."""

    value = secret.strip()
    if len(value) <= keep_start + keep_end + 4:
        return value[:2] + "…" + f" ({len(value)} characters)"
    return f"{value[:keep_start]}…{value[-keep_end:]} ({len(value)} characters)"


def merge_by_title(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse the same issue on many pages of one origin into one finding."""

    merged: dict[tuple[str, str, str], Finding] = {}
    for item in findings:
        key = (item.check, item.title, item.domain)
        kept = merged.get(key)
        if kept is None:
            if item.url and item.url not in item.affected_urls:
                item.affected_urls.insert(0, item.url)
            merged[key] = item
            continue
        for url in [item.url, *item.affected_urls]:
            if url and url not in kept.affected_urls:
                kept.affected_urls.append(url)
        if item.rank < kept.rank:
            kept.severity = item.severity
    return list(merged.values())
