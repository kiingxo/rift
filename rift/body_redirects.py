"""Read client-side redirects from HTML and script text.

This does not execute JavaScript and does not request the destination.
A meta refresh or a literal location assignment is evidence. A normal link
to an external site is not.
"""

from __future__ import annotations

import re

_META_HTTP = re.compile(
    r"""<meta\b[^>]*http-equiv\s*=\s*["']?\s*refresh\s*["']?[^>]*>""",
    re.IGNORECASE,
)
_META_CONTENT = re.compile(
    r"""content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_META_URL = re.compile(r"""url\s*=\s*([^;]+)""", re.IGNORECASE)
_SCRIPT_LOCATION = re.compile(
    r"""(?:window\.)?location(?:\s*\.\s*(?:href|assign|replace))?\s*(?:=|\()\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def extract_client_redirect(body: str | None) -> str | None:
    if not body:
        return None
    sample = body[:200_000]
    for tag in _META_HTTP.findall(sample):
        content = _META_CONTENT.search(tag)
        if not content:
            continue
        target = _META_URL.search(content.group(1))
        if target:
            value = target.group(1).strip().strip("'\"")
            if value:
                return value
    match = _SCRIPT_LOCATION.search(sample)
    if match:
        value = match.group(1).strip()
        if value:
            return value
    return None
