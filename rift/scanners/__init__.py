"""Registered vulnerability checks.

Add a scanner by implementing rift.extensions.VulnerabilityScanner
and including it in available_scanners().
"""

from __future__ import annotations

from rift.scanners.open_redirect import OpenRedirectScanner


def available_scanners() -> tuple[type, ...]:
    return (OpenRedirectScanner,)


__all__ = ["OpenRedirectScanner", "available_scanners"]
