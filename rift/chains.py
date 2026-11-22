"""Follow a short in-scope redirect chain.

External Location values are recorded and are not requested. A hop that stays
on the confirmed domain, including a canonical hop from the apex host to www,
is requested, because that response can forward to the canary.
"""

from __future__ import annotations

from typing import Protocol
from urllib.parse import urlsplit

from rift.classify import REDIRECT_STATUSES, destination_host, is_google_destination, resolve_redirect
from rift.config import ScanConfig
from rift.models import Observation
from rift.safety import ScopeError, host_is_allowlisted, validate_target


class ChainRequester(Protocol):
    def get(self, url: str, include_body: bool = False) -> Observation:
        """Perform one GET."""


def follow_same_origin(
    observation: Observation,
    request_url: str,
    requester: ChainRequester,
    config: ScanConfig,
    hops: int,
) -> tuple[Observation, str]:
    """Return the observation that decides the verdict, plus a chain description."""

    if hops <= 0 or observation.error or observation.safety_block:
        return observation, _format(observation)
    if observation.status_code not in REDIRECT_STATUSES:
        return observation, _format(observation)

    current = observation
    current_url = request_url
    parts = [_format(current)]
    for _ in range(hops):
        absolute, problem = resolve_redirect(current_url, current.location_header)
        if problem or not absolute or is_google_destination(absolute):
            break
        host = destination_host(absolute)
        scanned = destination_host(current_url)
        if not host or not scanned:
            break
        if host != scanned and not host_is_allowlisted(host, config.allowlist):
            break
        try:
            nxt_url = validate_target(absolute, config)
        except ScopeError:
            break
        if urlsplit(nxt_url).geturl() == urlsplit(current_url).geturl():
            break
        nxt = requester.get(nxt_url, include_body=False)
        parts.append(_format(nxt))
        if nxt.error or nxt.safety_block or nxt.status_code not in REDIRECT_STATUSES:
            break
        current = nxt
        current_url = nxt_url
    chain = " → ".join(part for part in parts if part)
    return current, chain


def _format(observation: Observation) -> str:
    if observation.status_code is None and observation.error:
        return observation.error
    location = observation.location_header or ""
    if observation.status_code is None:
        return location
    if location:
        return f"{observation.status_code} {location}"
    return str(observation.status_code)
