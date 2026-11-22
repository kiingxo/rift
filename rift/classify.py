"""Decide whether a redirect to the canary is parameter-controlled."""

from __future__ import annotations

from typing import Sequence
from urllib.parse import unquote, urljoin, urlsplit

from rift.config import GOOGLE_HOSTS, TEST_DESTINATION
from rift.models import Observation, ScanResult, Verdict
from rift.safety import ScopeError, host_is_allowlisted

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_VULNERABLE_REMEDIATION = (
    "Stop sending browsers to a client-supplied URL. Allow only relative paths from a "
    "server-side allowlist, or map an opaque token to a destination stored on the server. "
    "After parsing the value, reject absolute URLs, protocol-relative URLs (//host), and "
    "any hostname other than your own. Do not validate redirects by checking whether your "
    "domain appears somewhere in the string."
)

_NO_ISSUE_REMEDIATION = (
    "This payload did not show an open redirect. That is not a verdict that the endpoint "
    "is secure: a different value can still change the destination. If the parameter is "
    "client-controlled, accept only relative paths from a server-side allowlist."
)

_INCONCLUSIVE_REMEDIATION = (
    "The scan could not decide. Review the parameter manually and, if clients supply it, "
    "accept only relative paths from a server-side allowlist."
)

_SCOPE_REMEDIATION = (
    "This request was not sent. Scan the host only after it is on the allowlist and you "
    "are explicitly authorised to test it."
)


def resolve_redirect(request_url: str, location: str | None) -> tuple[str | None, str | None]:
    """Resolve a Location against the request URL.

    Returns (absolute_url, problem). problem is set when the header cannot be
    treated as an http(s) destination. Relative and protocol-relative values
    are resolved here so a query string that merely contains google.com is not
    confused with a navigation to Google.
    """

    if location is None:
        return None, "the response has no Location header"
    if any(character in location for character in "\r\n\x00"):
        return None, "the Location header contains a line break"
    stripped = location.strip()
    if not stripped:
        return None, "the Location header is empty"
    resolved = [_resolve_one(request_url, candidate) for candidate in _interpretations(stripped)]
    for absolute, problem in resolved:
        if absolute and problem is None and destination_host(absolute) in GOOGLE_HOSTS:
            return absolute, None
    return resolved[0]


def _interpretations(value: str) -> list[str]:
    """Browser-shaped readings of one Location value.

    Backslashes, extra leading slashes, and one or two rounds of percent-decoding
    are how filters miss a destination that still navigates to the canary host.
    """

    found: list[str] = []

    def add(item: str) -> None:
        if item and item not in found:
            found.append(item)

    add(value)
    add(value.replace("\\", "/"))
    if "%" in value:
        once = unquote(value)
        add(once)
        add(once.replace("\\", "/"))
        twice = unquote(once)
        add(twice)
        add(twice.replace("\\", "/"))
    for item in list(found):
        add(_collapse_extra_slashes(item))
    return found


def _collapse_extra_slashes(value: str) -> str:
    if not value.startswith("///"):
        return value
    rest = value.lstrip("/")
    host = rest.split("/", 1)[0]
    if "." not in host or any(character.isspace() for character in host):
        return value
    return "//" + rest


def _resolve_one(request_url: str, location: str) -> tuple[str | None, str | None]:
    try:
        absolute = urljoin(request_url, location.strip())
        parts = urlsplit(absolute)
    except ValueError:
        return None, "the Location header could not be parsed"
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return absolute, "the Location value does not resolve to an http(s) URL"
    return absolute, None


def destination_host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.rstrip(".").lower()


def is_google_destination(url: str | None) -> bool:
    return destination_host(url) in GOOGLE_HOSTS


def control_required(observation: Observation, test_url: str) -> bool:
    if observation.error or observation.safety_block:
        return False
    if observation.body_redirect and observation.status_code not in REDIRECT_STATUSES:
        absolute, problem = resolve_redirect(test_url, observation.body_redirect)
        if bool(absolute) and problem is None and is_google_destination(absolute):
            return True
    if observation.status_code not in REDIRECT_STATUSES:
        return False
    absolute, problem = resolve_redirect(test_url, observation.location_header)
    return bool(absolute) and problem is None and is_google_destination(absolute)


def _relation(dest_host: str, scanned_url: str, allowlist: Sequence[str]) -> str:
    scanned = destination_host(scanned_url)
    if scanned and (dest_host == scanned or dest_host.endswith("." + scanned)):
        return "scanned-site"
    try:
        if host_is_allowlisted(dest_host, allowlist):
            return "allowlisted"
    except ScopeError:
        return "external"
    return "external"


def _control_summary(control: Observation, control_url: str) -> tuple[str, str | None]:
    if control.error:
        return f"the control request failed ({control.error})", None
    if control.status_code not in REDIRECT_STATUSES:
        return f"the control responded {control.status_code} and did not redirect to Google", None
    absolute, problem = resolve_redirect(control_url, control.location_header)
    if problem or not absolute:
        return f"the control responded {control.status_code} with an unusable Location header", None
    if is_google_destination(absolute):
        return f"the control also redirected to {absolute}", absolute
    return f"the control redirected to {absolute}", absolute


def judge(
    *,
    original_url: str,
    parameter: str,
    test_url: str,
    control_url: str,
    test: Observation,
    control: Observation | None,
    allowlist: Sequence[str],
    payload: str = TEST_DESTINATION,
) -> ScanResult:
    if test.safety_block:
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=None,
            verdict=Verdict.INCONCLUSIVE.value,
            explanation=test.error or "The request was blocked by the safety policy.",
            remediation=_SCOPE_REMEDIATION,
        )
    if test.error:
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=None,
            verdict=Verdict.INCONCLUSIVE.value,
            explanation=(
                f"The request testing parameter '{parameter}' did not complete ({test.error}). "
                "No redirect was observed, so this result is inconclusive."
            ),
            remediation=_INCONCLUSIVE_REMEDIATION,
        )

    status = test.status_code
    absolute, problem = resolve_redirect(test_url, test.location_header)
    raw_location = test.location_header

    if status not in REDIRECT_STATUSES:
        explanation = (
            f"Parameter '{parameter}' was set to {payload}. "
            f"The server responded {status} and did not issue an HTTP redirect."
        )
        if raw_location and absolute and is_google_destination(absolute):
            explanation += (
                " A Location header pointing at Google was present, but browsers do not "
                "navigate on this status, so it was not flagged."
            )
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=None,
            verdict=Verdict.NO_ISSUE.value,
            explanation=explanation,
            remediation=_NO_ISSUE_REMEDIATION,
        )

    if problem or not absolute:
        detail = problem or "the response has no Location header"
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=None,
            verdict=Verdict.INCONCLUSIVE.value,
            explanation=(
                f"Parameter '{parameter}' was set to {payload}. "
                f"The server responded {status}, but {detail}."
            ),
            remediation=_INCONCLUSIVE_REMEDIATION,
        )

    dest_host = destination_host(absolute)
    if dest_host and is_google_destination(absolute):
        return _judge_google(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            control_url=control_url,
            test=test,
            control=control,
            absolute=absolute,
            dest_host=dest_host,
        )

    if dest_host and _relation(dest_host, original_url, allowlist) in {"scanned-site", "allowlisted"}:
        where = (
            "the site being scanned"
            if _relation(dest_host, original_url, allowlist) == "scanned-site"
            else "an authorised domain"
        )
        explanation = (
            f"Parameter '{parameter}' was set to {payload}. "
            f"The server responded {status} with Location {raw_location!r}, which resolves to {absolute}. "
            f"The destination host is {dest_host}, {where}."
        )
        if raw_location and "google.com" in raw_location.lower():
            explanation += (
                " google.com appears in that Location value only as part of the authorised URL, "
                "so the browser stays on the authorised host."
            )
        explanation += " The endpoint was not flagged."
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=absolute,
            verdict=Verdict.NO_ISSUE.value,
            explanation=explanation,
            remediation=_NO_ISSUE_REMEDIATION,
        )

    return _make(
        original_url=original_url,
        parameter=parameter,
        payload=payload,
        test_url=test_url,
        test=test,
        destination=absolute,
        verdict=Verdict.INCONCLUSIVE.value,
        explanation=(
            f"Parameter '{parameter}' was set to {payload}. "
            f"The server responded {status} with Location {raw_location!r}, which resolves to {absolute} "
            f"(host {dest_host}). That host is outside the authorised site and is not the test "
            "destination www.google.com, so the result is inconclusive."
        ),
        remediation=_INCONCLUSIVE_REMEDIATION,
    )


def _judge_google(
    *,
    original_url: str,
    parameter: str,
    payload: str,
    test_url: str,
    control_url: str,
    test: Observation,
    control: Observation | None,
    absolute: str,
    dest_host: str,
) -> ScanResult:
    status = test.status_code
    raw_location = test.location_header
    if control is None:
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=absolute,
            verdict=Verdict.INCONCLUSIVE.value,
            explanation=(
                f"Parameter '{parameter}' redirected to {absolute}, but there is no same-site "
                "control response to compare it with."
            ),
            remediation=_INCONCLUSIVE_REMEDIATION,
        )
    summary, control_destination = _control_summary(control, control_url)
    control_went_to_google = bool(control_destination) and is_google_destination(control_destination)
    if control.error or control_went_to_google:
        if control.error:
            explanation = (
                f"Parameter '{parameter}' was set to {payload}. The server responded {status} "
                f"with Location {raw_location!r}, which resolves to {absolute}. {summary[0].upper() + summary[1:]} "
                "The parameter cannot be confirmed as the cause."
            )
        else:
            explanation = (
                f"Parameter '{parameter}' was set to {payload}. The server responded {status} "
                f"with Location {raw_location!r}, which resolves to {absolute}. "
                f"A control request set '{parameter}' to a URL on the scanned host, and {summary}. "
                "The Google destination does not depend on the external test value, so this was not "
                "flagged as an open redirect."
            )
        return _make(
            original_url=original_url,
            parameter=parameter,
            payload=payload,
            test_url=test_url,
            test=test,
            destination=absolute,
            verdict=Verdict.INCONCLUSIVE.value,
            explanation=explanation,
            remediation=_INCONCLUSIVE_REMEDIATION,
            control=control,
            control_url=control_url,
            control_destination=control_destination,
        )
    return _make(
        original_url=original_url,
        parameter=parameter,
        payload=payload,
        test_url=test_url,
        test=test,
        destination=absolute,
        verdict=Verdict.POTENTIAL.value,
        explanation=(
            f"Parameter '{parameter}' was set to {payload}. The server responded {status} "
            f"with Location {raw_location!r}, which resolves to {absolute} (host {dest_host}). "
            f"A control request set '{parameter}' to a URL on the scanned host, and {summary}. "
            "The destination changes with the parameter and leaves the authorised site. "
            "This is a potential open redirect (CWE-601)."
        ),
        remediation=_VULNERABLE_REMEDIATION,
        control=control,
        control_url=control_url,
        control_destination=control_destination,
    )


def _make(
    *,
    original_url: str,
    parameter: str,
    payload: str,
    test_url: str,
    test: Observation,
    destination: str | None,
    verdict: str,
    explanation: str,
    remediation: str,
    control: Observation | None = None,
    control_url: str = "",
    control_destination: str | None = None,
) -> ScanResult:
    sent = control is not None
    return ScanResult(
        original_url=original_url,
        tested_parameter=parameter,
        payload=payload,
        test_url=test_url,
        http_status=test.status_code,
        location_header=test.location_header,
        redirect_destination=destination,
        result=verdict,
        explanation=explanation,
        remediation=remediation,
        control_url=control_url if sent else "",
        control_http_status=control.status_code if sent else None,
        control_location=control.location_header if sent else None,
        control_redirect_destination=control_destination if sent else None,
    )
