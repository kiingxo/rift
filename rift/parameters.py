"""Build one controlled request per candidate redirect parameter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from rift.catalog import profile_for
from rift.config import CONTROL_PATH
from rift.query import focus_plan


@dataclass(frozen=True)
class RequestPlan:
    parameter: str
    payload: str
    test_url: str
    control_url: str


def build_plans(
    url: str,
    parameters: Sequence[str] | None = None,
    payloads: Sequence[str] | None = None,
    manual_parameters: Sequence[str] | None = None,
) -> list[RequestPlan]:
    """Test existing navigation parameters, then each configured name.

    A URL with no query string is tested against the whole supplied catalogue.
    Values that already look like destinations are sent as well as the catalogue
    payloads. Authentication, unsubscribe, and other sensitive tokens are copied
    through unchanged. Ordinary parameters, such as campaign tags, are preserved.
    Other redirect parameters on the same URL are set to a same-site URL so one
    of them cannot cause a finding attributed to another.
    """

    selected = profile_for("standard")
    names = tuple(parameters) if parameters is not None else selected.parameters
    values = tuple(payloads) if payloads is not None else tuple(item.value for item in selected.payloads)
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    ordered, candidate_names, protected = focus_plan(pairs, names, tuple(manual_parameters or ()))
    supplied: dict[str, str] = {}
    for key, value in pairs:
        lowered = key.lower()
        if lowered in candidate_names and lowered not in supplied and _is_extra_payload(value):
            supplied[lowered] = value
    control_value = urlunsplit((parts.scheme, parts.netloc, CONTROL_PATH, "", ""))
    plans: list[RequestPlan] = []
    for name in ordered:
        chosen = list(values)
        extra = supplied.get(name.lower())
        if extra and extra not in chosen:
            chosen.append(extra)
        for payload in chosen:
            plans.append(
                RequestPlan(
                    parameter=name,
                    payload=payload,
                    test_url=_render(parts, pairs, name, payload, control_value, candidate_names, protected),
                    control_url=_render(parts, pairs, name, control_value, control_value, candidate_names, protected),
                )
            )
    return plans


def _is_extra_payload(value: str) -> bool:
    """Keep a caller-supplied redirect value that the standard payloads omit."""

    stripped = value.strip()
    lowered = stripped.lower()
    if lowered.startswith("//") or lowered.startswith(("http://", "https://", "\\\\")):
        return True
    return any(token in lowered for token in ("%2e", "%2f", "%5c"))


def _render(
    parts,
    pairs: list[tuple[str, str]],
    focus: str,
    focus_value: str,
    other_value: str,
    candidate_names: set[str],
    protected: set[str],
) -> str:
    focus_name = focus.lower()
    written: set[str] = set()
    rendered: list[tuple[str, str]] = []
    for key, value in pairs:
        lowered = key.lower()
        if lowered in protected:
            if lowered in written:
                continue
            rendered.append((key, value))
            written.add(lowered)
            continue
        if lowered in candidate_names:
            if lowered in written:
                continue
            rendered.append((key, focus_value if lowered == focus_name else other_value))
            written.add(lowered)
        else:
            rendered.append((key, value))
    if focus_name not in written:
        rendered.append((focus, focus_value))
    query = urlencode(rendered, doseq=True)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))
