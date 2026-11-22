"""Load payload, parameter, and endpoint catalogs, and describe each scan mode.

Payload text lives in payloads.json. Parameter names live in parameters.json.
Redirect endpoint names live in paths.json. Add a row there to extend a later
scan without changing the engine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache

from rift.config import tool_root

_MODE_ORDER = ("fast", "deep")
_MODE_ALIASES = {"quick": "fast", "standard": "deep"}
_TIER_BY_MODE = {
    "fast": frozenset({"core", "common"}),
    "deep": frozenset({"core", "common", "extended"}),
}
_PROBES = (
    "/sitemap.xml",
    "/robots.txt",
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/v3/api-docs",
)


@dataclass(frozen=True)
class PayloadSpec:
    id: str
    category: str
    value: str
    modes: tuple[str, ...]


@dataclass(frozen=True)
class ParameterSpec:
    name: str
    tier: str


@dataclass(frozen=True)
class ModeProfile:
    name: str
    label: str
    description: str
    parameters: tuple[str, ...]
    payloads: tuple[PayloadSpec, ...]
    discover: bool
    max_discovered: int
    same_origin_hops: int
    inspect_documents: bool
    probes: tuple[str, ...]
    max_plans: int
    fetch_scripts: bool = True
    max_path_probes: int = 24
    probes_per_directory: int = 8
    mine_parameters: bool = False
    max_extra_parameters: int = 8
    max_mining_requests: int = 0


@lru_cache(maxsize=1)
def load_payloads() -> tuple[PayloadSpec, ...]:
    raw = json.loads((tool_root() / "rift" / "payloads.json").read_text(encoding="utf-8"))
    specs = []
    seen: set[str] = set()
    for item in raw["payloads"]:
        value = str(item["value"])
        if value in seen:
            continue
        seen.add(value)
        specs.append(
            PayloadSpec(
                id=str(item["id"]),
                category=str(item["category"]),
                value=value,
                modes=tuple(str(mode) for mode in item["modes"]),
            )
        )
    if not specs:
        raise RuntimeError("payloads.json did not define any payloads")
    return tuple(specs)


@lru_cache(maxsize=1)
def load_redirect_paths() -> tuple[str, ...]:
    raw = json.loads((tool_root() / "rift" / "paths.json").read_text(encoding="utf-8"))
    names = []
    seen: set[str] = set()
    for item in raw["paths"]:
        name = str(item).strip().strip("/")
        if not name or "/" in name or name.lower() in seen:
            continue
        seen.add(name.lower())
        names.append(name)
    if not names:
        raise RuntimeError("paths.json did not define any paths")
    return tuple(names)


@lru_cache(maxsize=1)
def load_parameters() -> tuple[ParameterSpec, ...]:
    raw = json.loads((tool_root() / "rift" / "parameters.json").read_text(encoding="utf-8"))
    specs = []
    seen: set[str] = set()
    for item in raw["parameters"]:
        name = str(item["name"])
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        specs.append(ParameterSpec(name=name, tier=str(item["tier"])))
    if not specs:
        raise RuntimeError("parameters.json did not define any parameters")
    return tuple(specs)


def profile_for(mode: str) -> ModeProfile:
    name = _MODE_ALIASES.get(mode, mode)
    if name not in _MODE_ORDER:
        name = "fast"
    tiers = _TIER_BY_MODE[name]
    parameters = tuple(item.name for item in load_parameters() if item.tier in tiers)
    payloads = tuple(item for item in load_payloads() if name in item.modes)
    if name == "deep":
        return ModeProfile(
            name="deep",
            label="Deep Scan",
            description=(
                "Fast Scan, plus links, scripts, sitemaps, robots.txt, and OpenAPI discovery, "
                "common redirect paths under directories already opened, the full payload catalog, "
                "redirect chains, and static HTML and script inspection. Scripts are not executed, "
                "and external hosts are not requested. Deep Scan also reads parameter names from "
                "those documents and isolates uncommon names that change the response."
            ),
            parameters=parameters,
            payloads=payloads,
            discover=True,
            max_discovered=20,
            same_origin_hops=3,
            inspect_documents=True,
            probes=_PROBES,
            max_plans=5000,
            fetch_scripts=True,
            max_path_probes=160,
            probes_per_directory=8,
            mine_parameters=True,
            max_extra_parameters=24,
            max_mining_requests=16,
        )
    return ModeProfile(
        name="fast",
        label="Fast Scan",
        description=(
            "The submitted URL, plus pages and folders linked from it. Redirect filenames "
            "are checked inside directories the site itself links to. Existing parameters "
            "first, then common redirect names and parameter names found in those pages, links, and inline scripts, "
            "using an absolute HTTPS URL, a protocol-relative URL, and an encoded-dot bypass. "
            "A potential vulnerability "
            "is flagged as soon as the evidence is in. One in-scope hop covers a canonical "
            "redirect such as apex to www. Extra payload variants are recorded as skipped when "
            "the destination does not change."
        ),
        parameters=parameters,
        payloads=payloads,
        discover=True,
        max_discovered=8,
        same_origin_hops=1,
        inspect_documents=False,
        probes=(),
        max_plans=2000,
        fetch_scripts=False,
        max_path_probes=48,
        probes_per_directory=6,
    )


def is_signal_payload(value: str) -> bool:
    """Payloads that catch a different filter. The rest run only if one of these changes the destination."""

    stripped = value.strip()
    lowered = stripped.lower()
    if lowered.startswith("https://"):
        return True
    if lowered.startswith("http://") and not stripped.startswith("http://"):
        return True
    if lowered.startswith("//") and "google.com" in lowered:
        return True
    return "%2e" in lowered


def estimate_scan(url_count: int, profile: ModeProfile, interval_seconds: float) -> dict[str, int | bool]:
    """Upper bound shown before a scan. Unchanged parameters stop after the signal payloads."""

    extra = profile.max_discovered if profile.discover else 0
    endpoints = url_count + extra
    signal = sum(1 for item in profile.payloads if is_signal_payload(item.value)) or len(profile.payloads)
    per_endpoint = len(profile.parameters) * signal
    uncapped = endpoints * per_endpoint
    plans = min(profile.max_plans, uncapped)
    discovery_requests = 0
    if profile.discover:
        path_probes = min(profile.max_path_probes, profile.probes_per_directory * 2)
        discovery_requests = url_count * (1 + len(profile.probes) + path_probes)
    seconds = int((plans + discovery_requests) * max(interval_seconds, 0))
    return {
        "endpoints": endpoints,
        "parameters": len(profile.parameters),
        "payloads": signal,
        "plans": plans,
        "discovery_requests": discovery_requests,
        "seconds": seconds,
        "capped": uncapped > profile.max_plans,
    }
