"""Run the open-redirect check across an authorised URL list."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Protocol
from urllib.parse import urlsplit

from rift.body_redirects import extract_client_redirect
from rift.catalog import is_signal_payload, profile_for
from rift.chains import follow_same_origin
from rift.classify import REDIRECT_STATUSES, control_required, judge, resolve_redirect
from rift.config import ScanConfig
from rift.discover import _priority, discover_endpoints
from rift.http_client import HttpxRequester
from rift.models import Observation, ScanResult, Verdict
from rift.parameters import build_plans
from rift.param_discovery import (
    EvidenceIndex,
    collect_historical,
    collect_source_tree,
    isolate_parameters,
    mining_candidates,
)
from rift.safety import ScopeError, validate_target

ProgressCallback = Callable[[int, int, str], None]

_SCOPE_REMEDIATION = (
    "This URL was not requested. Scan it only after the hostname is on the allowlist "
    "and you are explicitly authorised to test it."
)
_BUDGET_REMEDIATION = (
    "This check was not sent because the scan mode reached its request budget. "
    "Run a smaller URL list or a deeper mode if you are authorised to continue."
)


class Requester(Protocol):
    def get(self, url: str, include_body: bool = False) -> Observation:
        """Perform one GET and return the first response only."""


class ScanBatch(list):
    """Scan results plus the counts the dashboard reports."""

    def __init__(
        self,
        results: list[ScanResult] | None = None,
        *,
        submitted_urls: list[str] | None = None,
        endpoints: list[str] | None = None,
        requests_sent: int = 0,
        payloads_tested: int = 0,
        mode: str = "",
        discovery=None,
    ) -> None:
        super().__init__(results or [])
        self.submitted_urls = list(submitted_urls or [])
        self.endpoints = list(endpoints or [])
        self.requests_sent = requests_sent
        self.payloads_tested = payloads_tested
        self.mode = mode
        self.discovery = discovery


class _CountingRequester:
    def __init__(self, inner: Requester) -> None:
        self.inner = inner
        self.requests = 0
        self._lock = threading.Lock()

    def get(self, url: str, include_body: bool = False) -> Observation:
        with self._lock:
            self.requests += 1
        return self.inner.get(url, include_body=include_body)


class _Progress:
    def __init__(self, callback: ProgressCallback | None, total: int) -> None:
        self.callback = callback
        self.total = max(total, 1)
        self.done = 0

    def tick(self, detail: str) -> None:
        self.done += 1
        if self.callback is not None:
            self.callback(min(self.done, self.total), self.total, detail)


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.payloads = 0
        self._lock = threading.Lock()

    def take(self, *, payload: bool) -> bool:
        with self._lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            if payload:
                self.payloads += 1
            return True


def scan_urls(
    urls: list[str],
    config: ScanConfig | None = None,
    requester: Requester | None = None,
    on_progress: ProgressCallback | None = None,
    on_finding: Callable[[ScanResult], None] | None = None,
    cancel: threading.Event | None = None,
    pause: threading.Event | None = None,
) -> ScanBatch:
    if not urls:
        return ScanBatch(mode=(config or ScanConfig()).mode)
    active = config or ScanConfig()
    started = time.monotonic()
    gate = _Gate(active, cancel, started, pause)
    if len(urls) > active.max_urls:
        raise ScopeError(f"A scan can include up to {active.max_urls} URLs. This request has {len(urls)}.")
    profile = profile_for(active.mode)
    owns_client = requester is None
    real = requester or HttpxRequester(active)
    if cancel is not None and hasattr(real, "cancel"):
        real.cancel = cancel
    if pause is not None and hasattr(real, "pause"):
        real.pause = pause
    client = _CountingRequester(real)
    try:
        def note(detail: str) -> None:
            if on_progress is not None:
                on_progress(0, 1, detail)

        evidence = EvidenceIndex()
        collect_historical(active.historical_urls, evidence)
        collect_source_tree(active.source_root, urls, evidence)
        if profile.name == "deep" and not active.historical_urls.strip():
            evidence.add_limitation(
                "Live archive lookup is not performed. Paste historical URLs to use them as evidence."
            )
        if profile.discover:
            note("Discovering endpoints")
            endpoints = _discover_all(urls, client, active, profile, note, gate.hold, evidence)
        else:
            endpoints = list(urls)
        endpoints = _cap_endpoints(endpoints, active, urls)
        testing = _testing_order(endpoints, urls)
        budget = _Budget(profile.max_plans)
        signal = sum(1 for item in profile.payloads if is_signal_payload(item.value)) or len(profile.payloads)
        progress = _Progress(
            on_progress,
            max(1, len(endpoints) * max(len(profile.parameters), 1) * signal),
        )
        if active.max_workers <= 1 or len(endpoints) == 1:
            results: list[ScanResult] = []
            for url in testing:
                if gate.hold():
                    results.append(_skipped(url, "The scan was cancelled. Completed checks were kept."))
                    break
                results.extend(scan_target(url, client, active, budget, progress, gate, on_finding, evidence))
        else:
            results = _scan_concurrent(testing, client, active, budget, on_progress, progress, gate, on_finding, evidence)
        report = evidence.report(profile.name)
        report.existing_parameters = evidence.existing_query_names(urls)
        report.endpoints_analysed = max(evidence.endpoints_analysed, len(endpoints))
        return ScanBatch(
            results,
            submitted_urls=list(urls),
            endpoints=endpoints,
            requests_sent=client.requests,
            payloads_tested=budget.payloads,
            mode=profile.name,
            discovery=report,
        )
    finally:
        if owns_client and isinstance(real, HttpxRequester):
            real.close()


def scan_target(
    url: str,
    requester: Requester,
    config: ScanConfig,
    budget: _Budget | None = None,
    progress: "_Progress | None" = None,
    gate: "_Gate | None" = None,
    on_finding: Callable[[ScanResult], None] | None = None,
    evidence: EvidenceIndex | None = None,
) -> list[ScanResult]:
    try:
        return _scan_target(
            url,
            requester,
            config,
            budget or _Budget(profile_for(config.mode).max_plans),
            progress,
            gate,
            on_finding,
            evidence,
        )
    except Exception as exc:  # noqa: BLE001 - one target must not abort the scan
        return [_skipped(url, f"The scan stopped on this URL because of an unexpected error ({exc.__class__.__name__}).")]


def _scan_target(
    url: str,
    requester: Requester,
    config: ScanConfig,
    budget: _Budget,
    progress: "_Progress | None" = None,
    gate: "_Gate | None" = None,
    on_finding: Callable[[ScanResult], None] | None = None,
    evidence: EvidenceIndex | None = None,
) -> list[ScanResult]:
    try:
        normalized = validate_target(url, config)
    except ScopeError as exc:
        return [_skipped(url, str(exc))]
    profile = profile_for(config.mode)
    inspect = profile.inspect_documents if config.inspect_documents is None else config.inspect_documents
    if not budget.take(payload=False):
        return [_budget(normalized, "", "")]
    baseline = _safe_get(requester, normalized, include_body=False)
    if baseline.safety_block:
        return [_skipped(normalized, baseline.error or "The baseline request was blocked by the safety policy.")]
    discovered = _discovered_names(normalized, requester, config, profile, evidence, progress, gate)
    plans = _signal_first(
        build_plans(
            normalized,
            parameters=tuple(dict.fromkeys((*profile.parameters, *discovered))),
            payloads=tuple(item.value for item in profile.payloads),
            manual_parameters=config.manual_parameters,
        )
    )
    rows: list[ScanResult] = []
    blocked: str | None = None
    confirmed: set[str] = set()
    unchanged: set[str] = set()
    signal_left: dict[str, int] = {}
    changed: set[str] = set()
    for plan in plans:
        if is_signal_payload(plan.payload):
            signal_left[plan.parameter.lower()] = signal_left.get(plan.parameter.lower(), 0) + 1
    budget_note = False
    for plan in plans:
        key = plan.parameter.lower()
        if gate is not None and gate.hold():
            rows.append(_skipped(normalized, "The scan was cancelled. Completed checks were kept."))
            break
        if key in confirmed or key in unchanged:
            continue
        if blocked is not None:
            row = _not_sent(normalized, plan.parameter, plan.test_url, blocked)
            _stamp_baseline(row, baseline)
            rows.append(row)
            continue
        if progress is not None:
            progress.tick(f"Checking {normalized} · parameter {plan.parameter} · {plan.payload}")
        if not budget.take(payload=True):
            if not budget_note:
                row = _budget(normalized, plan.parameter, plan.payload)
                _stamp_baseline(row, baseline)
                rows.append(row)
                budget_note = True
            continue
        if gate is not None and not gate.take(urlsplit(normalized).hostname or ""):
            rows.append(_skipped(normalized, "This domain reached its request limit. Remaining checks were not sent."))
            break
        test = _observe(requester, plan.test_url, config, inspect)
        if test.safety_block:
            blocked = test.error or "Blocked by the safety policy"
        same_path = not test.error and _same_path(test, plan.test_url, baseline, normalized)
        moved = not test.error and _moved(test, plan.test_url, baseline, normalized)
        if moved and profile.same_origin_hops > 0:
            redirected, chain = follow_same_origin(
                test,
                plan.test_url,
                requester,
                config,
                profile.same_origin_hops,
            )
        else:
            redirected, chain = test, _brief(test)
        control = None
        control_chain = ""
        if blocked is None and (
            control_required(redirected, plan.test_url) or control_required(test, plan.test_url)
        ):
            if budget.take(payload=False):
                control = _observe(requester, plan.control_url, config, inspect)
                control, control_chain = follow_same_origin(
                    control,
                    plan.control_url,
                    requester,
                    config,
                    profile.same_origin_hops,
                )
            else:
                control = Observation(error="The control request was not sent because the scan reached its request budget")
        judged, client_side, real_status, extracted = _evidence_for_judge(redirected)
        judged_control = _evidence_for_judge(control)[0] if control is not None else None
        row = judge(
            original_url=normalized,
            parameter=plan.parameter,
            payload=plan.payload,
            test_url=plan.test_url,
            control_url=plan.control_url,
            test=judged,
            control=judged_control,
            allowlist=config.allowlist,
        )
        row.redirect_chain = chain
        if control_chain:
            row.redirect_chain = f"{chain} || control: {control_chain}"
        if client_side:
            row.http_status = real_status
            row.location_header = extracted
            row.explanation = (
                f"The HTTP status was {real_status}. Static inspection of the HTML and script text "
                f"found a client-side redirect to {extracted!r}. The script was not executed, and that "
                f"destination was not requested. {row.explanation}"
            )
        _stamp_baseline(row, baseline)
        rows.append(row)
        if row.result == Verdict.POTENTIAL.value:
            confirmed.add(key)
        elif is_signal_payload(plan.payload):
            signal_left[key] = signal_left.get(key, 1) - 1
            if not same_path:
                changed.add(key)
            if signal_left[key] <= 0 and key not in changed:
                unchanged.add(key)
                _record_skip(rows, plans, key, normalized, baseline)
        _stamp_domain(row, normalized)
        if row.result == Verdict.POTENTIAL.value and evidence is not None:
            evidence.note_redirect(plan.parameter)
        if on_finding is not None and row.result == Verdict.POTENTIAL.value:
            on_finding(row)
    return rows


def _signal_first(plans):
    grouped: list = []
    current: list = []
    for plan in plans:
        if current and current[-1].parameter != plan.parameter:
            grouped.extend(sorted(current, key=lambda item: 0 if is_signal_payload(item.payload) else 1))
            current = []
        current.append(plan)
    grouped.extend(sorted(current, key=lambda item: 0 if is_signal_payload(item.payload) else 1))
    return grouped


def _absolute(url: str, observation: Observation) -> str | None:
    if observation.status_code not in REDIRECT_STATUSES:
        return None
    absolute, problem = resolve_redirect(url, observation.location_header)
    if problem or not absolute:
        return None
    return absolute


def _same_path(test: Observation, test_url: str, baseline: Observation, baseline_url: str) -> bool:
    test_absolute = _absolute(test_url, test)
    baseline_absolute = _absolute(baseline_url, baseline)
    if test_absolute is None or baseline_absolute is None:
        return test.status_code == baseline.status_code and test.status_code not in REDIRECT_STATUSES
    return _host_path(test_absolute) == _host_path(baseline_absolute)


def _moved(test: Observation, test_url: str, baseline: Observation, baseline_url: str) -> bool:
    return _absolute(test_url, test) != _absolute(baseline_url, baseline)


def _host_path(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return ((parts.hostname or "").rstrip(".").lower(), parts.path or "/")


def _brief(observation: Observation) -> str:
    if observation.location_header:
        return f"{observation.status_code} {observation.location_header}"
    return str(observation.status_code)


class _Gate:
    def __init__(
        self,
        config: ScanConfig,
        cancel: threading.Event | None,
        started: float,
        pause: threading.Event | None = None,
    ) -> None:
        self.config = config
        self.cancel = cancel
        self.pause = pause
        self.started = started
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()
        self.paused_seconds = 0.0
        self._pause_mark: float | None = None

    def hold(self) -> bool:
        """Wait while the scan is paused. Return True when it should stop."""

        while True:
            with self.lock:
                now = time.monotonic()
                paused = self.pause is not None and self.pause.is_set()
                if paused:
                    if self._pause_mark is None:
                        self._pause_mark = now
                elif self._pause_mark is not None:
                    self.paused_seconds += now - self._pause_mark
                    self._pause_mark = None
                stop = self._stopped(now)
            if stop or not paused:
                return stop
            time.sleep(0.2)

    def stopped(self) -> bool:
        with self.lock:
            return self._stopped(time.monotonic())

    def _stopped(self, now: float) -> bool:
        if self.cancel is not None and self.cancel.is_set():
            return True
        limit = self.config.max_duration_seconds
        if not limit:
            return False
        paused = self.paused_seconds
        if self._pause_mark is not None:
            paused += now - self._pause_mark
        return now - self.started - paused >= limit

    def take(self, host: str) -> bool:
        with self.lock:
            count = self.counts.get(host, 0) + 1
            if count > self.config.max_requests_per_domain:
                return False
            self.counts[host] = count
            return True


def _discovered_names(url, requester, config, profile, evidence, progress, gate) -> tuple[str, ...]:
    if evidence is None:
        return ()

    def announce(detail: str) -> None:
        if progress is not None and progress.callback is not None:
            progress.callback(progress.done, progress.total, detail)

    announce(f"Extracting parameters from {url}")
    observed = evidence.direct_names(url, 10_000)
    direct = observed[: profile.max_extra_parameters]
    for name in direct:
        evidence.note_verified(name)
    if not profile.mine_parameters:
        hidden = len(observed) - len(direct)
        if hidden > 0:
            evidence.add_limitation(
                f"{hidden} observed names on {url} were not tested because this mode caps extra parameters."
            )
        return tuple(direct)
    catalog = tuple(profile.parameters)
    guesses = mining_candidates(url, direct, catalog, config.extra_parameter_names, limit=24)
    mined = isolate_parameters(
        url,
        requester,
        guesses,
        profile.max_mining_requests,
        gate.hold if gate is not None else None,
        announce,
        evidence,
    )
    for name in mined:
        evidence.note_verified(name)
    merged = list(dict.fromkeys((*direct, *mined)))
    return tuple(merged[: profile.max_extra_parameters])


def _discover_all(urls, client, config, profile, note, should_stop, evidence: EvidenceIndex | None = None) -> list[str]:
    kwargs = dict(
        probes=profile.probes,
        max_discovered=profile.max_discovered,
        on_status=note,
        fetch_scripts=profile.fetch_scripts,
        max_path_probes=profile.max_path_probes,
        probes_per_directory=profile.probes_per_directory,
        should_stop=should_stop,
        evidence=evidence,
    )
    if config.max_workers <= 1 or len(urls) <= 1:
        return discover_endpoints(list(urls), client, config, **kwargs)
    found: list[str] = []
    seen: set[str] = set()
    workers = min(config.max_workers, len(urls))

    def one(url: str) -> list[str]:
        return discover_endpoints([url], client, config, **kwargs)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        groups = pool.map(one, urls)
    for group in groups:
        for endpoint in group:
            if endpoint not in seen:
                seen.add(endpoint)
                found.append(endpoint)
    return found


def _testing_order(endpoints: list[str], submitted: list[str]) -> list[str]:
    """Test the URLs the user submitted first, then discovered redirect endpoints."""

    submitted_set = set(submitted)

    def rank(item: tuple[int, str]) -> tuple[int, int, int]:
        index, url = item
        group = 0 if url in submitted_set else 1
        return (group, -_priority(url), index)

    return [url for _, url in sorted(enumerate(endpoints), key=rank)]


def _cap_endpoints(endpoints: list[str], config: ScanConfig, submitted: list[str] | None = None) -> list[str]:
    submitted_set = set(submitted or [])
    kept: list[str] = []
    counts: dict[str, int] = {}
    for url in endpoints:
        if len(kept) >= config.max_urls:
            break
        host = urlsplit(url).hostname or ""
        count = counts.get(host, 0)
        if url not in submitted_set and count >= config.max_endpoints_per_domain:
            continue
        counts[host] = count + 1
        kept.append(url)
    return kept


def _record_skip(rows: list[ScanResult], plans, key: str, url: str, baseline: Observation) -> None:
    pending = [plan.payload for plan in plans if plan.parameter.lower() == key and not is_signal_payload(plan.payload)]
    if not pending:
        return
    row = ScanResult(
        original_url=url,
        tested_parameter=key,
        test_url="",
        http_status=None,
        location_header=None,
        redirect_destination=None,
        result=Verdict.SKIPPED.value,
        explanation=(
            "These payloads were not sent because the high-value checks left the browser on the same "
            f"path as the baseline: {', '.join(pending)}"
        ),
        remediation="Run Deep Scan when you need the remaining payload variants on this parameter.",
        payload=", ".join(pending),
    )
    _stamp_baseline(row, baseline)
    _stamp_domain(row, url)
    rows.append(row)


def _stamp_domain(row: ScanResult, url: str) -> None:
    row.domain = urlsplit(url).hostname or ""
    if row.result == Verdict.POTENTIAL.value and not row.confidence:
        row.confidence = "high"
        row.detection_method = row.detection_method or "location-header"


def _stamp_baseline(row: ScanResult, baseline: Observation) -> None:
    row.baseline_status = baseline.status_code
    row.baseline_location = baseline.location_header
    row.baseline_error = baseline.error or ""


def _observe(requester: Requester, url: str, config: ScanConfig, inspect_documents: bool) -> Observation:
    observation = _safe_get(requester, url, include_body=inspect_documents)
    if inspect_documents and observation.body and observation.status_code not in REDIRECT_STATUSES:
        observation.body_redirect = extract_client_redirect(observation.body)
    return observation


def _evidence_for_judge(observation: Observation | None) -> tuple[Observation | None, bool, int | None, str | None]:
    if observation is None:
        return None, False, None, None
    if observation.status_code in REDIRECT_STATUSES or not observation.body_redirect:
        return observation, False, observation.status_code, None
    return (
        Observation(status_code=302, location_header=observation.body_redirect),
        True,
        observation.status_code,
        observation.body_redirect,
    )


def _scan_concurrent(
    urls: list[str],
    requester: Requester,
    config: ScanConfig,
    budget: _Budget,
    on_progress: ProgressCallback | None,
    progress: _Progress,
    gate: "_Gate",
    on_finding: Callable[[ScanResult], None] | None,
    evidence: EvidenceIndex | None = None,
) -> list[ScanResult]:
    ordered: dict[int, list[ScanResult]] = {}
    workers = min(config.max_workers, len(urls))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_target, url, requester, config, budget, progress, gate, on_finding, evidence): index
            for index, url in enumerate(urls)
        }
        finished = 0
        for future in as_completed(futures):
            index = futures[future]
            ordered[index] = future.result()
            finished += 1
            if on_progress is not None:
                on_progress(finished, len(urls), urls[index])
    results: list[ScanResult] = []
    for index in range(len(urls)):
        results.extend(ordered[index])
    return results


def _safe_get(requester: Requester, url: str, include_body: bool = False) -> Observation:
    try:
        return requester.get(url, include_body=include_body)
    except TypeError:
        try:
            return requester.get(url)
        except Exception as exc:  # noqa: BLE001 - transport bugs become inconclusive rows
            return Observation(error=f"Request failed: {exc.__class__.__name__}")
    except Exception as exc:  # noqa: BLE001 - transport bugs become inconclusive rows
        return Observation(error=f"Request failed: {exc.__class__.__name__}")


def _skipped(url: str, reason: str) -> ScanResult:
    return ScanResult(
        original_url=url,
        tested_parameter="",
        test_url="",
        http_status=None,
        location_header=None,
        redirect_destination=None,
        result=Verdict.INCONCLUSIVE.value,
        explanation=reason,
        remediation=_SCOPE_REMEDIATION,
    )


def _not_sent(url: str, parameter: str, test_url: str, reason: str) -> ScanResult:
    return ScanResult(
        original_url=url,
        tested_parameter=parameter,
        test_url=test_url,
        http_status=None,
        location_header=None,
        redirect_destination=None,
        result=Verdict.INCONCLUSIVE.value,
        explanation=(
            f"Parameter '{parameter}' was not requested because an earlier request to this host was blocked: {reason}"
        ),
        remediation=_SCOPE_REMEDIATION,
    )


def _budget(url: str, parameter: str, payload: str) -> ScanResult:
    return ScanResult(
        original_url=url,
        tested_parameter=parameter,
        test_url="",
        http_status=None,
        location_header=None,
        redirect_destination=None,
        result=Verdict.INCONCLUSIVE.value,
        explanation=(
            f"Parameter '{parameter}' payload {payload!r} was not sent. "
            "This scan mode reached its request budget."
        ),
        remediation=_BUDGET_REMEDIATION,
        payload=payload,
    )
