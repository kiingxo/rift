"""Hidden parameter names are learned from evidence, not from a memorised list."""

from urllib.parse import parse_qs, urlsplit

from rift.config import ScanConfig
from rift.engine import scan_urls
from rift.models import Observation, Verdict
from rift.param_discovery import javascript_names, normalize_body, response_changed
from tests.fakes import ScriptedRequester

HOST = "app.example.com"


def _config(mode: str, **kwargs) -> ScanConfig:
    base = dict(allowlist=(HOST,), allow_internal=False, max_workers=1, min_interval_seconds=0, mode=mode)
    base.update(kwargs)
    return ScanConfig(**base)


def _google(params, name: str) -> bool:
    return "google.com" in params.get(name, [""])[0]


def test_javascript_object_keys_and_set_calls_are_parameter_names():
    source = """
    const params = new URLSearchParams({customNavigationTarget: dest});
    params.set("berthChoice", dest);
    location.assign("/navigation?laneSelector=" + dest);
    """
    found = set(javascript_names(source))
    assert "customNavigationTarget" in found
    assert "berthChoice" in found
    assert "laneSelector" in found


def test_reflection_of_the_probe_marker_is_not_a_behaviour_change():
    baseline = Observation(status_code=200, body="calm")
    reflected = Observation(status_code=200, body="calm keelMarker=bpProbeValue")
    assert response_changed(200, None, baseline.body, reflected) is False
    assert "1710000000000" not in normalize_body("calm 1710000000000")


def test_fast_scan_tests_a_name_found_in_an_inline_script():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        if parts.path == "/navigation" and not params:
            body = (
                "<html><script>"
                "const params = new URLSearchParams();"
                "params.set('berthChoice', dest);"
                "location.assign('/navigation?' + params.toString());"
                "</script></html>"
            )
            return Observation(status_code=200, body=body if include_body else None)
        if _google(params, "berthChoice"):
            return Observation(status_code=302, location_header="https://www.google.com/")
        return Observation(status_code=404, body="missing" if include_body else None)

    batch = scan_urls([f"https://{HOST}/navigation"], _config("fast"), ScriptedRequester(app))
    found = [row for row in batch if row.tested_parameter == "berthChoice" and row.result == Verdict.POTENTIAL.value]
    assert found
    assert batch.discovery.requests == 0


def test_fast_scan_tests_a_form_field_that_is_not_in_the_catalog():
    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        if parts.path == "/hangar" and not params:
            body = '<html><form action="/hangar"><input name="laneSelector"></form></html>'
            return Observation(status_code=200, body=body if include_body else None)
        if _google(params, "laneSelector"):
            return Observation(status_code=302, location_header="https://www.google.com/")
        return Observation(status_code=404, body="missing" if include_body else None)

    batch = scan_urls([f"https://{HOST}/hangar"], _config("fast"), ScriptedRequester(app))
    assert any(row.tested_parameter == "laneSelector" and row.result == Verdict.POTENTIAL.value for row in batch)


def test_deep_scan_reads_an_openapi_query_parameter():
    spec = """
    {"paths": {"/dock": {"get": {"parameters": [
      {"name": "dockHandoff", "in": "query", "description": "where to send the browser"}
    ]}}}}
    """

    def app(url: str, include_body: bool = False) -> Observation:
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        if parts.path == "/openapi.json":
            return Observation(status_code=200, body=spec if include_body else None)
        if _google(params, "dockHandoff"):
            return Observation(status_code=302, location_header="https://www.google.com/")
        if parts.path == "/dock":
            return Observation(status_code=200, body="dock" if include_body else None)
        return Observation(status_code=404, body="missing" if include_body else None)

    batch = scan_urls([f"https://{HOST}/"], _config("deep"), ScriptedRequester(app))
    assert any(row.tested_parameter == "dockHandoff" and row.result == Verdict.POTENTIAL.value for row in batch)


def test_a_pasted_historical_url_supplies_the_parameter_name():
    def app(url: str, include_body: bool = False) -> Observation:
        params = parse_qs(urlsplit(url).query)
        if _google(params, "pierReturn"):
            return Observation(status_code=302, location_header="https://www.google.com/")
        return Observation(status_code=200, body="pier" if include_body else None)

    historical = f"https://{HOST}/pier?pierReturn=https://{HOST}/old&session=abc"
    batch = scan_urls(
        [f"https://{HOST}/pier"],
        _config("fast", historical_urls=historical),
        ScriptedRequester(app),
    )
    assert any(row.tested_parameter == "pierReturn" and row.result == Verdict.POTENTIAL.value for row in batch)
    assert all(row.tested_parameter != "session" for row in batch)


def test_deep_mining_isolates_one_name_from_a_supplied_dictionary():
    secret = "keelMarker"

    def app(url: str, include_body: bool = False) -> Observation:
        params = parse_qs(urlsplit(url).query)
        if _google(params, secret):
            return Observation(status_code=302, location_header="https://www.google.com/")
        if secret in params:
            return Observation(status_code=200, body="shifted")
        return Observation(status_code=200, body="calm")

    noise = ["amber1", "amber2", "amber3", "amber4", "amber5", "amber6", "amber7"]
    batch = scan_urls(
        [f"https://{HOST}/keel"],
        _config("deep", extra_parameter_names=tuple([*noise, secret])),
        ScriptedRequester(app),
    )
    assert secret in batch.discovery.recognised
    assert any(row.tested_parameter == secret and row.result == Verdict.POTENTIAL.value for row in batch)


def test_an_undiscoverable_name_is_reported_as_a_coverage_limit():
    def app(url: str, include_body: bool = False) -> Observation:
        params = parse_qs(urlsplit(url).query)
        if _google(params, "qq7m2vx"):
            return Observation(status_code=302, location_header="https://www.google.com/")
        return Observation(status_code=200, body="quiet" if include_body else None)

    batch = scan_urls([f"https://{HOST}/quiet"], _config("deep"), ScriptedRequester(app))
    assert not any(row.tested_parameter == "qq7m2vx" for row in batch)
    assert not any(row.result == Verdict.POTENTIAL.value for row in batch)
    assert any("cannot be discovered" in item for item in batch.discovery.limitations)


def test_optional_source_directory_contributes_a_name(tmp_path):
    (tmp_path / "view.py").write_text('target = request.args.get("slipChoice")\n', encoding="utf-8")

    def app(url: str, include_body: bool = False) -> Observation:
        params = parse_qs(urlsplit(url).query)
        if _google(params, "slipChoice"):
            return Observation(status_code=302, location_header="https://www.google.com/")
        return Observation(status_code=200, body="slip" if include_body else None)

    batch = scan_urls(
        [f"https://{HOST}/slip"],
        _config("fast", source_root=str(tmp_path)),
        ScriptedRequester(app),
    )
    assert any(row.tested_parameter == "slipChoice" and row.result == Verdict.POTENTIAL.value for row in batch)


def test_unstable_responses_skip_mining():
    calls = {"n": 0}

    def app(url: str, include_body: bool = False) -> Observation:
        calls["n"] += 1
        return Observation(status_code=200, body=f"quiet-{calls['n']}")

    batch = scan_urls([f"https://{HOST}/drift"], _config("deep"), ScriptedRequester(app))
    assert any("unstable" in item for item in batch.discovery.limitations)
    assert batch.discovery.recognised == []
