"""API surface: public API descriptions, endpoints that answer without credentials, GraphQL introspection.

Only GET is sent, and only to paths without placeholders. Paths the safety
policy treats as state-changing (delete, payment, order and similar) are never
requested, because the scoped client refuses them.
"""

from __future__ import annotations

import json
import re
import threading
from urllib.parse import quote, urlsplit

from rift.checks.base import PROBE, Check, CheckContext, clip, is_json, merge_by_title
from rift.models import Finding, Observation, Severity

_SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
)
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
_SENSITIVE_FIELD = re.compile(
    r"\"(password|passwd|pwd|password_hash|passwordHash|hashed_password|secret|api_?key|apiKey|private_?key|"
    r"access_?token|refresh_?token|ssn|social_security|credit_?card|card_?number|cvv|date_of_birth|dob)\"\s*:\s*\"[^\"]+\"",
    re.IGNORECASE,
)
_PERSONAL_FIELD = re.compile(r"\"(email|e_mail|phone|phone_number|address|full_?name)\"\s*:\s*\"[^\"]+\"", re.IGNORECASE)
_IDE = re.compile(r"<title>\s*(GraphiQL|GraphQL Playground|Playground - [^<]*|Apollo Sandbox|Altair)[^<]*</title>", re.IGNORECASE)


def load_spec(response: Observation) -> dict | None:
    if response.status_code != 200 or not response.body:
        return None
    try:
        spec = json.loads(response.body)
    except ValueError:
        return None
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return None
    if "openapi" not in spec and "swagger" not in spec:
        return None
    return spec


_SPEC_LOCK = threading.Lock()


def find_spec(ctx: CheckContext) -> tuple[str, dict] | None:
    """(url, spec) for the origin's public API description, fetched once per scan."""

    key = f"openapi:{ctx.origin}"
    with _SPEC_LOCK:
        if key in ctx.shared:
            return ctx.shared[key]  # type: ignore[return-value]
    found: tuple[str, dict] | None = None
    for path in _SPEC_PATHS:
        spec = load_spec(ctx.fetch(ctx.origin + path))
        if spec is not None:
            found = (ctx.origin + path, spec)
            break
    with _SPEC_LOCK:
        ctx.shared[key] = found
    return found


def base_path(spec: dict) -> str:
    """Path prefix from Swagger 2 basePath or the first OpenAPI 3 server URL."""

    prefix = ""
    if isinstance(spec.get("basePath"), str):
        prefix = spec["basePath"]
    else:
        servers = spec.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            url = str(servers[0].get("url", ""))
            prefix = urlsplit(url).path if "://" in url else url
    prefix = prefix.rstrip("/")
    return prefix if prefix.startswith("/") else ""


def get_operations(spec: dict) -> list[tuple[str, bool]]:
    """(path, requires_auth) for every GET operation with no path placeholder."""

    default_secured = bool(spec.get("security"))
    prefix = base_path(spec)
    operations: list[tuple[str, bool]] = []
    for path, item in spec["paths"].items():
        if not isinstance(path, str) or not isinstance(item, dict) or "{" in path:
            continue
        operation = item.get("get")
        if not isinstance(operation, dict):
            continue
        if any(isinstance(p, dict) and p.get("required") and p.get("in") == "query" for p in operation.get("parameters", []) or []):
            continue
        secured = bool(operation["security"]) if "security" in operation else default_secured
        operations.append((prefix + path, secured))
    return operations


class ApiSurfaceCheck(Check):
    id = "api-surface"
    title = "API exposure"
    summary = "Public API descriptions, endpoints that answer without a login, sensitive fields in responses, GraphQL introspection."
    kind = PROBE

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        found.extend(self._responses(ctx, ctx.pages))
        found.extend(self._openapi(ctx))
        found.extend(self._graphql(ctx))
        return merge_by_title(found)

    def _responses(self, ctx: CheckContext, pages: list[Observation]) -> list[Finding]:
        out: list[Finding] = []
        for page in pages:
            if page.status_code != 200 or not is_json(page) or not page.body:
                continue
            match = _SENSITIVE_FIELD.search(page.body)
            if match:
                who = (
                    "to the signed-in test account. Even a user's own record should not carry it, because anything "
                    "sent to the browser can be read there."
                    if page.signed_in
                    else "without any login."
                )
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="API response includes secret-looking fields",
                        severity=Severity.HIGH.value,
                        evidence=f"Field `{match.group(1)}` is present with a value. The value was not stored.",
                        explanation=(
                            "This endpoint returned a field that looks like a credential or regulated data "
                            + who
                            + " APIs often return whole database records and rely on the frontend to hide "
                            "fields, which hides nothing from someone calling the API directly."
                        ),
                        remediation="Return only the fields the client needs, chosen on the server. Never serialise password hashes, tokens or keys.",
                        cwe="CWE-213",
                        owasp="API3:2023 Broken Object Property Level Authorization",
                        confidence="medium",
                    )
                )
        return out

    def _openapi(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        located = find_spec(ctx)
        if located is None:
            return out
        spec_url, spec = located
        operations = get_operations(spec)
        out.append(
            self.finding(
                ctx,
                url=spec_url,
                title="API description is publicly accessible",
                severity=Severity.INFO.value,
                evidence=f"{spec_url} describes {len(spec['paths'])} paths.",
                explanation=(
                    "A public OpenAPI or Swagger file is fine for a public API. For an internal one it hands out a "
                    "complete map of every endpoint and parameter."
                ),
                remediation="If the API is not meant for the public, serve its description only to authenticated users or from an internal network.",
                cwe="CWE-200",
                owasp="API9:2023 Improper Inventory Management",
            )
        )
        limit = 25 if ctx.deep else 10
        for path, secured in operations[:limit]:
            url = ctx.origin + path
            response = ctx.fetch(url)
            if response.safety_block or response.status_code != 200 or not response.body:
                continue
            if not is_json(response) or response.body.strip() in {"{}", "[]", "null", '""'}:
                continue
            if secured:
                out.append(
                    self.finding(
                        ctx,
                        url=url,
                        title="Endpoint documented as authenticated answers without credentials",
                        severity=Severity.HIGH.value,
                        evidence=(
                            f"GET {path} with no cookie or token returned HTTP 200 and {len(response.body)} bytes of JSON. "
                            f"{spec_url} lists a security requirement for this operation."
                        ),
                        explanation=(
                            "The API's own description says this endpoint needs a login, but it returned data to an "
                            "anonymous request. Either the access check is missing or the documentation is wrong."
                        ),
                        remediation="Enforce authentication on the server for this route, and add a test that calls it without credentials and expects 401.",
                        cwe="CWE-306",
                        owasp="API2:2023 Broken Authentication",
                    )
                )
                continue
            personal = _SENSITIVE_FIELD.search(response.body) or _PERSONAL_FIELD.search(response.body)
            if personal:
                secret = bool(_SENSITIVE_FIELD.search(response.body))
                out.append(
                    self.finding(
                        ctx,
                        url=url,
                        title=(
                            "Unauthenticated endpoint returns secret-looking fields"
                            if secret
                            else "Unauthenticated endpoint returns personal data fields"
                        ),
                        severity=Severity.HIGH.value if secret else Severity.MEDIUM.value,
                        evidence=f"GET {path} with no credentials returned HTTP 200 with field `{personal.group(1)}`. The value was not stored.",
                        explanation="Anyone on the internet can read this data. Confirm whether the endpoint is meant to be public.",
                        remediation="Require authentication, check that the caller is allowed to see each record, and return only the fields that are needed.",
                        cwe="CWE-306",
                        owasp="API1:2023 Broken Object Level Authorization",
                        confidence="medium",
                    )
                )
        return out

    def _graphql(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        for path in _GRAPHQL_PATHS:
            url = ctx.origin + path
            landing = ctx.fetch(url)
            ide = _IDE.search(landing.body or "") if landing.status_code == 200 else None
            if ide:
                out.append(
                    self.finding(
                        ctx,
                        url=url,
                        title="GraphQL IDE is publicly accessible",
                        severity=Severity.LOW.value,
                        evidence=clip(ide.group(0), 100),
                        explanation="An in-browser query console is being served to the public. It makes exploring the API trivial.",
                        remediation="Disable the IDE in production.",
                        cwe="CWE-489",
                        owasp="API8:2023 Security Misconfiguration",
                    )
                )
            alive = ctx.fetch(url + "?query=" + quote("{__typename}"))
            if alive.status_code != 200 or '"__typename"' not in (alive.body or ""):
                continue
            schema = ctx.fetch(url + "?query=" + quote("{__schema{queryType{name}}}"))
            if schema.status_code == 200 and '"__schema"' in (schema.body or "") and '"queryType"' in (schema.body or ""):
                out.append(
                    self.finding(
                        ctx,
                        url=url,
                        title="GraphQL introspection is enabled",
                        severity=Severity.MEDIUM.value,
                        evidence=f"GET {path}?query={{__schema{{queryType{{name}}}}}} returned the schema root: {clip(schema.body or '', 120)}",
                        explanation=(
                            "Anyone can download the full schema: every type, field, query and mutation, including "
                            "ones the frontend never uses. That is the starting map for finding unprotected fields."
                        ),
                        remediation="Disable introspection in production, or allow it only for authenticated developers.",
                        cwe="CWE-200",
                        owasp="API8:2023 Security Misconfiguration",
                    )
                )
            else:
                ctx.note(self.id, "GraphQL answers GET queries. Introspection over GET was refused; POST is not sent by this scanner.", url)
        return out
