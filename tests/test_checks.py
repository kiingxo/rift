"""Unit tests for each check, using hand-built responses. No network."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from rift.checks import all_checks, catalog, resolve_checks
from rift.checks.api_surface import ApiSurfaceCheck, get_operations
from rift.checks.base import CheckContext, redact
from rift.checks.content import ContentCheck
from rift.checks.cookies import CookieCheck, parse_set_cookie
from rift.checks.cors import PROBE_ORIGIN, CorsCheck
from rift.checks.disclosure import DisclosureCheck
from rift.checks.dns_checks import EmailAuthCheck, TakeoverCheck, organisation_domain
from rift.checks.exposure import ExposedFilesCheck
from rift.checks.headers import SecurityHeadersCheck, csp_weaknesses, parse_csp, parse_hsts
from rift.checks.secrets import JwtCheck, SecretsCheck, scan_text
from rift.checks.server_config import ServerConfigCheck
from rift.checks.transport import TransportCheck, days_until
from rift.config import ScanConfig
from rift.models import Observation
from tests.weak_site import EXAMPLE_AWS_KEY, UNSIGNED_JWT

ORIGIN = "https://app.example.com"


def page(path="/", body="<html><body>hi</body></html>", status=200, content_type="text/html", headers=None, cookies=()):
    pairs = [("Content-Type", content_type)]
    pairs += list((headers or {}).items())
    pairs += [("Set-Cookie", cookie) for cookie in cookies]
    return Observation(status_code=status, body=body, headers=tuple(pairs), url=ORIGIN + path)


def context(pages=(), scripts=(), routes=None, deep=False, origin=ORIGIN, resolver=None):
    """A check context whose extra requests are answered from a dict of path -> response."""

    table = routes or {}
    calls = []

    def fetch(url, *, method="GET", headers=None, include_body=True):
        calls.append((method, url, dict(headers or {})))
        path = url[len(origin):] if url.startswith(origin) else url
        answer = table.get((method, path), table.get(path))
        if callable(answer):
            answer = answer(method, headers or {})
        if answer is None:
            answer = Observation(status_code=404, body="<html>not found</html>", headers=(("Content-Type", "text/html"),))
        if not answer.url:
            answer.url = url
        return answer

    ctx = CheckContext(
        origin=origin,
        config=ScanConfig(),
        pages=list(pages),
        scripts=list(scripts),
        fetcher=fetch,
        deep=deep,
        resolver=resolver,
    )
    ctx.calls = calls
    return ctx


def titles(findings):
    return {item.title for item in findings}


def text(body, content_type="text/plain", status=200, headers=None):
    return Observation(status_code=status, body=body, headers=(("Content-Type", content_type), *((headers or {}).items())))


# --- registry -----------------------------------------------------------------


def test_every_check_has_a_unique_id_and_a_description():
    checks = all_checks()
    ids = [check.id for check in checks]
    assert len(ids) == len(set(ids))
    assert all(check.title and check.summary for check in checks)
    assert "open-redirect" in {row[0] for row in catalog()}


def test_resolve_checks_rejects_an_unknown_name():
    with pytest.raises(ValueError):
        resolve_checks(["security-headers", "not-a-check"])
    selected, redirects = resolve_checks(["cookies"])
    assert [check.id for check in selected] == ["cookies"] and redirects is False


# --- security headers ---------------------------------------------------------


def test_missing_headers_are_reported_once_per_origin_with_every_affected_page():
    found = SecurityHeadersCheck().run(context([page("/"), page("/about")]))
    names = titles(found)
    assert "HSTS header is missing" in names
    assert "Content-Security-Policy header is missing" in names
    assert "Page can be framed by other sites (clickjacking)" in names
    hsts = next(item for item in found if item.title == "HSTS header is missing")
    assert hsts.affected_urls == [ORIGIN + "/", ORIGIN + "/about"]


def test_a_well_configured_page_has_no_header_findings():
    good = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    assert SecurityHeadersCheck().run(context([page(headers=good)])) == []


def test_hsts_is_not_expected_on_plain_http():
    ctx = context([Observation(status_code=200, body="<html></html>", headers=(("Content-Type", "text/html"),), url="http://app.example.com/")], origin="http://app.example.com")
    assert "HSTS header is missing" not in titles(SecurityHeadersCheck().run(ctx))


def test_hsts_parsing_and_short_max_age():
    assert parse_hsts("max-age=31536000; includeSubDomains; preload") == (31536000, True, True)
    found = SecurityHeadersCheck().run(context([page(headers={"Strict-Transport-Security": "max-age=3600"})]))
    assert "HSTS max-age is short" in titles(found)


def test_csp_weaknesses():
    labels = {label for _severity, label, _text in csp_weaknesses(parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline' https:"))}
    assert {"inline scripts allowed", "scripts allowed from any host", "base-uri missing"} <= labels
    # A nonce makes browsers ignore 'unsafe-inline', and strict-dynamic makes them ignore host lists.
    strict = parse_csp("script-src 'nonce-abc123' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'")
    assert csp_weaknesses(strict) == []


def test_frame_ancestors_alone_prevents_the_clickjacking_finding():
    found = SecurityHeadersCheck().run(context([page(headers={"Content-Security-Policy": "frame-ancestors 'self'"})]))
    assert "Page can be framed by other sites (clickjacking)" not in titles(found)


def test_json_responses_are_not_judged_as_html_documents():
    found = SecurityHeadersCheck().run(context([page(body="{}", content_type="application/json", headers={"Strict-Transport-Security": "max-age=63072000; includeSubDomains"})]))
    assert found == []


# --- cookies ------------------------------------------------------------------


def test_cookie_parsing():
    cookie = parse_set_cookie("sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert (cookie.name, cookie.secure, cookie.http_only, cookie.same_site) == ("sessionid", True, True, "lax")
    assert parse_set_cookie("garbage") is None


def test_session_cookie_without_flags():
    found = CookieCheck().run(context([page(cookies=["sessionid=abc; Path=/"])]))
    assert titles(found) == {
        "Session cookie `sessionid` is sent without Secure",
        "Session cookie `sessionid` is readable by JavaScript",
        "Session cookie `sessionid` has no SameSite attribute",
    }
    assert all("abc" not in item.evidence for item in found)


def test_well_formed_cookies_and_csrf_tokens_are_not_flagged():
    cookies = [
        "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "csrftoken=xyz; Path=/; Secure; SameSite=Lax",
    ]
    assert CookieCheck().run(context([page(cookies=cookies)])) == []


def test_host_prefix_rules():
    found = CookieCheck().run(context([page(cookies=["__Host-id=1; Secure; Path=/; Domain=example.com; HttpOnly; SameSite=Lax"])]))
    assert "Cookie `__Host-id` breaks the __Host- prefix rules" in titles(found)


# --- page content -------------------------------------------------------------


def test_mixed_content_missing_sri_and_insecure_forms():
    body = """<html><script src="http://cdn.example.net/a.js"></script>
    <script src="https://cdn.example.net/b.js"></script>
    <script src="https://cdn.example.net/c.js" integrity="sha384-x"></script>
    <img src="http://img.example.net/x.png">
    <form method="get" action="http://app.example.com/login"><input type="password" name="p"></form></html>"""
    found = ContentCheck().run(context([page(body=body)]))
    assert titles(found) == {
        "HTTPS page loads scripts, styles or frames over plain HTTP",
        "HTTPS page loads images or media over plain HTTP",
        "Third-party scripts load without Subresource Integrity",
        "Password form is sent over plain HTTP",
        "Password form submits with GET",
    }
    sri = next(item for item in found if "Subresource" in item.title)
    assert "c.js" not in sri.evidence


def test_same_origin_scripts_and_post_forms_are_fine():
    body = '<html><script src="/app.js"></script><form method="post" action="/login"><input type="password"></form></html>'
    assert ContentCheck().run(context([page(body=body)])) == []


# --- information disclosure ---------------------------------------------------


def test_version_banners_need_a_version_number():
    found = DisclosureCheck().run(context([page(headers={"Server": "nginx", "X-Powered-By": "PHP/8.1.2"})]))
    assert titles(found) == {"Response header reveals software version (x-powered-by)"}


@pytest.mark.parametrize(
    "body, expected",
    [
        ('Traceback (most recent call last):\n  File "/srv/app.py", line 3, in view', "Python traceback shown in a response"),
        ("java.lang.NullPointerException: oops\n\tat com.acme.Service.run(Service.java:42)", "Java stack trace shown in a response"),
        ("<b>Fatal error</b>:  Uncaught Error in <b>/var/www/index.php</b> on line <b>12</b>", "PHP error shown in a response"),
        ("You have an error; check the manual that corresponds to your MySQL server version", "MySQL error message shown in a response"),
        ("ORA-00933: SQL command not properly ended", "Oracle error message shown in a response"),
        ("<p>You’re seeing this error because you have <code>DEBUG = True</code> in settings</p>", "Django debug page is exposed"),
        ("<html><head><title>Index of /backup</title></head></html>", "Directory listing is enabled"),
    ],
)
def test_error_fingerprints(body, expected):
    assert expected in titles(DisclosureCheck().run(context([page(body=body)])))


def test_ordinary_prose_about_errors_is_not_flagged():
    body = "<html><p>Our docs explain how to read a Python traceback and what an Oracle error means. Server 10.0 is fast.</p></html>"
    assert DisclosureCheck().run(context([page(body=body)])) == []


def test_internal_addresses():
    found = DisclosureCheck().run(context([page(body="<html><!-- upstream 192.168.4.20 --> version 172.99.1.1</html>")]))
    internal = next(item for item in found if item.title == "Internal IP address disclosed")
    assert internal.evidence == "192.168.4.20"


# --- secrets and tokens -------------------------------------------------------


def test_secrets_are_found_and_redacted():
    body = f'const k = "{EXAMPLE_AWS_KEY}"; const s = "sk_live_' + "a1B2c3D4e5F6g7H8i9J0k1L2" + '";'
    found = SecretsCheck().run(context(scripts=[page("/app.js", body=body, content_type="application/javascript")]))
    assert titles(found) == {
        "AWS access key ID exposed in a public response",
        "Stripe live secret key exposed in a public response",
    }
    for item in found:
        assert EXAMPLE_AWS_KEY not in item.evidence and "a1B2c3D4e5F6g7H8i9J0k1L2" not in item.evidence


def test_redaction_never_returns_the_whole_value():
    assert "…" in redact("abcdefghijklmnopqrstuvwxyz") and redact("abcdefghijklmnopqrstuvwxyz") != "abcdefghijklmnopqrstuvwxyz"
    assert redact("short") != "short"


def test_placeholders_and_public_keys_are_not_high_severity():
    assert scan_text('password: "your_password_here_1234"') == []
    assert scan_text('apiSecret = "changeme-changeme-changeme"') == []
    found = SecretsCheck().run(context([page(body='<script>key="AIzaSyA1234567890abcdefghijklmnopqrstuv"</script>')]))
    assert [item.severity for item in found] == ["info"]


def test_database_url_with_real_looking_password():
    hits = scan_text('db = "postgres://app:Sup3rS3cretPw@db.internal.acme.test:5432/app"')
    assert [rule.id for rule, _value in hits] == ["database-url"]
    assert scan_text('db = "postgres://user:password_example@localhost/db"') == []


def test_unsigned_jwt_without_expiry():
    found = JwtCheck().run(context([page(body=f"<script>t='{UNSIGNED_JWT}'</script>")]))
    assert titles(found) == {
        "Site issues an unsigned JSON Web Token",
        "JSON Web Token has no expiry",
        "JSON Web Token carries sensitive-looking claims",
    }


def test_text_that_only_looks_like_a_jwt_is_ignored():
    assert JwtCheck().run(context([page(body="eyJhbGciOiJIUzI1NiJ9abc.eyJub3RqC29uIjp0cnVlfQzzz.sig")])) == []


# --- CORS ---------------------------------------------------------------------


def _cors_routes(reflect=True, credentials=True, null=False):
    def answer(_method, headers):
        origin = headers.get("Origin")
        pairs = [("Content-Type", "application/json")]
        if origin and ((reflect and origin != "null") or (null and origin == "null")):
            pairs.append(("Access-Control-Allow-Origin", origin))
            if credentials:
                pairs.append(("Access-Control-Allow-Credentials", "true"))
        return Observation(status_code=200, headers=tuple(pairs))

    return {"/api/me": answer}


def test_reflected_origin_with_credentials_is_high():
    ctx = context([page("/api/me", body="{}", content_type="application/json")], routes=_cors_routes())
    found = CorsCheck().run(ctx)
    assert [(item.title, item.severity) for item in found] == [("CORS trusts any website and shares the visitor's session", "high")]
    assert PROBE_ORIGIN in found[0].evidence
    assert all(method == "GET" for method, _url, _headers in ctx.calls)


def test_reflected_origin_without_credentials_is_low():
    found = CorsCheck().run(context([page("/api/me", body="{}", content_type="application/json")], routes=_cors_routes(credentials=False)))
    assert [item.severity for item in found] == ["low"]


def test_null_origin_and_fixed_allow_list():
    found = CorsCheck().run(context([page("/api/me")], routes=_cors_routes(reflect=False, null=True)))
    assert titles(found) == {"CORS trusts the `null` origin with credentials"}
    fixed = {"/api/me": text("{}", "application/json", headers={"Access-Control-Allow-Origin": "https://app.example.com"})}
    assert CorsCheck().run(context([page("/api/me")], routes=fixed)) == []


# --- server configuration -----------------------------------------------------


def test_methods_caching_and_security_txt():
    routes = {
        ("OPTIONS", "/"): Observation(status_code=200, headers=(("Allow", "GET, POST, TRACE, DELETE"),)),
        "/.well-known/security.txt": text("Contact: mailto:sec@example.com\nExpires: 2001-01-01T00:00:00Z\n"),
    }
    cached = page(headers={"Cache-Control": "public, max-age=60"}, cookies=["sessionid=1; Secure; HttpOnly; SameSite=Lax"])
    found = ServerConfigCheck().run(context([cached], routes=routes))
    assert titles(found) == {
        "Server advertises the TRACE method",
        "Server advertises write methods on the site root",
        "Response that sets a session cookie is marked cacheable",
        "security.txt has expired",
    }


def test_missing_security_txt_is_informational_and_spa_fallback_does_not_count_as_present():
    routes = {"/.well-known/security.txt": text("<html><body>Contact: us</body></html>", "text/html")}
    found = ServerConfigCheck().run(context([page()], routes=routes))
    assert [(item.title, item.severity) for item in found] == [("No security.txt contact file", "info")]


# --- exposed files ------------------------------------------------------------


def test_exposed_files_need_a_matching_fingerprint():
    routes = {
        "/.git/HEAD": text("ref: refs/heads/main\n"),
        "/.env": text("DB_PASSWORD=hunter2\nAPP_KEY=abc\n"),
        "/backup.sql": text("<html><body>Login</body></html>", "text/html"),  # soft 404
        "/.aws/credentials": text("nothing here"),
    }
    found = ExposedFilesCheck().run(context([page()], routes=routes))
    assert titles(found) == {
        "Git repository is publicly accessible (/.git/HEAD)",
        "Environment file is publicly accessible (/.env)",
    }
    assert all("hunter2" not in item.evidence for item in found)


def test_a_site_that_answers_every_path_the_same_way_produces_nothing():
    class Everything(dict):
        def get(self, key, default=None):
            return text("ref: refs/heads/main\n")

    assert ExposedFilesCheck().run(context([page()], routes=Everything())) == []


def test_actuator_index_severity_follows_what_it_lists():
    index = {"_links": {"self": {"href": "/actuator"}, "health": {"href": "/actuator/health"}, "env": {"href": "/actuator/env"}}}
    found = ExposedFilesCheck().run(context([page()], routes={"/actuator": text(json.dumps(index), "application/json")}))
    assert [(item.severity, "env" in item.evidence) for item in found] == [("high", True)]


def test_source_map_and_directory_listing_use_what_the_page_references():
    script = page("/static/app.js", body="x()\n//# sourceMappingURL=app.js.map", content_type="application/javascript")
    home = page(body='<html><script src="/static/app.js"></script></html>')
    routes = {
        "/static/app.js.map": text('{"version":3,"sources":["a.ts"],"sourcesContent":["x"]}', "application/json"),
        "/static/": text("<html><title>Index of /static</title></html>", "text/html"),
    }
    found = ExposedFilesCheck().run(context([home], scripts=[script], routes=routes))
    assert titles(found) == {"JavaScript source map is downloadable", "Directory listing is enabled"}


# --- API surface --------------------------------------------------------------


SPEC = {
    "openapi": "3.0.0",
    "security": [{"bearer": []}],
    "servers": [{"url": "https://app.example.com/v1"}],
    "paths": {
        "/users": {"get": {}},
        "/status": {"get": {"security": []}},
        "/users/{id}": {"get": {}},
        "/search": {"get": {"parameters": [{"in": "query", "name": "q", "required": True}]}},
        "/items": {"post": {}},
    },
}


def test_only_plain_get_operations_are_selected_and_security_is_inherited():
    assert get_operations(SPEC) == [("/v1/users", True), ("/v1/status", False)]


def test_secured_endpoint_that_answers_anonymously():
    routes = {
        "/openapi.json": text(json.dumps(SPEC), "application/json"),
        "/v1/users": text('[{"id":1,"email":"a@b.co"}]', "application/json"),
        "/v1/status": text('{"ok":true}', "application/json"),
    }
    found = ApiSurfaceCheck().run(context([page()], routes=routes))
    assert titles(found) == {
        "API description is publicly accessible",
        "Endpoint documented as authenticated answers without credentials",
    }


def test_secured_endpoint_that_refuses_is_clean():
    routes = {
        "/openapi.json": text(json.dumps(SPEC), "application/json"),
        "/v1/users": text('{"error":"unauthorized"}', "application/json", status=401),
    }
    assert titles(ApiSurfaceCheck().run(context([page()], routes=routes))) == {"API description is publicly accessible"}


def test_sensitive_fields_in_a_json_response_are_reported_without_the_value():
    body = '{"id":1,"password_hash":"$2b$12$abcdefghijklmnop"}'
    found = ApiSurfaceCheck().run(context([page("/api/u", body=body, content_type="application/json")]))
    assert [item.title for item in found] == ["API response includes secret-looking fields"]
    assert "$2b$" not in found[0].evidence


def test_graphql_introspection():
    routes = {
        "/graphql?query=%7B__typename%7D": text('{"data":{"__typename":"Query"}}', "application/json"),
        "/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D": text('{"data":{"__schema":{"queryType":{"name":"Query"}}}}', "application/json"),
    }
    assert "GraphQL introspection is enabled" in titles(ApiSurfaceCheck().run(context([page()], routes=routes)))


# --- transport ----------------------------------------------------------------


def _transport(certificate, legacy=None):
    check = TransportCheck()
    check.certificate_probe = lambda *_args: certificate
    check.legacy_probe = lambda *_args: legacy
    return check


def _soon(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%b %d %H:%M:%S %Y GMT")


def test_expiring_untrusted_and_legacy_tls():
    resolver = lambda host, port: ["93.184.216.34"]  # noqa: E731
    redirecting = {"http://app.example.com/": Observation(status_code=301, location_header="https://app.example.com/")}
    ok = {"valid": True, "protocol": "TLSv1.3", "not_after": _soon(400), "error": ""}
    assert _transport(ok).run(context([page()], routes=redirecting, resolver=resolver)) == []

    expiring = dict(ok, not_after=_soon(3))
    found = _transport(expiring, legacy="TLS 1.0").run(context([page()], routes=redirecting, resolver=resolver))
    assert {item.title.split(" in ")[0] for item in found} == {"TLS certificate expires", "Server accepts TLS 1.0"}

    untrusted = {"valid": False, "protocol": "", "not_after": "", "error": "self-signed certificate"}
    found = _transport(untrusted).run(context([page()], routes=redirecting, resolver=resolver))
    assert titles(found) == {"TLS certificate is not trusted"}


def test_plain_http_that_serves_content_is_reported():
    resolver = lambda host, port: ["93.184.216.34"]  # noqa: E731
    ok = {"valid": True, "protocol": "TLSv1.3", "not_after": _soon(400), "error": ""}
    serving = {"http://app.example.com/": Observation(status_code=200)}
    assert titles(_transport(ok).run(context([page()], routes=serving, resolver=resolver))) == {"Plain HTTP does not redirect to HTTPS"}


def test_days_until_handles_bad_input():
    assert days_until("") is None and days_until("not a date") is None


# --- DNS ----------------------------------------------------------------------


def _dns(records):
    def lookup(name, record):
        value = records.get((name, record), [])
        return value

    return lookup


def test_organisation_domain():
    assert organisation_domain("api.eu.example.com") == "example.com"
    assert organisation_domain("shop.example.co.uk") == "example.co.uk"


def test_email_authentication_records():
    check = EmailAuthCheck()
    check.lookup = _dns({})
    assert titles(check.run(context())) == {"No SPF record for example.com", "No DMARC record for example.com"}

    check.lookup = _dns({("example.com", "TXT"): ["v=spf1 +all"], ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]})
    assert titles(check.run(context())) == {
        "SPF record for example.com allows every sender",
        "DMARC policy for example.com does not block spoofed email",
    }

    check.lookup = _dns({("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"], ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]})
    assert check.run(context()) == []


def test_dangling_cname_needs_the_provider_placeholder_page():
    check = TakeoverCheck()
    check.lookup = _dns({("app.example.com", "CNAME"): ["acme.github.io"]})
    live = context([page(body="<html>Welcome to Acme</html>")])
    assert check.run(live) == []
    dead = context([page(body="<p>There isn't a GitHub Pages site here.</p>", status=404)])
    assert titles(check.run(dead)) == {"Subdomain points at an unclaimed GitHub Pages resource"}


def test_dangling_cname_to_a_name_that_no_longer_exists():
    check = TakeoverCheck()
    check.lookup = _dns({("app.example.com", "CNAME"): ["old-app.azurewebsites.net"], ("old-app.azurewebsites.net", "A"): None})
    assert titles(check.run(context())) == {"Subdomain points at an unclaimed Microsoft Azure resource"}
    check.lookup = _dns({("app.example.com", "CNAME"): ["old-app.azurewebsites.net"], ("old-app.azurewebsites.net", "A"): ["20.1.2.3"]})
    assert check.run(context()) == []
