"""Two local sites for exercising every check over real sockets.

WeakSite gets nearly everything wrong on purpose. HardenedSite sets every
header correctly and answers every unknown path with the same HTML page, the
way a single-page app does, so it doubles as the false-positive test.

Both listen on 127.0.0.1 only. Every credential in this file is a published
documentation example or made up; none of them work anywhere.

Run one by hand to try the scanner against it:

    python -m tests.weak_site          # weak site on http://127.0.0.1:8770
    python -m tests.weak_site hardened # hardened site on the same port
"""

from __future__ import annotations

import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


# An unsigned token with no expiry and a sensitive claim.
UNSIGNED_JWT = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '42', 'role': 'admin', 'password': 'hunter2'})}."
# The access key ID AWS uses in its own documentation.
EXAMPLE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

WEAK_HOME = f"""<!doctype html>
<html><head><title>Acme Portal</title>
<script src="/static/app.js"></script>
<script src="https://cdn.example.net/widgets/v2/widget.js"></script>
<link rel="stylesheet" href="/static/site.css">
</head><body>
<h1>Acme Portal</h1>
<a href="/about">About</a> <a href="/api/users">Users API</a>
<form method="get" action="/session"><input name="user"><input type="password" name="pass"></form>
<!-- build host 10.20.30.40 -->
</body></html>"""

WEAK_JS = f"""const config = {{
  awsKey: "{EXAMPLE_AWS_KEY}",
  session: "{UNSIGNED_JWT}",
  db: "postgres://app:Sup3rS3cretPw@db.internal.acme.test:5432/app"
}};
//# sourceMappingURL=app.js.map
"""

TRACEBACK = """<html><body><pre>Traceback (most recent call last):
  File "/srv/acme/app/views.py", line 88, in about
    return render(page)
KeyError: 'page'</pre></body></html>"""

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Acme", "version": "1"},
    "security": [{"bearer": []}],
    "paths": {
        "/api/users": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/api/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/api/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
    },
}
USERS = [{"id": 1, "email": "ada@acme.test", "password_hash": "$2b$12$abcdefghijklmnopqrstuv"}]

# The signed-in area. A made-up session for a made-up test account.
TEST_COOKIE_NAME = "acme_session"
TEST_SESSION = "weak-test-session-7f3a9c1e2b5d"
TEST_EMAIL = "alice@acme.test"
# Paths that would change the account. A signed-in scan must never request them.
ACTION_PATHS = ("/logout", "/account/delete", "/account/archive-all", "/account/export")


def account_page(session_link: bool) -> str:
    link = f'<a href="/account/settings?sid={TEST_SESSION}">Settings</a>' if session_link else '<a href="/account/settings">Settings</a>'
    leak = f'<script>window.SESSION = "{TEST_SESSION}";</script>' if session_link else ""
    return f"""<!doctype html>
<html><head><title>Your account</title>{leak}</head><body>
<h1>Signed in as {TEST_EMAIL}</h1>
<a href="/account/invoices">Invoices</a> {link}
<a href="/logout">Sign out</a> <a href="/account/delete">Delete account</a>
<a href="/account/archive-all">Archive everything</a> <a href="/account/export?action=delete">Export and delete</a>
</body></html>"""


INVOICE_LIST = """<!doctype html><html><head><title>Invoices</title></head><body>
<h1>Invoices</h1><a href="/account/invoices/1042">Invoice 1042</a></body></html>"""
INVOICE = f"""<!doctype html><html><head><title>Invoice 1042</title></head><body>
<h1>Invoice 1042</h1><p>Billed to {TEST_EMAIL}. Total 120.00</p></body></html>"""


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4.1"
    sys_version = ""
    # Every path requested, with whether it carried the session. Tests read and reset it.
    requested: list = []

    def log_message(self, fmt: str, *args) -> None:
        return

    def signed_in(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        found = any(part.strip() == f"{TEST_COOKIE_NAME}={TEST_SESSION}" for part in cookie.split(";"))
        _Base.requested.append((self.path, found))
        return found

    def _send(self, status: int, body: bytes | str, content_type: str = "text/html", headers: dict | None = None, cookies=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


class WeakSite(_Base):
    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(200, b"", headers={"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        cors = {}
        origin = self.headers.get("Origin")
        if origin:
            cors = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
        signed_in = self.signed_in()
        to_login = {"Location": "/login"}
        if path == "/account":
            # Private, but sent with no Cache-Control, a session in a link, and the session in a script.
            if signed_in:
                self._send(200, account_page(session_link=True))
            else:
                self._send(302, b"", headers=to_login)
        elif path == "/account/settings":
            if signed_in:
                self._send(200, f"<html><body>Settings for {TEST_EMAIL}</body></html>", headers={"Cache-Control": "public, max-age=300"})
            else:
                self._send(401, "<html><body>Sign in first</body></html>")
        elif path == "/account/invoices":
            if signed_in:
                self._send(200, INVOICE_LIST, headers={"Cache-Control": "no-store"})
            else:
                self._send(302, b"", headers=to_login)
        elif path == "/account/invoices/1042":
            # Broken: the invoice is served whether or not anyone is signed in.
            self._send(200, INVOICE, headers={"Cache-Control": "no-store"})
        elif path in ACTION_PATHS:
            self._send(200, "<html><body>Done</body></html>")
        elif path == "/":
            self._send(
                200,
                WEAK_HOME,
                headers={"X-Powered-By": "PHP/5.6.1", "Cache-Control": "public, max-age=600", **cors},
                cookies=["sessionid=abc123; Path=/", "theme=dark; Path=/"],
            )
        elif path == "/about":
            self._send(500, TRACEBACK)
        elif path == "/static/app.js":
            self._send(200, WEAK_JS, "application/javascript")
        elif path == "/static/app.js.map":
            self._send(200, json.dumps({"version": 3, "file": "app.js", "sources": ["src/app.ts"], "sourcesContent": ["// original"]}), "application/json")
        elif path == "/static/":
            self._send(200, "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1></body></html>")
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.env":
            self._send(200, "APP_KEY=base64:not-a-real-key\nDB_PASSWORD=not-a-real-password\n", "text/plain")
        elif path == "/openapi.json":
            self._send(200, json.dumps(OPENAPI), "application/json")
        elif path == "/api/users":
            self._send(200, json.dumps(USERS), "application/json", headers=cors)
        elif path == "/api/health":
            self._send(200, json.dumps({"status": "ok"}), "application/json", headers=cors)
        elif path == "/graphql":
            asked = query.get("query", [""])[0]
            if "__schema" in asked:
                self._send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}), "application/json")
            elif "__typename" in asked:
                self._send(200, json.dumps({"data": {"__typename": "Query"}}), "application/json")
            else:
                self._send(400, json.dumps({"errors": [{"message": "Must provide query string."}]}), "application/json")
        elif path == "/go":
            target = query.get("next", ["/"])[0]
            self._send(302, b"", headers={"Location": target})
        else:
            self._send(404, "<html><body>Not found</body></html>")


SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}
HARDENED_HOME = """<!doctype html>
<html><head><title>Acme</title><script src="/assets/app.js"></script></head>
<body><h1>Acme</h1><a href="/pricing">Pricing</a>
<form method="post" action="/session"><input type="password" name="pass"></form></body></html>"""


class HardenedSite(_Base):
    server_version = "acme"
    # Set to False by a test to play "the user signed out": the server forgets the session.
    session_valid = True

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"", headers={"Allow": "GET, HEAD, OPTIONS"})

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        signed_in = self.signed_in() and HardenedSite.session_valid
        if path in {"/account", "/account/settings", "/account/invoices", "/account/invoices/1042"}:
            if signed_in:
                links = '<a href="/account/settings">Settings</a> <a href="/account/invoices/1042">Invoice</a> <a href="/logout">Sign out</a>'
                self._send(200, f"<!doctype html><html><head><title>Account</title></head><body><h1>Signed in as {TEST_EMAIL}</h1>{links}</body></html>", headers=SECURE_HEADERS)
            else:
                self._send(302, b"", headers={**SECURE_HEADERS, "Location": "/login"})
        elif path in ACTION_PATHS:
            self._send(200, HARDENED_HOME, headers=SECURE_HEADERS)
        elif path == "/assets/app.js":
            self._send(200, "console.log('acme');", "application/javascript", headers={"X-Content-Type-Options": "nosniff"})
        elif path == "/.well-known/security.txt":
            self._send(200, "Contact: mailto:security@acme.test\nExpires: 2099-01-01T00:00:00Z\n", "text/plain")
        else:
            # Single-page-app behaviour: every other path returns the same page with 200.
            self._send(
                200,
                HARDENED_HOME,
                headers=SECURE_HEADERS,
                cookies=["__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"] if path == "/" else (),
            )


# ---- a single-page app with a PocketBase-style API on another port ----------
#
# The front end serves an empty HTML shell and JavaScript; the account's data
# only comes from the API, which reads the session from the Authorization
# header. The main bundle is padded past 200 KB so the collection calls sit
# where a 200 KB read would never reach, and one collection is only named in a
# chunk the bundle loads later.

SPA_TOKEN = "spa-test-token-91c4e7a2f0b3"
SPA_ADDRESSES_NEVER_READ = (
    "/api/realtime",
    "/api/settings/test/email",
    "/api/backups",
    "/api/files/token",
    "/api/collections/patients/records/delete",
    "/api/auth/sendPhoneNumberOTP",
    "/api/orders/cancel",
)
SPA_SHELL = """<!doctype html><html><head><title>Acme Health</title>
<script type="module" crossorigin src="/assets/index-Ab12Cd34.js"></script>
<link rel="modulepreload" crossorigin href="/assets/vendor-Ef56Gh78.js">
</head><body><div id="root"></div></body></html>"""


def spa_bundle(api_port: int) -> str:
    api = f"http://127.0.0.1:{api_port}"
    head = (
        f'const pb = new PocketBase("{api}");const API="{api}/api/";\n'
        'const sdk={list:"/api/collections/",realtime:"/api/realtime",health:"/api/health",'
        'mail:"/api/settings/test/email",backups:"/api/backups",token:"/api/files/token"};\n'
        'const other="https://api.acme-health.test/api/";const docs="https://www.w3.org/2000/svg";\n'
        'export const me=()=>fetch("/api/me");\n'
        f'const rest=rg({{baseUrl:"{api}/api/",prepareHeaders:h=>h}});\n'
        'export const profile=()=>http.get("auth/profile");\n'
        'export const claims=()=>http.get("hmo/claim");\n'
        'export const stop=()=>http.get("orders/cancel");\n'
        'export const lookup=(k)=>params.get("content-type");\n'
        'const visits=b=>({list:b.query({query:()=>"/visits?limit=All"}),'
        'add:b.query({query:(v)=>({url:"visits",method:"POST",body:v})}),'
        'one:b.query({query:(id)=>`/visits/${id}`})});\n'
        "export const send=()=>http.get(`${API}auth/sendPhoneNumberOTP`);\n"
        "export const patient=(id)=>fetch(`/api/patients/${id}`);\n"
        'export const drop=()=>fetch("/api/collections/patients/records/delete");\n'
        'const Invoices=()=>import("./Invoices-Zx90Yw87.js");\n'
    )
    padding = "/*" + ("x" * 250_000) + "*/\n"
    tail = 'export const patients=()=>pb.collection("patients").getList(1,20);\n'
    return head + padding + tail


SPA_CHUNK = 'export const invoices=()=>pb.collection("invoices").getFullList();\n'


class SpaFront(_Base):
    api_port = 0

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        _Base.requested.append((self.path, bool(self.headers.get("Authorization"))))
        if path == "/":
            self._send(200, SPA_SHELL)
        elif path == "/assets/index-Ab12Cd34.js":
            self._send(200, spa_bundle(SpaFront.api_port), "application/javascript")
        elif path == "/assets/vendor-Ef56Gh78.js":
            self._send(200, "export const v=1;", "application/javascript")
        elif path == "/assets/Invoices-Zx90Yw87.js":
            self._send(200, SPA_CHUNK, "application/javascript")
        else:
            self._send(200, SPA_SHELL)


class SpaApi(_Base):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        signed = self.headers.get("Authorization", "") in {SPA_TOKEN, f"Bearer {SPA_TOKEN}"}
        _Base.requested.append((self.path, signed))
        if path == "/api/auth/profile":
            if signed:
                self._send(200, json.dumps({"id": "u1", "email": TEST_EMAIL}), "application/json", headers={"Cache-Control": "no-store"})
            else:
                self._send(401, json.dumps({"message": "Unauthorized"}), "application/json")
        elif path == "/api/hmo/claim":
            if signed:
                self._send(200, json.dumps({"data": [{"id": "c1", "status": "open"}]}), "application/json", headers={"Cache-Control": "no-store"})
            else:
                self._send(401, json.dumps({"message": "Unauthorized"}), "application/json")
        elif path == "/api/visits":
            if signed:
                self._send(200, json.dumps({"data": [{"id": "v1", "patient": "p1"}], "total": 1}), "application/json")
            else:
                self._send(401, json.dumps({"message": "Unauthorized"}), "application/json")
        elif path == "/api/me":
            if signed:
                self._send(200, json.dumps({"email": TEST_EMAIL}), "application/json", headers={"Cache-Control": "no-store"})
            else:
                self._send(401, json.dumps({"message": "Unauthorized"}), "application/json")
        elif path == "/api/collections/patients/records":
            # Private: the list rule filters by owner, so nobody signed in gets an empty list.
            items = [{"id": "p1", "name": "Test Patient", "owner": "u1"}] if signed else []
            self._send(200, json.dumps({"page": 1, "perPage": 1, "totalItems": len(items), "items": items}), "application/json")
        elif path == "/api/collections/invoices/records":
            # Public by mistake: an empty list rule, so anyone reads every invoice.
            items = [{"id": "i1", "billed_to": TEST_EMAIL, "total": 120}]
            self._send(200, json.dumps({"page": 1, "perPage": 1, "totalItems": 1, "items": items}), "application/json")
        elif path == "/api/health":
            self._send(200, json.dumps({"code": 200, "message": "API is healthy."}), "application/json")
        else:
            self._send(404, json.dumps({"message": "Not found"}), "application/json")


def serve(handler=WeakSite, port: int = 8770) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"{handler.__name__} listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve(HardenedSite if "hardened" in sys.argv[1:] else WeakSite)
