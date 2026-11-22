"""Local HTTP fixture used to exercise the scanner against real sockets.

The process listens on 127.0.0.1 only. It is a test double for three outcomes:
/login honors `next`, /floor keeps the redirect on this host, and /oauth/start
always redirects to Google.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse


class RedirectFixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        self.seen.append(self.path)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/login":
            target = params.get("next", ["http://127.0.0.1/"])[0]
            self._redirect(target)
            return
        if parsed.path == "/floor":
            nxt = params.get("next", [""])[0]
            self._redirect(f"/office?next={nxt}")
            return
        if parsed.path == "/oauth/start":
            self._redirect("https://www.google.com")
            return
        if parsed.path == "/newsletter/tracking.php":
            target = params.get("url", [""])[0]
            if target.startswith("//google.com/") or "%2e%2e" in target:
                self._redirect(target)
                return
            self._redirect("/")
            return
        if parsed.path == "/chain":
            target = params.get("next", [""])[0]
            self._redirect(f"/chain/hop?next={quote(target, safe='')}")
            return
        if parsed.path == "/chain/hop":
            target = params.get("next", [""])[0]
            if target.startswith("//") or "google.com" in target:
                self._redirect(target)
                return
            self._send(200, b"stay")
            return
        if parsed.path == "/":
            body = (
                b"<html><body><a href=\"/newsletter/tracking.php\">tracking</a>"
                b"<a href=\"/about\">about</a></body></html>"
            )
            self._send(200, body, "text/html")
            return
        if parsed.path == "/sitemap.xml":
            host = self.headers.get("Host", "127.0.0.1")
            xml = (
                f"<urlset><url><loc>http://{host}/login</loc></url></urlset>"
            ).encode()
            self._send(200, xml, "application/xml")
            return
        if parsed.path == "/meta":
            target = params.get("url", [""])[0]
            if target.startswith("//") or target.startswith("http"):
                page = f'<html><meta http-equiv="refresh" content="0;url={target}"></html>'.encode()
            else:
                page = b"<html><p>See https://www.google.com for an example.</p></html>"
            self._send(200, page, "text/html")
            return
        body = b"ok" if parsed.path == "/plain" else b"missing"
        status = 200 if parsed.path == "/plain" else 404
        self._send(status, body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        self._send(405, b"GET only")

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        return


def serve(port: int = 8765) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), RedirectFixtureHandler)
    print(f"listening http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve()
