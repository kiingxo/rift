import socket

import httpx

from rift.config import ScanConfig
from rift.http_client import HttpxRequester, SystemResolver

HOST = "app.example.com"
CONFIG = ScanConfig(allowlist=(HOST,), min_interval_seconds=0, max_workers=1)


def _answer(ip: str, port: int):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


def test_private_dns_answer_does_not_open_a_connection():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    def lookup(host, port):
        return _answer("10.1.2.3", port)

    requester = HttpxRequester(
        CONFIG,
        transport=httpx.MockTransport(handler),
        resolver=SystemResolver(CONFIG, lookup=lookup),
    )
    observation = requester.get(f"https://{HOST}/login")
    assert observation.safety_block
    assert "10.1.2.3" in (observation.error or "")
    assert captured == []
    requester.close()


def test_changed_dns_answer_is_rejected_before_connect():
    captured = []
    answers = ["1.1.1.1", "8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    def lookup(host, port):
        return _answer(answers.pop(0), port)

    requester = HttpxRequester(
        CONFIG,
        transport=httpx.MockTransport(handler),
        resolver=SystemResolver(CONFIG, lookup=lookup),
    )
    observation = requester.get(f"https://{HOST}/login")
    assert observation.safety_block
    assert "rebinding" in (observation.error or "").lower()
    assert captured == []
    requester.close()


def test_request_is_pinned_to_the_checked_ip_and_does_not_follow():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(302, headers={"Location": "https://www.google.com"})

    def lookup(host, port):
        return _answer("8.8.8.8", port)

    requester = HttpxRequester(
        CONFIG,
        transport=httpx.MockTransport(handler),
        resolver=SystemResolver(CONFIG, lookup=lookup),
    )
    observation = requester.get(f"https://{HOST}/login?utm=1")
    assert observation.status_code == 302
    assert observation.location_header == "https://www.google.com"
    assert len(captured) == 1
    request = captured[0]
    assert request.url.host == "8.8.8.8"
    assert request.headers["host"] == HOST
    assert request.extensions["sni_hostname"] == HOST
    assert request.url.path == "/login"
    assert "utm=1" in str(request.url)
    assert "cookie" not in request.headers
    assert "authorization" not in request.headers
    assert requester.client.follow_redirects is False
    assert requester.client.max_redirects == 0
    requester.close()


def test_external_host_is_refused_without_a_lookup():
    captured = []
    lookups = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    def lookup(host, port):
        lookups.append(host)
        return _answer("8.8.8.8", port)

    requester = HttpxRequester(
        CONFIG,
        transport=httpx.MockTransport(handler),
        resolver=SystemResolver(CONFIG, lookup=lookup),
    )
    observation = requester.get("https://www.google.com/")
    assert observation.safety_block
    assert captured == []
    assert lookups == []
    requester.close()


def test_metadata_address_from_dns_is_refused():
    def lookup(host, port):
        return _answer("169.254.169.254", port)

    requester = HttpxRequester(
        CONFIG,
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        resolver=SystemResolver(CONFIG, lookup=lookup),
    )
    observation = requester.get(f"https://{HOST}/login")
    assert observation.safety_block
    assert "metadata" in (observation.error or "").lower()
    requester.close()
