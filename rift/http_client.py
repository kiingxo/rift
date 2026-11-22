"""Read-only client that pins DNS, refuses private targets, and does not follow redirects."""

from __future__ import annotations

import asyncio
import http.cookiejar
import socket
import threading
import time
from typing import Callable, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

from rift.config import MAX_DOCUMENT_BYTES, MAX_SCRIPT_BYTES, ScanConfig
from rift.models import Observation
from rift.safety import (
    ScopeError,
    ensure_ip_allowed,
    is_ip_literal,
    is_metadata_host,
    normalize_host,
    validate_target,
)

Lookup = Callable[[str, int], Sequence[tuple]]

# Methods that do not change state on a well-behaved server.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Request headers a check may add. Anything else is refused, so a check cannot
# smuggle credentials, a different Host, or a request body through this client.
_ALLOWED_EXTRA_HEADERS = frozenset(
    {"origin", "accept", "access-control-request-method", "access-control-request-headers"}
)


def _refusing_jar() -> http.cookiejar.CookieJar:
    """A cookie jar that never stores anything.

    httpx keeps cookies a server sets and sends them on later requests. Rift
    sends no cookies of its own, and the signed-in comparison needs its
    anonymous requests to stay anonymous, so nothing is kept.
    """

    return http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))


class RateLimiter:
    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay < 0:
                delay = 0.0
            self._next = max(now, self._next) + self.min_interval
        if delay:
            time.sleep(delay)


def _getaddrinfo_timed(host: str, port: int, timeout: float):
    outcome: dict[str, object] = {}

    def _run() -> None:
        try:
            outcome["value"] = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except Exception as exc:  # noqa: BLE001 - returned to the caller below
            outcome["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise ScopeError(f"DNS resolution timed out for {host}")
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome["value"]


class SystemResolver:
    """Resolve a host twice and refuse any answer that is not a public IP.

    The HTTP client then connects to one of those checked addresses instead of
    letting the operating system resolve the name again. A DNS rebinding answer
    that flips to a private or metadata address cannot be used for the connection.
    """

    def __init__(self, config: ScanConfig, lookup: Lookup | None = None) -> None:
        self.config = config
        self._lookup = lookup or (lambda host, port: _getaddrinfo_timed(host, port, config.dns_timeout_seconds))

    def resolve(self, hostname: str, port: int) -> list[str]:
        host = normalize_host(hostname)
        if is_metadata_host(host):
            raise ScopeError("Cloud metadata hosts are blocked")
        if is_ip_literal(host):
            ensure_ip_allowed(host, allow_internal=self.config.allow_internal)
            return [host]
        first = self._collect(host, port)
        second = self._collect(host, port)
        if set(first) != set(second):
            raise ScopeError(
                f"DNS answers for {host} changed between checks; the request was aborted to prevent DNS rebinding"
            )
        return first

    def _collect(self, host: str, port: int) -> list[str]:
        try:
            infos = self._lookup(host, port)
        except ScopeError:
            raise
        except socket.gaierror as exc:
            raise ScopeError(f"DNS resolution failed for {host}") from exc
        addresses: list[str] = []
        for info in infos:
            ip = info[4][0]
            if "%" in ip:
                raise ScopeError("Scoped IPv6 addresses are blocked")
            ensure_ip_allowed(ip, allow_internal=self.config.allow_internal)
            if ip not in addresses:
                addresses.append(ip)
        if not addresses:
            raise ScopeError(f"No addresses found for {host}")
        return addresses


def pin_url(url: str, ip: str) -> str:
    parts = urlsplit(url)
    host = f"[{ip}]" if ":" in ip else ip
    netloc = f"{host}:{parts.port}" if parts.port is not None else host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def host_header_value(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port is not None:
        return f"{host}:{parts.port}"
    return host


def _short_error(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or exc.__class__.__name__
    if len(text) > 240:
        return text[:237] + "..."
    return text


class HttpxRequester:
    """Send scoped GET requests without following Location."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        resolver: SystemResolver | None = None,
        session=None,
    ) -> None:
        self.config = config
        # A SignedInSession (rift.session), or None for an anonymous scan.
        self.session = session
        self.resolver = resolver or SystemResolver(config)
        self.cancel = threading.Event()
        self.pause = threading.Event()
        self._limiters: dict[str, RateLimiter] = {}
        self._limiter_lock = threading.Lock()
        self._global = threading.Semaphore(max(1, config.max_workers))
        self._domain_slots: dict[str, threading.Semaphore] = {}
        self._cache: dict[tuple, Observation] = {}
        self._cache_lock = threading.Lock()
        self._async_client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        limits = httpx.Limits(
            max_connections=max(1, config.max_workers),
            max_keepalive_connections=max(1, config.max_workers),
        )
        timeout = httpx.Timeout(config.timeout_seconds, connect=config.connect_timeout_seconds)
        if transport is None:
            self._loop = asyncio.new_event_loop()
            self._loop_thread = threading.Thread(target=self._loop.run_forever, name="rift-http", daemon=True)
            self._loop_thread.start()
            self._async_client = asyncio.run_coroutine_threadsafe(self._open_async(timeout, limits), self._loop).result()
            self.client = None
        else:
            self.client = httpx.Client(
                transport=transport,
                timeout=timeout,
                follow_redirects=False,
                max_redirects=0,
                trust_env=False,
                limits=limits,
                headers={"User-Agent": config.user_agent},
                cookies=_refusing_jar(),
            )

    async def _open_async(self, timeout: httpx.Timeout, limits: httpx.Limits) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            max_redirects=0,
            trust_env=False,
            limits=limits,
            headers={"User-Agent": self.config.user_agent},
            cookies=_refusing_jar(),
        )

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
        if self._async_client is not None and self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._async_client.aclose(), self._loop).result(timeout=5)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=2)
        if self._loop is not None and not self._loop.is_running() and not self._loop.is_closed():
            self._loop.close()

    def __enter__(self) -> "HttpxRequester":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _limiter_for(self, host: str) -> RateLimiter:
        with self._limiter_lock:
            limiter = self._limiters.get(host)
            if limiter is None:
                limiter = RateLimiter(self.config.min_interval_seconds)
                self._limiters[host] = limiter
            return limiter

    def _slot_for(self, host: str) -> threading.Semaphore:
        with self._limiter_lock:
            slot = self._domain_slots.get(host)
            if slot is None:
                slot = threading.Semaphore(max(1, self.config.per_domain_concurrency))
                self._domain_slots[host] = slot
            return slot

    def _hold(self) -> bool:
        """Wait while paused. Return True when the scan is cancelled."""

        while self.pause is not None and self.pause.is_set():
            if self.cancel.is_set():
                return True
            time.sleep(0.2)
        return self.cancel.is_set()

    def get(self, url: str, include_body: bool = False) -> Observation:
        # A script is read only when its text is wanted. Other static files stay blocked.
        script = include_body and urlsplit(url).path.lower().endswith(".js")
        return self.request(url, include_body=include_body, allow_static=script)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        include_body: bool = False,
        allow_static: bool = False,
        signed_in: bool = False,
        max_bytes: int | None = None,
        app_read: bool = False,
    ) -> Observation:
        """Send one scoped, read-only request and return the first response.

        signed_in adds the test account's session, but only for a host the
        session was given for, and never to a URL that looks like an action.
        max_bytes reads a longer body (up to MAX_SCRIPT_BYTES), for scripts.
        app_read marks an address the app's own JavaScript reads with GET: only
        clear actions (sign out, delete, send, pay and similar) are refused.
        """

        verb = method.upper()
        if verb not in SAFE_METHODS:
            return Observation(error=f"Method {verb} is not sent by this scanner", safety_block=True)
        extra: dict[str, str] = {}
        for name, value in (headers or {}).items():
            if name.lower() not in _ALLOWED_EXTRA_HEADERS or any(ch in value for ch in "\r\n"):
                return Observation(error=f"Request header {name} is not sent by this scanner", safety_block=True)
            extra[name] = value
        if self._hold():
            return Observation(error="Scan cancelled")
        try:
            logical = validate_target(url, self.config, allow_static=allow_static)
        except ScopeError as exc:
            return Observation(error=str(exc), safety_block=True)
        parts = urlsplit(logical)
        hostname = parts.hostname or ""
        session = self.session if signed_in and self.session is not None and self.session.applies_to(hostname) else None
        if session is not None:
            from rift.session import looks_like_action

            if looks_like_action(logical, app_read=app_read):
                return Observation(
                    error="This URL looks like an action (sign out, delete, approve and similar), so it is not opened while signed in",
                    safety_block=True,
                    url=logical,
                )
        limit = MAX_DOCUMENT_BYTES if not max_bytes else max(1, min(int(max_bytes), MAX_SCRIPT_BYTES))
        cache_key = (logical, include_body, verb, tuple(sorted(extra.items())), session is not None, limit)
        with self._cache_lock:
            cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        with self._global:
            with self._slot_for(hostname):
                self._limiter_for(hostname).wait()
                if self._hold():
                    return Observation(error="Scan cancelled")
                with self._cache_lock:
                    cached = self._cache.get(cache_key)
                if cached is not None:
                    return cached
                sent_extra = dict(extra)
                if session is not None:
                    sent_extra.update(session.request_headers())
                if self._async_client is not None and self._loop is not None:
                    observation = asyncio.run_coroutine_threadsafe(
                        self._asend(logical, verb, sent_extra, include_body, limit),
                        self._loop,
                    ).result()
                else:
                    observation = self._send(logical, verb, sent_extra, include_body, limit)
                observation.signed_in = session is not None
        if observation.status_code is not None and not observation.error:
            with self._cache_lock:
                self._cache.setdefault(cache_key, observation)
        return observation

    def resolve_checked(self, hostname: str, port: int) -> list[str]:
        """Public addresses for a host, for checks that open their own socket."""

        return self.resolver.resolve(hostname, port)

    def _prepare(self, logical: str, extra: dict[str, str]):
        parts = urlsplit(logical)
        hostname = parts.hostname
        if not hostname:
            raise ScopeError("URL is missing a host")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses = self.resolver.resolve(hostname, port)
        pinned = pin_url(logical, addresses[0])
        extensions = {"sni_hostname": hostname} if parts.scheme == "https" else {}
        sent = {"Accept": "*/*", "Cache-Control": "no-store"}
        sent.update(extra)
        sent["Host"] = host_header_value(logical)
        return pinned, sent, extensions

    @staticmethod
    def _observe(logical: str, response: httpx.Response, raw: bytes | None, limit: int = MAX_DOCUMENT_BYTES) -> Observation:
        body = None
        if raw is not None:
            body = raw[:limit].decode("utf-8", errors="replace")
        return Observation(
            status_code=response.status_code,
            location_header=response.headers.get("location"),
            body=body,
            headers=tuple(response.headers.multi_items()),
            url=logical,
        )

    async def _asend(
        self, logical: str, method: str, extra: dict[str, str], include_body: bool, limit: int = MAX_DOCUMENT_BYTES
    ) -> Observation:
        assert self._async_client is not None
        try:
            pinned, sent, extensions = self._prepare(logical, extra)
        except ScopeError as exc:
            return Observation(error=str(exc), safety_block=True)
        try:
            async with self._async_client.stream(
                method, pinned, headers=sent, extensions=extensions, follow_redirects=False
            ) as response:
                raw = await _aread_capped(response, limit) if include_body and method != "HEAD" else None
                return self._observe(logical, response, raw, limit)
        except httpx.TimeoutException:
            return Observation(error="Request timed out")
        except httpx.HTTPError as exc:
            return Observation(error=f"Request failed: {_short_error(exc)}")
        except OSError as exc:
            return Observation(error=f"Request failed: {_short_error(exc)}")

    def _send(
        self, logical: str, method: str, extra: dict[str, str], include_body: bool, limit: int = MAX_DOCUMENT_BYTES
    ) -> Observation:
        try:
            pinned, sent, extensions = self._prepare(logical, extra)
        except ScopeError as exc:
            return Observation(error=str(exc), safety_block=True)
        try:
            with self.client.stream(
                method, pinned, headers=sent, extensions=extensions, follow_redirects=False
            ) as response:
                raw = _read_capped(response, limit) if include_body and method != "HEAD" else None
                return self._observe(logical, response, raw, limit)
        except httpx.TimeoutException:
            return Observation(error="Request timed out")
        except httpx.HTTPError as exc:
            return Observation(error=f"Request failed: {_short_error(exc)}")
        except OSError as exc:
            return Observation(error=f"Request failed: {_short_error(exc)}")


def _read_capped(response: httpx.Response, limit: int = MAX_DOCUMENT_BYTES) -> bytes:
    """Stop reading once the document cap is reached, so a huge file is not downloaded."""

    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    return b"".join(chunks)


async def _aread_capped(response: httpx.Response, limit: int = MAX_DOCUMENT_BYTES) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    return b"".join(chunks)
