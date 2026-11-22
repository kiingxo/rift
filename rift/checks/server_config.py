"""Server configuration: allowed methods, default pages, caching of private pages, security.txt."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from rift.checks.base import PROBE, Check, CheckContext, clip, merge_by_title
from rift.checks.cookies import parse_set_cookie
from rift.models import Finding, Severity

_DEFAULT_PAGES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nginx", re.compile(r"<title>Welcome to nginx!</title>")),
    ("Apache", re.compile(r"<title>Apache2 (?:Ubuntu|Debian) Default Page|<title>Test Page for the Apache HTTP Server")),
    ("IIS", re.compile(r"<title>IIS Windows Server</title>|<title>IIS7</title>")),
    ("Tomcat", re.compile(r"<title>Apache Tomcat/[\d.]+</title>")),
)
_DEPRECATED_HEADERS = {
    "feature-policy": "Replaced by Permissions-Policy.",
    "expect-ct": "Certificate Transparency is now enforced by browsers without it.",
    "public-key-pins": "Removed from browsers because a mistake could lock users out permanently.",
}
_EXPIRES = re.compile(r"(?mi)^Expires:\s*(\S+)")
_CONTACT = re.compile(r"(?mi)^Contact:\s*\S+")


class ServerConfigCheck(Check):
    id = "server-config"
    title = "Server configuration"
    summary = "Risky HTTP methods, default server pages, private pages that caches may store, and security.txt."
    kind = PROBE

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        found.extend(self._methods(ctx))
        found.extend(self._defaults(ctx))
        found.extend(self._caching(ctx))
        found.extend(self._deprecated(ctx))
        found.extend(self._security_txt(ctx))
        return merge_by_title(found)

    def _methods(self, ctx: CheckContext) -> list[Finding]:
        response = ctx.fetch(ctx.origin + "/", method="OPTIONS", include_body=False)
        if response.status_code is None:
            return []
        allowed = {item.strip().upper() for item in (response.header("allow") or "").split(",") if item.strip()}
        out: list[Finding] = []
        tracing = sorted(allowed & {"TRACE", "TRACK"})
        if tracing:
            out.append(
                self.finding(
                    ctx,
                    title="Server advertises the TRACE method",
                    severity=Severity.LOW.value,
                    evidence=f"OPTIONS / returned Allow: {clip(response.header('allow') or '', 160)}",
                    explanation="TRACE echoes the request back, including headers. It is a debugging feature with no use in production.",
                    remediation="Disable TRACE (`TraceEnable off` in Apache; nginx does not support it by default).",
                    cwe="CWE-16",
                    owasp="A05:2021 Security Misconfiguration",
                    confidence="medium",
                )
            )
        writing = sorted(allowed & {"PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND", "MKCOL"})
        if writing:
            out.append(
                self.finding(
                    ctx,
                    title="Server advertises write methods on the site root",
                    severity=Severity.INFO.value,
                    evidence=f"OPTIONS / returned Allow: {clip(response.header('allow') or '', 160)}",
                    explanation=(
                        f"The root path lists {', '.join(writing)}. Rift does not send these methods, so this is "
                        "only what the server says it accepts. Review whether they are needed and protected."
                    ),
                    remediation="Allow only the methods each route needs, and require authentication for every method that changes data.",
                    cwe="CWE-650",
                    owasp="A05:2021 Security Misconfiguration",
                    confidence="low",
                )
            )
        return out

    def _defaults(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        for page in ctx.pages:
            for product, pattern in _DEFAULT_PAGES:
                if page.body and pattern.search(page.body):
                    out.append(
                        self.finding(
                            ctx,
                            url=page.url,
                            title=f"Default {product} page is being served",
                            severity=Severity.LOW.value,
                            evidence=clip(pattern.search(page.body).group(0), 120),
                            explanation="A default install page means this host is not configured for its intended site. Forgotten hosts are rarely patched.",
                            remediation="Deploy the intended site, or take the host out of DNS if it is unused.",
                            cwe="CWE-1188",
                            owasp="A05:2021 Security Misconfiguration",
                        )
                    )
        return out

    def _caching(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        for page in ctx.pages:
            cookies = [parse_set_cookie(value) for value in page.header_all("set-cookie")]
            if not any(cookie is not None and cookie.is_session for cookie in cookies):
                continue
            cache = (page.header("cache-control") or "").lower()
            shared = "public" in cache or "s-maxage" in cache
            if shared and "no-store" not in cache and "private" not in cache:
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="Response that sets a session cookie is marked cacheable",
                        severity=Severity.MEDIUM.value,
                        evidence=f"Cache-Control: {clip(cache, 120)} · Set-Cookie present",
                        explanation="A shared cache or CDN may store this response and hand one user's session cookie to the next visitor.",
                        remediation="Send `Cache-Control: no-store` (or at least `private`) on any response that sets or depends on a session.",
                        cwe="CWE-525",
                        owasp="A04:2021 Insecure Design",
                    )
                )
        return out

    def _deprecated(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        for page in ctx.pages:
            for name, reason in _DEPRECATED_HEADERS.items():
                if page.header(name) is not None:
                    out.append(
                        self.finding(
                            ctx,
                            url=page.url,
                            title=f"Deprecated header `{name}` is still sent",
                            severity=Severity.INFO.value,
                            evidence=f"{name}: {clip(page.header(name) or '', 120)}",
                            explanation=f"Browsers no longer act on this header. {reason}",
                            remediation="Remove the header and use its current replacement where one exists.",
                            cwe="CWE-477",
                            owasp="A05:2021 Security Misconfiguration",
                        )
                    )
        return out

    def _security_txt(self, ctx: CheckContext) -> list[Finding]:
        response = ctx.fetch(ctx.origin + "/.well-known/security.txt")
        if response.status_code is None:
            return []
        body = response.body or ""
        present = response.status_code == 200 and "<html" not in body[:500].lower() and bool(_CONTACT.search(body))
        reference = "https://www.rfc-editor.org/rfc/rfc9116"
        if not present:
            return [
                self.finding(
                    ctx,
                    url=ctx.origin + "/.well-known/security.txt",
                    title="No security.txt contact file",
                    severity=Severity.INFO.value,
                    evidence=f"GET /.well-known/security.txt returned HTTP {response.status_code} with no Contact line.",
                    explanation="Researchers who find a problem have no published way to report it, so reports go nowhere or go public.",
                    remediation="Publish /.well-known/security.txt with a `Contact:` and an `Expires:` line (RFC 9116).",
                    cwe="CWE-1059",
                    owasp="A09:2021 Security Logging and Monitoring Failures",
                    reference=reference,
                )
            ]
        match = _EXPIRES.search(body)
        if match:
            try:
                expires = datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
            except ValueError:
                return []
            if expires < datetime.now(timezone.utc):
                return [
                    self.finding(
                        ctx,
                        url=ctx.origin + "/.well-known/security.txt",
                        title="security.txt has expired",
                        severity=Severity.INFO.value,
                        evidence=f"Expires: {match.group(1)}",
                        explanation="An expired file tells researchers the contact details may be stale.",
                        remediation="Update the `Expires:` date and confirm the contact still works.",
                        cwe="CWE-1059",
                        owasp="A09:2021 Security Logging and Monitoring Failures",
                        reference=reference,
                    )
                ]
        return []
