"""Cookie attributes: Secure, HttpOnly, SameSite, and the __Host-/__Secure- prefixes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from rift.checks.base import Check, CheckContext, merge_by_title
from rift.models import Finding, Severity

_REF = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#security"

# Cookie names that carry a login or session. A stolen one is an account takeover.
_SESSION_NAME = re.compile(
    r"(sess|sid$|^sid|auth|token|jwt|login|logged|remember|identity|passport|"
    r"^connect\.sid$|^phpsessid$|^jsessionid$|^asp\.net_sessionid$|^laravel_session$|^_session)",
    re.IGNORECASE,
)
# Anti-forgery tokens are read by page script on purpose, so HttpOnly does not apply.
_CSRF_NAME = re.compile(r"(csrf|xsrf)", re.IGNORECASE)


@dataclass(frozen=True)
class Cookie:
    name: str
    secure: bool
    http_only: bool
    same_site: str
    domain: str
    path: str

    @property
    def is_session(self) -> bool:
        return bool(_SESSION_NAME.search(self.name)) and not _CSRF_NAME.search(self.name)


def parse_set_cookie(header: str) -> Cookie | None:
    parts = [part.strip() for part in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip()
    return Cookie(
        name=name,
        secure="secure" in attributes,
        http_only="httponly" in attributes,
        same_site=attributes.get("samesite", "").lower(),
        domain=attributes.get("domain", ""),
        path=attributes.get("path", ""),
    )


class CookieCheck(Check):
    id = "cookies"
    title = "Cookie flags"
    summary = "Session cookies missing Secure, HttpOnly or SameSite, and broken cookie prefixes."

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            for header in page.header_all("set-cookie"):
                cookie = parse_set_cookie(header)
                if cookie is None or cookie.name in seen:
                    continue
                seen.add(cookie.name)
                found.extend(self._judge(ctx, page.url, cookie))
        return merge_by_title(found)

    def _judge(self, ctx: CheckContext, url: str, cookie: Cookie) -> list[Finding]:
        out: list[Finding] = []
        kind = "Session cookie" if cookie.is_session else "Cookie"
        common = dict(url=url, owasp="A05:2021 Security Misconfiguration", reference=_REF)
        shown = (
            f"Set-Cookie: {cookie.name}=…; "
            f"Secure={'yes' if cookie.secure else 'no'}; HttpOnly={'yes' if cookie.http_only else 'no'}; "
            f"SameSite={cookie.same_site or 'not set'}"
        )
        if ctx.is_https and not cookie.secure:
            out.append(
                self.finding(
                    ctx,
                    title=f"{kind} `{cookie.name}` is sent without Secure",
                    severity=Severity.MEDIUM.value if cookie.is_session else Severity.LOW.value,
                    evidence=shown,
                    explanation=(
                        "The browser will also send this cookie over plain HTTP, where anyone on the network "
                        "path can read it."
                    ),
                    remediation="Add the `Secure` attribute so the cookie only travels over HTTPS.",
                    cwe="CWE-614",
                    **common,
                )
            )
        if cookie.is_session and not cookie.http_only:
            out.append(
                self.finding(
                    ctx,
                    title=f"Session cookie `{cookie.name}` is readable by JavaScript",
                    severity=Severity.MEDIUM.value,
                    evidence=shown,
                    explanation=(
                        "Without HttpOnly, any script on the page can read this cookie. One cross-site "
                        "scripting bug then becomes a stolen session."
                    ),
                    remediation="Add the `HttpOnly` attribute to session cookies.",
                    cwe="CWE-1004",
                    **common,
                )
            )
        if cookie.same_site == "none" and not cookie.secure:
            out.append(
                self.finding(
                    ctx,
                    title=f"Cookie `{cookie.name}` uses SameSite=None without Secure",
                    severity=Severity.MEDIUM.value,
                    evidence=shown,
                    explanation="Browsers reject this combination, so the cookie is dropped or handled inconsistently.",
                    remediation="Pair `SameSite=None` with `Secure`, or use `SameSite=Lax`.",
                    cwe="CWE-1275",
                    **common,
                )
            )
        elif cookie.is_session and not cookie.same_site:
            out.append(
                self.finding(
                    ctx,
                    title=f"Session cookie `{cookie.name}` has no SameSite attribute",
                    severity=Severity.LOW.value,
                    evidence=shown,
                    explanation=(
                        "Protection against cross-site request forgery then depends on each browser's default, "
                        "which differs between browsers and versions."
                    ),
                    remediation="Set `SameSite=Lax` (or `Strict`) explicitly.",
                    cwe="CWE-1275",
                    **common,
                )
            )
        elif cookie.is_session and cookie.same_site == "none":
            out.append(
                self.finding(
                    ctx,
                    title=f"Session cookie `{cookie.name}` is sent on cross-site requests",
                    severity=Severity.LOW.value,
                    evidence=shown,
                    explanation="SameSite=None sends the session with requests started by other sites, so every state-changing endpoint needs its own anti-forgery token.",
                    remediation="Use `SameSite=Lax` unless the site is designed to be embedded cross-site.",
                    cwe="CWE-1275",
                    **common,
                )
            )
        if cookie.name.startswith("__Host-") and (not cookie.secure or cookie.domain or cookie.path != "/"):
            out.append(
                self.finding(
                    ctx,
                    title=f"Cookie `{cookie.name}` breaks the __Host- prefix rules",
                    severity=Severity.LOW.value,
                    evidence=shown + f"; Domain={cookie.domain or 'not set'}; Path={cookie.path or 'not set'}",
                    explanation="A __Host- cookie must be Secure, have Path=/, and have no Domain. Browsers discard it otherwise.",
                    remediation="Set `Secure; Path=/` and remove the Domain attribute.",
                    cwe="CWE-1275",
                    **common,
                )
            )
        if cookie.name.startswith("__Secure-") and not cookie.secure:
            out.append(
                self.finding(
                    ctx,
                    title=f"Cookie `{cookie.name}` breaks the __Secure- prefix rules",
                    severity=Severity.LOW.value,
                    evidence=shown,
                    explanation="A __Secure- cookie must carry the Secure attribute. Browsers discard it otherwise.",
                    remediation="Add the `Secure` attribute.",
                    cwe="CWE-1275",
                    **common,
                )
            )
        return out
