"""Browser security headers: HSTS, CSP, framing, sniffing, referrer, isolation."""

from __future__ import annotations

import re

from rift.checks.base import Check, CheckContext, clip, merge_by_title
from rift.models import Finding, Observation, Severity

_SIX_MONTHS = 15_552_000
_REF = "https://owasp.org/www-project-secure-headers/"


def parse_csp(value: str) -> dict[str, list[str]]:
    """Directive name to source list. The first copy of a directive wins, as in browsers."""

    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = [token.lower() for token in tokens[1:]]
    return directives


def csp_weaknesses(directives: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    """(severity, short label, sentence) for each weakness in an enforced policy."""

    problems: list[tuple[str, str, str]] = []
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        problems.append(
            (Severity.MEDIUM.value, "scripts are not restricted", "No script-src or default-src, so the policy does not restrict scripts at all.")
        )
    else:
        has_nonce_or_hash = any(
            token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for token in script
        )
        strict_dynamic = "'strict-dynamic'" in script
        if "'unsafe-inline'" in script and not has_nonce_or_hash:
            problems.append(
                (
                    Severity.MEDIUM.value,
                    "inline scripts allowed",
                    "script-src allows 'unsafe-inline' with no nonce or hash, so injected inline script runs.",
                )
            )
        if "'unsafe-eval'" in script:
            problems.append((Severity.LOW.value, "eval allowed", "script-src allows 'unsafe-eval', so strings can be run as code."))
        if not strict_dynamic:
            broad = [token for token in script if token in {"*", "http:", "https:", "data:", "blob:"}]
            if broad:
                problems.append(
                    (
                        Severity.MEDIUM.value,
                        "scripts allowed from any host",
                        f"script-src allows {', '.join(broad)}, so a script can be loaded from almost anywhere.",
                    )
                )
            wild = [token for token in script if token.startswith("*.") or "://*." in token]
            if wild:
                problems.append(
                    (
                        Severity.LOW.value,
                        "wildcard script hosts",
                        f"script-src trusts whole wildcard domains ({', '.join(wild[:3])}).",
                    )
                )
    default_none = directives.get("default-src") == ["'none'"]
    if "object-src" not in directives and not default_none:
        if directives.get("default-src") is None or any(
            token in {"*", "http:", "https:", "data:"} for token in directives.get("default-src", [])
        ):
            problems.append((Severity.LOW.value, "plugins not restricted", "object-src is not restricted. Set object-src 'none'."))
    if "base-uri" not in directives:
        problems.append(
            (
                Severity.LOW.value,
                "base-uri missing",
                "base-uri is missing, so an injected <base> tag can repoint relative script URLs.",
            )
        )
    return problems


def parse_hsts(value: str) -> tuple[int | None, bool, bool]:
    max_age: int | None = None
    lowered = value.lower()
    match = re.search(r"max-age\s*=\s*\"?(\d+)", lowered)
    if match:
        max_age = int(match.group(1))
    return max_age, "includesubdomains" in lowered, "preload" in lowered


class SecurityHeadersCheck(Check):
    id = "security-headers"
    title = "Security headers"
    summary = "HSTS, Content-Security-Policy, clickjacking, MIME sniffing, referrer and isolation headers."

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        for page in ctx.pages:
            if page.status_code is None:
                continue
            found.extend(self._transport(ctx, page))
        for page in ctx.documents:
            found.extend(self._document(ctx, page))
        return merge_by_title(found)

    def _transport(self, ctx: CheckContext, page: Observation) -> list[Finding]:
        out: list[Finding] = []
        if not ctx.is_https:
            return out
        hsts = page.header("strict-transport-security")
        if hsts is None:
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="HSTS header is missing",
                    severity=Severity.MEDIUM.value,
                    evidence="No Strict-Transport-Security header in the HTTPS response.",
                    explanation=(
                        "Without HSTS a browser will still try plain HTTP when a user types the address or "
                        "follows an old link. Someone on the same network can intercept that first request "
                        "and keep the user on an unencrypted copy of the site."
                    ),
                    remediation=(
                        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS "
                        "response. Start with a short max-age if you are unsure every subdomain supports HTTPS."
                    ),
                    cwe="CWE-319",
                    owasp="A05:2021 Security Misconfiguration",
                    reference=_REF,
                )
            )
            return out
        max_age, subdomains, _preload = parse_hsts(hsts)
        if max_age is None or max_age == 0:
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="HSTS is switched off or malformed",
                    severity=Severity.MEDIUM.value,
                    evidence=f"Strict-Transport-Security: {clip(hsts, 160)}",
                    explanation="A max-age of 0, or no max-age at all, tells browsers to forget the HTTPS-only rule.",
                    remediation="Set max-age to at least 31536000 (one year).",
                    cwe="CWE-319",
                    owasp="A05:2021 Security Misconfiguration",
                    reference=_REF,
                )
            )
        elif max_age < _SIX_MONTHS:
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="HSTS max-age is short",
                    severity=Severity.LOW.value,
                    evidence=f"Strict-Transport-Security: {clip(hsts, 160)}",
                    explanation=(
                        f"The HTTPS-only rule expires after {max_age // 86400} days. Users who visit less often "
                        "than that are unprotected on their next visit."
                    ),
                    remediation="Raise max-age to 31536000 (one year) once HTTPS is stable.",
                    cwe="CWE-319",
                    owasp="A05:2021 Security Misconfiguration",
                    reference=_REF,
                )
            )
        elif not subdomains:
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="HSTS does not cover subdomains",
                    severity=Severity.INFO.value,
                    evidence=f"Strict-Transport-Security: {clip(hsts, 160)}",
                    explanation="Subdomains can still be reached over plain HTTP, which can expose cookies scoped to the parent domain.",
                    remediation="Add `includeSubDomains` once every subdomain serves HTTPS.",
                    cwe="CWE-319",
                    owasp="A05:2021 Security Misconfiguration",
                    reference=_REF,
                )
            )
        return out

    def _document(self, ctx: CheckContext, page: Observation) -> list[Finding]:
        out: list[Finding] = []
        common = dict(owasp="A05:2021 Security Misconfiguration", reference=_REF, url=page.url)
        csp = page.header("content-security-policy")
        report_only = page.header("content-security-policy-report-only")
        directives = parse_csp(csp) if csp else {}
        if csp is None:
            if report_only:
                out.append(
                    self.finding(
                        ctx,
                        title="Content-Security-Policy is report-only",
                        severity=Severity.LOW.value,
                        evidence=f"Content-Security-Policy-Report-Only: {clip(report_only, 200)}",
                        explanation="The policy is only logging violations. Browsers do not block anything yet.",
                        remediation="When the reports are clean, send the same policy as `Content-Security-Policy`.",
                        cwe="CWE-693",
                        **common,
                    )
                )
            else:
                out.append(
                    self.finding(
                        ctx,
                        title="Content-Security-Policy header is missing",
                        severity=Severity.MEDIUM.value,
                        evidence="No Content-Security-Policy header on this HTML page.",
                        explanation=(
                            "CSP is the browser-side safety net for cross-site scripting. Without it, any script "
                            "an attacker manages to inject runs with full access to the page and the user's session."
                        ),
                        remediation=(
                            "Start with `Content-Security-Policy: default-src 'self'; object-src 'none'; "
                            "base-uri 'self'; frame-ancestors 'self'` and add the specific sources the page needs. "
                            "Use nonces or hashes instead of 'unsafe-inline'."
                        ),
                        cwe="CWE-693",
                        **common,
                    )
                )
        else:
            for severity, label, sentence in csp_weaknesses(directives):
                out.append(
                    self.finding(
                        ctx,
                        title=f"Weak Content-Security-Policy: {label}",
                        severity=severity,
                        evidence=f"Content-Security-Policy: {clip(csp, 300)}",
                        explanation=sentence,
                        remediation=(
                            "Tighten the policy: use nonces or hashes for scripts, list exact hosts, and set "
                            "`object-src 'none'` and `base-uri 'self'`."
                        ),
                        cwe="CWE-693",
                        **common,
                    )
                )
        xfo = (page.header("x-frame-options") or "").strip().lower()
        if "frame-ancestors" not in directives and xfo not in {"deny", "sameorigin"}:
            evidence = "No X-Frame-Options header and no CSP frame-ancestors directive."
            if xfo:
                evidence = f"X-Frame-Options: {clip(xfo, 80)} is not a value browsers honour, and CSP has no frame-ancestors."
            out.append(
                self.finding(
                    ctx,
                    title="Page can be framed by other sites (clickjacking)",
                    severity=Severity.MEDIUM.value,
                    evidence=evidence,
                    explanation=(
                        "Another site can load this page in an invisible frame and trick a signed-in user "
                        "into clicking buttons on it."
                    ),
                    remediation="Send `Content-Security-Policy: frame-ancestors 'self'` (and `X-Frame-Options: SAMEORIGIN` for older browsers).",
                    cwe="CWE-1021",
                    **common,
                )
            )
        if (page.header("x-content-type-options") or "").strip().lower() != "nosniff":
            out.append(
                self.finding(
                    ctx,
                    title="X-Content-Type-Options: nosniff is missing",
                    severity=Severity.LOW.value,
                    evidence="No `X-Content-Type-Options: nosniff` header.",
                    explanation="Browsers may guess a file's type from its contents, which can turn an uploaded file into runnable script.",
                    remediation="Send `X-Content-Type-Options: nosniff` on every response.",
                    cwe="CWE-693",
                    **common,
                )
            )
        referrer = (page.header("referrer-policy") or "").strip().lower()
        if not referrer:
            out.append(
                self.finding(
                    ctx,
                    title="Referrer-Policy header is missing",
                    severity=Severity.INFO.value,
                    evidence="No Referrer-Policy header.",
                    explanation="Browsers fall back to their own default. Setting it explicitly stops full URLs, including any tokens in them, leaking to other sites.",
                    remediation="Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
                    cwe="CWE-200",
                    **common,
                )
            )
        elif referrer.split(",")[-1].strip() in {"unsafe-url", "no-referrer-when-downgrade"}:
            out.append(
                self.finding(
                    ctx,
                    title="Referrer-Policy leaks full URLs to other sites",
                    severity=Severity.LOW.value,
                    evidence=f"Referrer-Policy: {clip(referrer, 80)}",
                    explanation="The full address of the page, including its query string, is sent to every third-party site the page links to or loads from.",
                    remediation="Use `strict-origin-when-cross-origin` or `no-referrer`.",
                    cwe="CWE-200",
                    **common,
                )
            )
        if page.header("permissions-policy") is None:
            out.append(
                self.finding(
                    ctx,
                    title="Permissions-Policy header is missing",
                    severity=Severity.INFO.value,
                    evidence="No Permissions-Policy header.",
                    explanation="Embedded third-party content can ask for the camera, microphone, location and other device features.",
                    remediation="Send a Permissions-Policy that switches off features the site does not use, for example `geolocation=(), camera=(), microphone=()`.",
                    cwe="CWE-693",
                    **common,
                )
            )
        if page.header("cross-origin-opener-policy") is None:
            out.append(
                self.finding(
                    ctx,
                    title="Cross-Origin-Opener-Policy header is missing",
                    severity=Severity.INFO.value,
                    evidence="No Cross-Origin-Opener-Policy header.",
                    explanation="A page that opens this one in a new window keeps a handle to it, which enables some cross-window attacks.",
                    remediation="Send `Cross-Origin-Opener-Policy: same-origin` unless the site relies on cross-origin popups.",
                    cwe="CWE-693",
                    **common,
                )
            )
        xss = (page.header("x-xss-protection") or "").strip()
        if xss and not xss.startswith("0"):
            out.append(
                self.finding(
                    ctx,
                    title="Deprecated X-XSS-Protection filter is switched on",
                    severity=Severity.INFO.value,
                    evidence=f"X-XSS-Protection: {clip(xss, 60)}",
                    explanation="This legacy browser filter has been removed from modern browsers and introduced its own vulnerabilities in old ones.",
                    remediation="Send `X-XSS-Protection: 0` or drop the header, and rely on Content-Security-Policy.",
                    cwe="CWE-693",
                    **common,
                )
            )
        return out
