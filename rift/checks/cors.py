"""Cross-origin resource sharing: does the server trust origins it should not?

Each probe is one ordinary GET with an Origin header naming a host that does not
exist. A finding needs the server to echo that origin back, and a control request
without the header to show the echo was caused by it.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from rift.checks.base import PROBE, Check, CheckContext, is_json, merge_by_title
from rift.models import Finding, Observation, Severity

# .invalid is reserved by RFC 2606, so this origin can never be a real site.
PROBE_ORIGIN = "https://rift-cors-check.invalid"
_REF = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS"


def _acao(page: Observation) -> str:
    return (page.header("access-control-allow-origin") or "").strip()


def _credentials(page: Observation) -> bool:
    return (page.header("access-control-allow-credentials") or "").strip().lower() == "true"


class CorsCheck(Check):
    id = "cors"
    title = "CORS policy"
    summary = "Servers that let any website read responses, with or without the visitor's cookies."
    kind = PROBE

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        for url in self._targets(ctx):
            found.extend(self._probe(ctx, url))
        return merge_by_title(found)

    def _targets(self, ctx: CheckContext) -> list[str]:
        """API-looking responses first, then pages. Capped so the check stays small."""

        ranked = sorted(
            (page for page in ctx.pages if page.status_code is not None and page.status_code < 500),
            key=lambda page: (0 if is_json(page) or "/api" in page.url else 1, page.url),
        )
        limit = 8 if ctx.deep else 3
        urls: list[str] = []
        for page in ranked:
            if page.url not in urls:
                urls.append(page.url)
        return urls[:limit]

    def _probe(self, ctx: CheckContext, url: str) -> list[Finding]:
        out: list[Finding] = []
        common = dict(url=url, cwe="CWE-942", owasp="A05:2021 Security Misconfiguration", reference=_REF)
        baseline = ctx.fetch(url, include_body=False)
        if baseline.status_code is None:
            return out
        baseline_origin = _acao(baseline)
        if baseline_origin == "*" and _credentials(baseline):
            out.append(
                self.finding(
                    ctx,
                    title="CORS allows every origin and also claims credentials",
                    severity=Severity.LOW.value,
                    evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    explanation=(
                        "Browsers refuse this combination, so it does not work as intended. It usually means the "
                        "CORS settings were copied without review."
                    ),
                    remediation="List the exact origins that need access and send credentials only to those.",
                    **common,
                )
            )
        probed = ctx.fetch(url, headers={"Origin": PROBE_ORIGIN}, include_body=False)
        if probed.status_code is None:
            return out
        echoed = _acao(probed)
        if echoed == PROBE_ORIGIN and baseline_origin != PROBE_ORIGIN:
            with_credentials = _credentials(probed)
            out.append(
                self.finding(
                    ctx,
                    title=(
                        "CORS trusts any website and shares the visitor's session"
                        if with_credentials
                        else "CORS reflects any website's origin"
                    ),
                    severity=Severity.HIGH.value if with_credentials else Severity.LOW.value,
                    evidence=(
                        f"Request header  Origin: {PROBE_ORIGIN}\n"
                        f"Response header Access-Control-Allow-Origin: {echoed}\n"
                        f"Response header Access-Control-Allow-Credentials: {'true' if with_credentials else 'not set'}\n"
                        f"Control request without Origin returned Access-Control-Allow-Origin: {baseline_origin or 'not set'}"
                    ),
                    explanation=(
                        "The server copies whatever origin it is given into its allow-list. With credentials "
                        "allowed, any website a signed-in user visits can call this endpoint as that user and "
                        "read the response."
                        if with_credentials
                        else "The server copies whatever origin it is given into its allow-list. Any website can read "
                        "this endpoint's response. That only matters if the response is not meant to be public, "
                        "for example when access depends on network location rather than a login."
                    ),
                    remediation=(
                        "Compare the Origin header against a fixed list of origins you trust and echo it only on "
                        "an exact match. Never build the allow-list from the request."
                    ),
                    **common,
                )
            )
            return out
        null_probe = ctx.fetch(url, headers={"Origin": "null"}, include_body=False)
        if null_probe.status_code is not None and _acao(null_probe) == "null" and _credentials(null_probe):
            out.append(
                self.finding(
                    ctx,
                    title="CORS trusts the `null` origin with credentials",
                    severity=Severity.HIGH.value,
                    evidence=(
                        "Request header  Origin: null\n"
                        "Response header Access-Control-Allow-Origin: null\n"
                        "Response header Access-Control-Allow-Credentials: true"
                    ),
                    explanation=(
                        "Sandboxed frames and local files send `Origin: null`, and any website can create one. "
                        "Trusting it lets a hostile page read this endpoint as the signed-in user."
                    ),
                    remediation="Remove `null` from the allowed origins.",
                    **common,
                )
            )
        if ctx.deep:
            host = urlsplit(url).hostname or ""
            lookalike = f"https://{host}.rift-cors-check.invalid"
            suffix = ctx.fetch(url, headers={"Origin": lookalike}, include_body=False)
            if suffix.status_code is not None and _acao(suffix) == lookalike:
                with_credentials = _credentials(suffix)
                out.append(
                    self.finding(
                        ctx,
                        title="CORS origin check accepts look-alike domains",
                        severity=Severity.HIGH.value if with_credentials else Severity.LOW.value,
                        evidence=(
                            f"Request header  Origin: {lookalike}\n"
                            f"Response header Access-Control-Allow-Origin: {lookalike}\n"
                            f"Response header Access-Control-Allow-Credentials: {'true' if with_credentials else 'not set'}"
                        ),
                        explanation=(
                            "The origin check matches on the start of the hostname instead of the whole hostname, "
                            "so a domain an attacker registers can pass it."
                        ),
                        remediation="Match the full origin exactly against a fixed list.",
                        **common,
                    )
                )
        return out
