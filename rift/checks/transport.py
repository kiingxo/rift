"""Transport security: the TLS certificate, old protocol versions, and plain-HTTP access.

The TLS handshakes connect to an address the scoped client has already checked,
so the same private-network and metadata rules apply here.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlsplit

from rift.checks.base import PROBE, Check, CheckContext
from rift.models import Finding, Severity

_REF = "https://wiki.mozilla.org/Security/Server_Side_TLS"
_WARN_DAYS = 21


def _connect(address: str, port: int, host: str, context: ssl.SSLContext, timeout: float):
    raw = socket.create_connection((address, port), timeout=timeout)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def inspect_certificate(address: str, port: int, host: str, timeout: float) -> dict[str, object]:
    """Verify the certificate the way a browser would and report what was negotiated."""

    context = ssl.create_default_context()
    try:
        with _connect(address, port, host, context, timeout) as tls:
            certificate = tls.getpeercert() or {}
            return {
                "valid": True,
                "protocol": tls.version() or "",
                "not_after": certificate.get("notAfter", ""),
                "error": "",
            }
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "protocol": "", "not_after": "", "error": exc.verify_message or str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"valid": None, "protocol": "", "not_after": "", "error": f"{exc.__class__.__name__}: {exc}"}


def accepts_legacy_protocol(address: str, port: int, host: str, timeout: float) -> str | None:
    """Return the legacy protocol name the server completes a handshake with, or None.

    The answer is None both when the server refuses and when this machine's own
    TLS library can no longer speak those versions, so absence is not proof.
    """

    for version, label in ((ssl.TLSVersion.TLSv1_1, "TLS 1.1"), (ssl.TLSVersion.TLSv1, "TLS 1.0")):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            try:
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with _connect(address, port, host, context, timeout):
                return label
        except (OSError, ssl.SSLError, ValueError):
            continue
    return None


def days_until(not_after: str, now: datetime | None = None) -> int | None:
    if not not_after:
        return None
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    except ValueError:
        return None
    return (expires - (now or datetime.now(timezone.utc))).days


class TransportCheck(Check):
    id = "transport"
    title = "HTTPS and TLS"
    summary = "Certificate validity and expiry, outdated TLS versions, and whether plain HTTP redirects to HTTPS."
    kind = PROBE

    # Replaceable in tests so no real socket is opened.
    certificate_probe: Callable[[str, int, str, float], dict[str, object]] = staticmethod(inspect_certificate)
    legacy_probe: Callable[[str, int, str, float], str | None] = staticmethod(accepts_legacy_protocol)

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        if ctx.is_https:
            found.extend(self._tls(ctx))
            found.extend(self._plain_http(ctx))
        else:
            found.append(
                self.finding(
                    ctx,
                    title="Site is served over plain HTTP",
                    severity=Severity.HIGH.value,
                    evidence=f"{ctx.origin} answered without TLS.",
                    explanation=(
                        "Everything sent to and from this origin, including passwords and session cookies, "
                        "can be read and changed by anyone on the network path."
                    ),
                    remediation="Serve the site over HTTPS and redirect every HTTP request to it.",
                    cwe="CWE-319",
                    owasp="A02:2021 Cryptographic Failures",
                    reference=_REF,
                )
            )
        return found

    def _tls(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        parts = urlsplit(ctx.origin)
        host = parts.hostname or ""
        port = parts.port or 443
        if ctx.resolver is None:
            ctx.note(self.id, "The TLS handshake was skipped because this client cannot supply a checked address.")
            return out
        try:
            addresses = ctx.resolver(host, port)
        except Exception as exc:  # noqa: BLE001 - scope refusal or DNS failure
            ctx.note(self.id, f"The TLS handshake was skipped: {exc}")
            return out
        address = addresses[0]
        timeout = ctx.config.connect_timeout_seconds
        common = dict(cwe="CWE-295", owasp="A02:2021 Cryptographic Failures", reference=_REF)
        result = self.certificate_probe(address, port, host, timeout)
        if result["valid"] is False:
            out.append(
                self.finding(
                    ctx,
                    title="TLS certificate is not trusted",
                    severity=Severity.HIGH.value,
                    evidence=str(result["error"]),
                    explanation=(
                        "Browsers show a full-page warning for this certificate. Users who are trained to click "
                        "through it cannot tell the real site from an impostor."
                    ),
                    remediation="Install a certificate from a trusted authority that covers this hostname and include the full chain.",
                    **common,
                )
            )
        elif result["valid"] is None:
            ctx.note(self.id, f"The TLS handshake did not complete: {result['error']}")
        else:
            remaining = days_until(str(result["not_after"]))
            if remaining is not None and remaining <= _WARN_DAYS:
                out.append(
                    self.finding(
                        ctx,
                        title=f"TLS certificate expires in {max(remaining, 0)} days",
                        severity=Severity.MEDIUM.value if remaining <= 7 else Severity.LOW.value,
                        evidence=f"notAfter: {result['not_after']}",
                        explanation="When the certificate expires, browsers and API clients will refuse to connect.",
                        remediation="Renew the certificate now and automate renewal (for example with ACME).",
                        **common,
                    )
                )
            if result["protocol"] in {"TLSv1", "TLSv1.1"}:
                out.append(self._legacy(ctx, str(result["protocol"]), common))
        legacy = self.legacy_probe(address, port, host, timeout)
        if legacy and not any(item.title.startswith("Server accepts") for item in out):
            out.append(self._legacy(ctx, legacy, common))
        return out

    def _legacy(self, ctx: CheckContext, label: str, common: dict[str, str]) -> Finding:
        fields = dict(common)
        fields["cwe"] = "CWE-326"
        return self.finding(
            ctx,
            title=f"Server accepts {label}",
            severity=Severity.MEDIUM.value,
            evidence=f"A handshake restricted to {label} completed.",
            explanation=(
                "TLS 1.0 and 1.1 were retired in 2021 (RFC 8996). They have known weaknesses and fail PCI DSS "
                "and most compliance baselines."
            ),
            remediation="Disable TLS 1.0 and 1.1. Offer TLS 1.2 and 1.3 only.",
            **fields,
        )

    def _plain_http(self, ctx: CheckContext) -> list[Finding]:
        parts = urlsplit(ctx.origin)
        if parts.port not in (None, 443):
            return []
        plain = f"http://{parts.hostname}/"
        response = ctx.fetch(plain, include_body=False)
        if response.status_code is None:
            return []
        if response.status_code in {301, 302, 303, 307, 308} and response.location_header:
            target = urljoin(plain, response.location_header)
            if target.startswith("https://"):
                return []
        if response.status_code >= 400:
            return []
        return [
            self.finding(
                ctx,
                url=plain,
                title="Plain HTTP does not redirect to HTTPS",
                severity=Severity.MEDIUM.value,
                evidence=f"GET {plain} returned HTTP {response.status_code}"
                + (f" with Location: {response.location_header}" if response.location_header else ""),
                explanation="Visitors who arrive over http:// stay on an unencrypted connection, where pages and cookies can be read or altered in transit.",
                remediation="Answer every HTTP request with a 301 redirect to the same path on https://, then add HSTS.",
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                reference=_REF,
            )
        ]
