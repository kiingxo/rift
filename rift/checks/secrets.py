"""Credentials left in pages and scripts, and weaknesses in JSON Web Tokens the site issues.

Matches are redacted before they are stored, so a report never contains a usable secret.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

from rift.checks.base import Check, CheckContext, merge_by_title, redact
from rift.models import Finding, Observation, Severity


@dataclass(frozen=True)
class SecretRule:
    id: str
    label: str
    severity: str
    pattern: re.Pattern[str]
    note: str = ""
    confidence: str = "high"
    group: int = 0


def _rule(id: str, label: str, severity: str, pattern: str, note: str = "", confidence: str = "high", group: int = 0) -> SecretRule:
    return SecretRule(id, label, severity, re.compile(pattern), note, confidence, group)


_HIGH = Severity.HIGH.value
_CRIT = Severity.CRITICAL.value
_MED = Severity.MEDIUM.value
_INFO = Severity.INFO.value

RULES: tuple[SecretRule, ...] = (
    _rule("private-key", "Private key", _CRIT, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    _rule("aws-access-key", "AWS access key ID", _HIGH, r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _rule("github-token", "GitHub token", _CRIT, r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"),
    _rule("gitlab-token", "GitLab personal access token", _CRIT, r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _rule("slack-token", "Slack token", _HIGH, r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    _rule("slack-webhook", "Slack incoming webhook", _MED, r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
    _rule("stripe-secret", "Stripe live secret key", _CRIT, r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
    _rule("google-oauth-secret", "Google OAuth client secret", _HIGH, r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b"),
    _rule("sendgrid", "SendGrid API key", _HIGH, r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    _rule("mailgun", "Mailgun API key", _HIGH, r"\bkey-[0-9a-f]{32}\b", confidence="medium"),
    _rule("twilio", "Twilio API key", _HIGH, r"\bSK[0-9a-f]{32}\b", confidence="medium"),
    _rule("npm-token", "npm access token", _HIGH, r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("openai", "OpenAI API key", _HIGH, r"\bsk-(?:proj-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
    _rule("anthropic", "Anthropic API key", _HIGH, r"\bsk-ant-[a-z0-9]+-[A-Za-z0-9_\-]{60,}"),
    _rule("huggingface", "Hugging Face token", _HIGH, r"\bhf_[A-Za-z0-9]{34,}\b"),
    _rule("square", "Square access token", _HIGH, r"\bsq0(?:atp|csp)-[0-9A-Za-z_\-]{22,43}\b"),
    _rule("shopify", "Shopify access token", _HIGH, r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    _rule("telegram", "Telegram bot token", _HIGH, r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"),
    _rule("digitalocean", "DigitalOcean token", _HIGH, r"\bdo[por]_v1_[a-f0-9]{64}\b"),
    _rule(
        "database-url",
        "Database connection string with a password",
        _CRIT,
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^\s:@/\"'<>]+:[^\s@/\"'<>]{3,}@[^\s\"'<>]+",
    ),
    _rule(
        "basic-auth-url",
        "Username and password inside a URL",
        _MED,
        r"\bhttps?://[A-Za-z0-9._%+\-]+:[^\s:@/\"'<>]{3,}@[A-Za-z0-9.\-]+",
        confidence="medium",
    ),
    _rule(
        "google-api-key",
        "Google API key",
        _INFO,
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        note=(
            "Google browser keys (Maps, Firebase) are meant to be public, but only if they are restricted. "
            "Check in the Google Cloud console that this key is limited to your domains and to the APIs it needs."
        ),
    ),
    _rule(
        "generic-secret",
        "Hard-coded secret in a script",
        _MED,
        r"(?i)\b(?:api[_-]?secret|client[_-]?secret|secret[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|passwd|password)"
        r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/_\-=.]{16,120})[\"']",
        confidence="low",
        group=1,
    ),
)

_PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|placeholder|changeme|your[_-]?|xxxx|0000000|1234567|abcdef|test|undefined|null|redacted|\*{4})"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
_SENSITIVE_CLAIM = re.compile(r"(?i)(passw|secret|ssn|card.?number|cvv|api.?key|private)")
_THIRTY_DAYS = 30 * 86400


def _looks_random(value: str) -> bool:
    """True when a string mixes character classes the way a generated secret does."""

    classes = sum(
        (
            any(ch.islower() for ch in value),
            any(ch.isupper() for ch in value),
            any(ch.isdigit() for ch in value),
        )
    )
    return classes >= 2 and len(set(value)) >= 10


def _url_password(url: str) -> str:
    """The password part of scheme://user:password@host, so only that is tested for placeholders."""

    credentials = url.split("://", 1)[-1].rsplit("@", 1)[0]
    return credentials.split(":", 1)[-1]


def scan_text(text: str) -> list[tuple[SecretRule, str]]:
    """Every (rule, raw match) in a document. The caller redacts before storing."""

    hits: list[tuple[SecretRule, str]] = []
    seen: set[str] = set()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(rule.group)
            if value in seen:
                continue
            if rule.id == "generic-secret" and (_PLACEHOLDER.search(value) or not _looks_random(value)):
                continue
            if rule.id in {"basic-auth-url", "database-url"} and _PLACEHOLDER.search(_url_password(value)):
                continue
            seen.add(value)
            hits.append((rule, value))
            if len(hits) >= 40:
                return hits
    return hits


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    pieces = token.split(".")
    if len(pieces) != 3:
        return None
    decoded = []
    for piece in pieces[:2]:
        padded = piece + "=" * (-len(piece) % 4)
        try:
            value = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        except Exception:  # noqa: BLE001 - not a real token
            return None
        if not isinstance(value, dict):
            return None
        decoded.append(value)
    if "alg" not in decoded[0]:
        return None
    return decoded[0], decoded[1]


class SecretsCheck(Check):
    id = "secrets"
    title = "Exposed secrets"
    summary = "API keys, tokens, private keys and connection strings left in pages and JavaScript files."

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        for document in [*ctx.pages, *ctx.scripts]:
            body = document.body or ""
            if not body:
                continue
            for rule, value in scan_text(body):
                found.append(self._report(ctx, document, rule, value))
        return merge_by_title(found)

    def _report(self, ctx: CheckContext, document: Observation, rule: SecretRule, value: str) -> Finding:
        shown = redact(value) if rule.id != "private-key" else value
        explanation = rule.note or (
            "This value is downloadable by anyone who opens the page or script. If it is a live credential, "
            "it can be used to call the service as your organisation until it is revoked."
        )
        remediation = (
            "Treat it as compromised: revoke or rotate it now, then remove it from the frontend. Keep secrets "
            "on the server and have the browser call your own backend instead."
        )
        if rule.severity == Severity.INFO.value:
            remediation = "Restrict the key to your domains and to the specific APIs it needs."
        return self.finding(
            ctx,
            url=document.url,
            title=f"{rule.label} exposed in a public response",
            severity=rule.severity,
            evidence=f"{shown}",
            explanation=explanation,
            remediation=remediation,
            cwe="CWE-798",
            owasp="A07:2021 Identification and Authentication Failures",
            confidence=rule.confidence,
        )


class JwtCheck(Check):
    id = "jwt"
    title = "JSON Web Tokens"
    summary = "Tokens the site hands out that are unsigned, never expire, or carry sensitive data."

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        seen: set[str] = set()
        for document in [*ctx.pages, *ctx.scripts]:
            sources = [document.body or ""]
            sources.extend(document.header_all("set-cookie"))
            sources.extend(value for name, value in document.headers if name.lower() in {"authorization", "x-auth-token", "x-access-token"})
            for text in sources:
                for token in _JWT.findall(text):
                    if token in seen:
                        continue
                    seen.add(token)
                    decoded = decode_jwt(token)
                    if decoded is None:
                        continue
                    found.extend(self._judge(ctx, document.url, token, *decoded))
        return merge_by_title(found)

    def _judge(self, ctx: CheckContext, url: str, token: str, header: dict, payload: dict) -> list[Finding]:
        out: list[Finding] = []
        shown = redact(token, keep_start=12, keep_end=0)
        algorithm = str(header.get("alg", "")).lower()
        claims = ", ".join(sorted(str(key) for key in payload)[:12])
        common = dict(url=url, owasp="API2:2023 Broken Authentication", reference="https://datatracker.ietf.org/doc/html/rfc8725")
        if algorithm == "none" or not token.split(".")[2]:
            out.append(
                self.finding(
                    ctx,
                    title="Site issues an unsigned JSON Web Token",
                    severity=Severity.HIGH.value,
                    evidence=f"{shown} · header alg={header.get('alg')!r}",
                    explanation="An unsigned token can be edited by its holder. If the server accepts it, anyone can change the user ID or role inside it.",
                    remediation="Sign every token (RS256/ES256, or HS256 with a long random secret) and reject `alg: none` on verification.",
                    cwe="CWE-347",
                    **common,
                )
            )
        expiry = payload.get("exp")
        issued = payload.get("iat")
        if expiry is None:
            out.append(
                self.finding(
                    ctx,
                    title="JSON Web Token has no expiry",
                    severity=Severity.MEDIUM.value,
                    evidence=f"{shown} · claims: {claims or 'none'}",
                    explanation="A token without `exp` stays valid forever, so a single leak gives permanent access.",
                    remediation="Set a short `exp` (minutes to hours for access tokens) and use refresh tokens for long sessions.",
                    cwe="CWE-613",
                    **common,
                )
            )
        elif isinstance(expiry, (int, float)) and isinstance(issued, (int, float)) and expiry - issued > _THIRTY_DAYS:
            out.append(
                self.finding(
                    ctx,
                    title="JSON Web Token is valid for more than 30 days",
                    severity=Severity.LOW.value,
                    evidence=f"{shown} · lifetime {int((expiry - issued) // 86400)} days",
                    explanation="Long-lived tokens widen the window in which a leaked token can be used.",
                    remediation="Shorten the access-token lifetime and rotate with refresh tokens.",
                    cwe="CWE-613",
                    **common,
                )
            )
        sensitive = sorted(str(key) for key in payload if _SENSITIVE_CLAIM.search(str(key)))
        if sensitive:
            out.append(
                self.finding(
                    ctx,
                    title="JSON Web Token carries sensitive-looking claims",
                    severity=Severity.MEDIUM.value,
                    evidence=f"{shown} · claims: {', '.join(sensitive)}",
                    explanation="A JWT payload is only encoded, not encrypted. Anyone holding the token can read these fields.",
                    remediation="Keep secrets and personal data out of the token. Store an opaque ID and look the rest up on the server.",
                    cwe="CWE-312",
                    **common,
                )
            )
        return out
