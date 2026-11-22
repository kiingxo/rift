"""A test account's session, for scans that read pages while signed in.

Rift never logs in by itself and never handles a password. The person running
the scan signs in to a test account in their own browser and pastes the
session cookie or the Authorization header. Rift then:

- sends it only to the hosts of the submitted URLs, and only with GET, HEAD or
  OPTIONS, through the same scoped client as every other request;
- refuses, while signed in, any URL that looks like it does something (sign out,
  delete, approve, archive, ...), so reading the app cannot change the account;
- keeps it in memory only, and replaces every copy of it with ``[session]``
  before a finding, note, page list or log line leaves the scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlsplit

MAX_VALUE = 8192
MIN_MARKER = 4
MAX_MARKER = 200
PLACEHOLDER = "[session]"

# Headers that would change where or how a request goes, or that Rift sets itself.
_RESERVED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "accept",
        "accept-encoding",
        "cache-control",
        "origin",
        "referer",
        "user-agent",
        "cookie",
        "proxy-authorization",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "x-original-url",
        "x-rewrite-url",
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
    }
)
_HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")
_COOKIE_ATTRIBUTES = frozenset({"path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "priority", "partitioned"})

# Words that mark a URL as an action rather than a page. While signed in, a URL
# whose path segments or query contain one of them is not requested. The list
# is deliberately broad: a page that is skipped costs a little coverage, a
# link that is followed could sign the account out or change its data.
_ACTION_WORDS = frozenset(
    {
        "logout", "logoff", "signout", "signoff", "endsession", "exit",
        "delete", "destroy", "remove", "purge", "wipe", "erase", "clear", "trash",
        "revoke", "disable", "enable", "deactivate", "activate", "suspend", "terminate",
        "archive", "unarchive", "restore", "approve", "reject", "accept", "decline",
        "cancel", "confirm", "verify", "toggle", "impersonate", "sudo", "masquerade",
        "subscribe", "unsubscribe", "invite", "join", "leave", "follow", "unfollow",
        "like", "unlike", "vote", "upvote", "downvote", "upgrade", "downgrade",
        "reset", "rotate", "regenerate", "resend", "send", "publish", "unpublish",
        "ban", "unban", "kick", "block", "unblock", "mute", "unmute", "report",
        "refund", "pay", "payment", "payments", "charge", "checkout", "purchase",
        "buy", "sell", "trade", "swap", "withdraw", "withdrawal", "deposit", "transfer",
        "order", "claim", "redeem", "create", "add", "update", "save", "set", "undo",
        "close", "kill", "stop", "lock", "unlock", "password", "passwd", "register", "signup",
    }
)
_SPLIT = re.compile(r"[^a-z0-9]+")


class SessionError(ValueError):
    """The pasted session could not be used."""


_CAMEL = re.compile(r"([a-z0-9])([A-Z])")


def _words(text: str) -> set[str]:
    lowered = text.lower()
    words = {word for word in _SPLIT.split(lowered) if word}
    # sendPhoneNumberOTP and resetPassword name actions too.
    words.update(word for word in _SPLIT.split(_CAMEL.sub(r"\1 \2", text).lower()) if word)
    compact = _SPLIT.sub("", lowered)
    if compact:
        words.add(compact)
    return words


# For an address the app itself reads with GET (found in its JavaScript), only
# words that clearly do something are refused: the app's own read of
# /hmo/claim or /laboratory/test is a list, not an action.
_HARD_ACTION_WORDS = frozenset(
    {
        "logout", "logoff", "signout", "signoff", "endsession",
        "delete", "destroy", "remove", "purge", "wipe", "erase", "trash",
        "revoke", "disable", "deactivate", "suspend", "terminate", "impersonate", "sudo", "masquerade",
        "approve", "reject", "decline", "cancel", "confirm", "verify",
        "subscribe", "unsubscribe", "invite", "send", "resend", "publish", "unpublish", "notify",
        "reset", "rotate", "generate", "regenerate", "trigger", "execute", "sync", "import",
        "refund", "pay", "charge", "checkout", "purchase", "withdraw", "deposit",
        "lock", "unlock", "ban", "unban", "block", "unblock", "kill", "stop", "undo", "password", "passwd",
    }
)
# A segment that names a list or record of past events is a read even with an action word in it.
_READ_NOUNS = frozenset({"history", "histories", "list", "logs", "log", "category", "categories", "filter", "search", "summary", "stats", "count", "types"})


def action_word(url: str, *, app_read: bool = False) -> str | None:
    """The word that marks a URL as an action, or None. app_read applies the narrower list."""

    words_for = _HARD_ACTION_WORDS if app_read else _ACTION_WORDS
    parts = urlsplit(url)
    for segment in parts.path.split("/"):
        if not segment:
            continue
        words = _words(segment)
        if app_read and words & _READ_NOUNS:
            continue
        hit = words & words_for
        if hit:
            return sorted(hit)[0]
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        hit = (_words(key) | _words(value)) & words_for
        if hit:
            return sorted(hit)[0]
    return None


def looks_like_action(url: str, *, app_read: bool = False) -> bool:
    """True when a URL's path or query names an action that could change the account."""

    return action_word(url, app_read=app_read) is not None


def _clean(text: str, what: str) -> str:
    value = (text or "").strip()
    if len(value) > MAX_VALUE:
        raise SessionError(f"The {what} is longer than {MAX_VALUE} characters.")
    if any(character in value for character in "\r\n\0"):
        raise SessionError(f"The {what} must be on one line.")
    return value


def parse_cookie(text: str) -> tuple[tuple[str, str], ...]:
    """Pairs from a Cookie header value, with or without the `Cookie:` prefix."""

    value = _clean(text, "cookie")
    if not value:
        return ()
    if value.lower().startswith("cookie:"):
        value = value[7:].strip()
    pairs: list[tuple[str, str]] = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            if part.lower() in _COOKIE_ATTRIBUTES:
                continue
            raise SessionError(f"`{part[:40]}` is not a name=value pair. Paste the Cookie header, for example: session=abc123")
        name, _, cookie_value = part.partition("=")
        name = name.strip()
        if name.lower() in _COOKIE_ATTRIBUTES:
            continue
        if not _COOKIE_NAME.fullmatch(name):
            raise SessionError(f"`{name[:40]}` is not a valid cookie name.")
        pairs.append((name, cookie_value.strip()))
    if not pairs:
        raise SessionError("The cookie has no name=value pairs.")
    return tuple(pairs)


def parse_header(text: str) -> tuple[str, str]:
    """(name, value) from `Name: value`. A bare `Bearer ...` means Authorization."""

    value = _clean(text, "header")
    if not value:
        return "", ""
    if value.lower().startswith("bearer ") or value.lower().startswith("basic "):
        return "Authorization", value
    name, colon, rest = value.partition(":")
    name = name.strip()
    rest = rest.strip()
    if not colon or not rest:
        raise SessionError("Write the header as `Name: value`, for example `Authorization: Bearer eyJ...`.")
    if not _HEADER_NAME.fullmatch(name):
        raise SessionError(f"`{name[:40]}` is not a valid header name.")
    if name.lower() in _RESERVED_HEADERS:
        raise SessionError(f"Rift does not send a custom `{name}` header. Use the Cookie field for cookies.")
    return name, rest


@dataclass(frozen=True)
class SignedInSession:
    """A signed-in test account. Never printed, logged or saved."""

    cookies: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    header_name: str = ""
    header_value: str = field(default="", repr=False)
    marker: str = field(default="", repr=False)
    hosts: tuple[str, ...] = ()

    @classmethod
    def build(cls, *, cookie: str = "", header: str = "", marker: str = "", hosts=()) -> "SignedInSession | None":
        """A session from what the person pasted, or None when nothing was pasted."""

        cookies = parse_cookie(cookie)
        header_name, header_value = parse_header(header)
        text = _clean(marker, "signed-in text")
        if not cookies and not header_name:
            if text:
                raise SessionError("Add the test account's cookie or header, or leave the signed-in text empty.")
            return None
        if text and len(text) < MIN_MARKER:
            raise SessionError(f"The signed-in text needs at least {MIN_MARKER} characters, or it will match by chance.")
        if len(text) > MAX_MARKER:
            raise SessionError(f"The signed-in text can be up to {MAX_MARKER} characters.")
        targets = tuple(dict.fromkeys(str(host).strip().lower() for host in hosts if str(host).strip()))
        if not targets:
            raise SessionError("The session needs at least one host to be sent to.")
        return cls(cookies=cookies, header_name=header_name, header_value=header_value, marker=text, hosts=targets)

    @property
    def method(self) -> str:
        if self.cookies and self.header_name:
            return "cookie and header"
        return "cookie" if self.cookies else "header"

    def applies_to(self, host: str) -> bool:
        return (host or "").lower() in self.hosts

    def request_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies)
        if self.header_name:
            headers[self.header_name] = self.header_value
        return headers

    def tokens(self) -> list[str]:
        """Credential values worth looking for in pages, longest first."""

        values = [value for _, value in self.cookies]
        if self.header_value:
            values.append(self.header_value)
            scheme, _, rest = self.header_value.partition(" ")
            if rest and scheme.lower() in {"bearer", "basic", "token"}:
                values.append(rest.strip())
        kept = {value for value in values if len(value) >= 8}
        return sorted(kept, key=len, reverse=True)

    def cookie_tokens(self) -> list[str]:
        return sorted({value for _, value in self.cookies if len(value) >= 12}, key=len, reverse=True)

    def _variants(self) -> list[str]:
        found: set[str] = set()
        for value in self.tokens():
            found.add(value)
            found.add(quote(value, safe=""))
            found.add(quote(value, safe="/"))
        if self.header_value:
            found.add(self.header_value)
        return sorted((item for item in found if len(item) >= 8), key=len, reverse=True)

    def scrub(self, text: str) -> str:
        """Replace every copy of the credential in text with [session]."""

        if not text:
            return text
        for value in self._variants():
            if value in text:
                text = text.replace(value, PLACEHOLDER)
        return text

    def describe(self) -> dict[str, object]:
        """What a report may say about the session: never the values."""

        return {
            "signed_in": True,
            "method": self.method,
            "cookie_names": [name for name, _ in self.cookies],
            "header": self.header_name,
            "signed_in_text": bool(self.marker),
            "hosts": list(self.hosts),
        }

    def __str__(self) -> str:  # pragma: no cover - guard against accidental printing
        return f"SignedInSession({self.method} for {', '.join(self.hosts)})"
