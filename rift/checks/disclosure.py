"""Information the server gives away: version banners, debug pages, error text, listings."""

from __future__ import annotations

import ipaddress
import re

from rift.checks.base import Check, CheckContext, clip, merge_by_title
from rift.models import Finding, Observation, Severity

_VERSION = re.compile(r"\d+\.\d+")
# Headers that name the software. Drawn from the OWASP Secure Headers "remove" list.
_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-php-version",
    "x-generator",
    "x-generated-by",
    "x-powered-cms",
    "x-cms",
    "x-framework",
    "x-joomla-version",
    "x-umbraco-version",
    "x-owa-version",
    "x-powered-by-plesk",
    "x-server-powered-by",
    "powered-by",
)
# These carry a version by definition; the rest are reported only when a version number is present.
_ALWAYS_VERSIONED = frozenset({"x-aspnet-version", "x-aspnetmvc-version", "x-php-version", "x-joomla-version", "x-umbraco-version", "x-owa-version"})

# (label, severity, pattern). Each pattern is specific to the framework's own error page,
# so ordinary prose that mentions an error does not match.
_DEBUG_PAGES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("Django debug page", Severity.HIGH.value, re.compile(r"You.re seeing this error because you have <code>DEBUG = True</code>|Django tried these URL patterns, in this order")),
    ("Werkzeug interactive debugger", Severity.HIGH.value, re.compile(r"// Werkzeug Debugger</title>|The debugger caught an exception in your WSGI application|Werkzeug powered traceback interpreter")),
    ("Laravel debug page", Severity.HIGH.value, re.compile(r"<title>Whoops! There was an error|<div class=\"Whoops container\">|window\.ignite\(window\.data\)")),
    ("Rails error page", Severity.HIGH.value, re.compile(r"<title>Action Controller: Exception caught</title>|Rails\.root: ")),
    ("Symfony debug toolbar or profiler", Severity.HIGH.value, re.compile(r"id=\"sfWebDebugSymfony\"|debug mode</a> is enabled\.")),
    ("ASP.NET detailed error page", Severity.MEDIUM.value, re.compile(r"ASP\.NET is configured to show verbose error messages|This error page might contain sensitive information because ASP\.NET|<b>\s*Stack Trace:\s*</b>|An unhandled exception occurred while processing the request\.</h1>")),
    ("Spring Boot Whitelabel error page", Severity.LOW.value, re.compile(r"Whitelabel Error Page")),
    ("Tomcat error report with stack trace", Severity.MEDIUM.value, re.compile(r"<h1>HTTP Status 500[^<]*</h1>.*?(Exception|Stacktrace)", re.DOTALL)),
)

_STACK_TRACES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):\s*\n?\s*File \"")),
    ("Java stack trace", re.compile(r"(?:Exception|Error)(?::[^\n]{0,200})?\s+at [\w$.]+\([\w$]+\.java:\d+\)")),
    ("Node.js stack trace", re.compile(r"\bat [\w$.<> ]+ \((?:/|[A-Za-z]:\\)[^)\n]+\.(?:js|ts|mjs|cjs):\d+:\d+\)")),
    ("PHP error", re.compile(r"<b>(?:Fatal error|Warning|Notice|Parse error)</b>:\s+.{0,300}? in <b>[^<]+</b> on line <b>\d+</b>", re.DOTALL)),
    ("PHP stack trace", re.compile(r"PHP (?:Fatal error|Warning):\s+.{0,200}? in /[^\s]+\.php(?: on line |:)\d+", re.DOTALL)),
    (".NET stack trace", re.compile(r"\bat [\w.<>`]+\([^)]*\) in (?:[A-Za-z]:\\|/)[^\n]+:line \d+")),
    ("Go panic", re.compile(r"goroutine \d+ \[running\]:")),
    ("Ruby stack trace", re.compile(r"\.rb:\d+:in `[^']+'")),
)

_DATABASE_ERRORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("MySQL", re.compile(r"check the manual that (?:corresponds to|fits) your (?:MySQL|MariaDB) server version|MySQLSyntaxErrorException|com\.mysql\.jdbc|pymysql\.err\.|SQLSTATE\[\d+\]: Syntax error or access violation")),
    ("PostgreSQL", re.compile(r"PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s+syntax error at or near|psycopg2?\.errors\.|asyncpg\.exceptions\.")),
    ("Microsoft SQL Server", re.compile(r"Unclosed quotation mark after the character string|System\.Data\.SqlClient\.SqlException|Microsoft OLE DB Provider for SQL Server|\[SQL Server\]")),
    ("Oracle", re.compile(r"\bORA-\d{5}\b")),
    ("SQLite", re.compile(r"SQLite3::SQLException|sqlite3\.OperationalError:|\[SQLITE_ERROR\]|System\.Data\.SQLite\.SQLiteException")),
    ("MongoDB", re.compile(r"MongoServerError|MongoError:|com\.mongodb\.MongoException")),
)

_PRIVATE_IP = re.compile(
    r"(?<![\d.\w-])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])"
)
_DIRECTORY_LISTING = re.compile(
    r"<title>Index of /[^<]*</title>|<h1>Index of /[^<]*</h1>|<title>Directory listing for /[^<]*</title>|\[To Parent Directory\]",
    re.IGNORECASE,
)


def _is_internal(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private and not parsed.is_loopback


class DisclosureCheck(Check):
    id = "info-disclosure"
    title = "Information disclosure"
    summary = "Version banners, debug pages, stack traces, database errors, directory listings and internal addresses."

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        for page in ctx.pages:
            if page.status_code is None:
                continue
            found.extend(self._banners(ctx, page))
            found.extend(self._body(ctx, page))
        return merge_by_title(found)

    def _banners(self, ctx: CheckContext, page: Observation) -> list[Finding]:
        out: list[Finding] = []
        for name in _BANNER_HEADERS:
            value = page.header(name)
            if not value:
                continue
            if name not in _ALWAYS_VERSIONED and not _VERSION.search(value):
                continue
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title=f"Response header reveals software version ({name})",
                    severity=Severity.LOW.value,
                    evidence=f"{name}: {clip(value, 120)}",
                    explanation=(
                        "An exact product and version lets someone look up the known vulnerabilities for "
                        "that release without sending a single test request."
                    ),
                    remediation="Remove the header or strip the version number in the web server or framework configuration.",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        return out

    def _body(self, ctx: CheckContext, page: Observation) -> list[Finding]:
        body = page.body or ""
        out: list[Finding] = []
        if not body:
            return out
        for label, severity, pattern in _DEBUG_PAGES:
            match = pattern.search(body)
            if match:
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title=f"{label} is exposed",
                        severity=severity,
                        evidence=clip(_around(body, match), 240),
                        explanation=(
                            "The application is returning its developer error page to visitors. These pages "
                            "show source code, file paths, configuration and sometimes environment secrets."
                        ),
                        remediation="Turn debug mode off in production and return a generic error page. Log the detail on the server instead.",
                        cwe="CWE-489",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
                break
        for label, pattern in _STACK_TRACES:
            match = pattern.search(body)
            if match:
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title=f"{label} shown in a response",
                        severity=Severity.MEDIUM.value,
                        evidence=clip(_around(body, match), 240),
                        explanation="Stack traces reveal file paths, library versions and the internal structure of the code.",
                        remediation="Catch unhandled errors and return a generic message with a reference ID. Keep the trace in server logs.",
                        cwe="CWE-209",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
                break
        for label, pattern in _DATABASE_ERRORS:
            match = pattern.search(body)
            if match:
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title=f"{label} error message shown in a response",
                        severity=Severity.MEDIUM.value,
                        evidence=clip(_around(body, match), 240),
                        explanation=(
                            "Raw database errors reveal the database engine and query structure. They are also "
                            "a common sign that user input is reaching a query unsafely, which should be reviewed."
                        ),
                        remediation="Return a generic error. Review the query on this endpoint and make sure it uses parameterised statements.",
                        cwe="CWE-209",
                        owasp="A03:2021 Injection",
                        confidence="medium",
                    )
                )
                break
        if page.status_code == 200 and _DIRECTORY_LISTING.search(body):
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM.value,
                    evidence=clip(_DIRECTORY_LISTING.search(body).group(0), 120),
                    explanation="Anyone can browse the files in this folder, including backups and files that are not linked from the site.",
                    remediation="Disable directory indexes (`Options -Indexes` in Apache, `autoindex off` in nginx).",
                    cwe="CWE-548",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        internal = sorted({item for item in _PRIVATE_IP.findall(body) if _is_internal(item)})
        header_text = " ".join(value for _name, value in page.headers)
        internal += [item for item in sorted(set(_PRIVATE_IP.findall(header_text))) if _is_internal(item) and item not in internal]
        if internal:
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="Internal IP address disclosed",
                    severity=Severity.LOW.value,
                    evidence=", ".join(internal[:6]),
                    explanation="Private network addresses help map the internal network behind the site.",
                    remediation="Remove internal addresses from responses and headers, including those added by proxies and load balancers.",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    confidence="medium",
                )
            )
        return out


def _around(body: str, match: re.Match[str], radius: int = 90) -> str:
    start = max(0, match.start() - 20)
    end = min(len(body), match.end() + radius)
    return body[start:end]
