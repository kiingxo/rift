"""Files and admin endpoints that should never be reachable from the internet.

A path is reported only when the response body carries a fingerprint that the
real file has and an error page does not. A request to a random path on the same
origin is the control: if the fingerprint also matches there, the site answers
everything the same way and nothing is reported. File contents are never stored;
the evidence says which fingerprint matched.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from rift.checks.base import PROBE, Check, CheckContext, clip
from rift.checks.content import parse_resources
from rift.models import Finding, Observation, Severity

_CRIT = Severity.CRITICAL.value
_HIGH = Severity.HIGH.value
_MED = Severity.MEDIUM.value
_LOW = Severity.LOW.value


@dataclass(frozen=True)
class Exposure:
    path: str
    label: str
    severity: str
    proof: re.Pattern[str]
    what: str
    fix: str
    cwe: str = "CWE-538"
    plain_text: bool = True
    deep_only: bool = False
    min_matches: int = 1


def _x(path, label, severity, proof, what, fix, **extra) -> Exposure:
    return Exposure(path, label, severity, re.compile(proof, re.DOTALL | re.MULTILINE), what, fix, **extra)


_SOURCE = "Remove it from the web root and block dot-directories in the web server configuration."
_ROTATE = "Remove the file from the web root, then rotate every credential it contained."

EXPOSURES: tuple[Exposure, ...] = (
    _x("/.git/HEAD", "Git repository", _HIGH, r"\A(?:ref: refs/heads/\S+|[0-9a-f]{40})\s*\Z",
       "The site's Git folder is downloadable, which lets anyone rebuild the full source code and its history, including any secrets ever committed.",
       _SOURCE + " Rotate any secret that was ever committed.", cwe="CWE-527"),
    _x("/.git/config", "Git configuration", _HIGH, r"(?m)^\[core\]",
       "The Git configuration is readable. It names the remote repository and can contain access tokens.",
       _SOURCE, cwe="CWE-527"),
    _x("/.env", "Environment file", _CRIT, r"(?m)^[A-Z][A-Z0-9_]{2,}=\S",
       "The application's environment file is public. These files normally hold database passwords, API keys and signing secrets.",
       _ROTATE, min_matches=2),
    _x("/.env.production", "Environment file", _CRIT, r"(?m)^[A-Z][A-Z0-9_]{2,}=\S",
       "A production environment file is public. These files normally hold database passwords, API keys and signing secrets.",
       _ROTATE, min_matches=2, deep_only=True),
    _x("/.env.local", "Environment file", _CRIT, r"(?m)^[A-Z][A-Z0-9_]{2,}=\S",
       "A local environment file is public. These files normally hold database passwords, API keys and signing secrets.",
       _ROTATE, min_matches=2, deep_only=True),
    _x("/.env.bak", "Environment file backup", _CRIT, r"(?m)^[A-Z][A-Z0-9_]{2,}=\S",
       "A backup of the environment file is public.", _ROTATE, min_matches=2, deep_only=True),
    _x("/.aws/credentials", "AWS credentials file", _CRIT, r"(?i)aws_access_key_id\s*=",
       "An AWS credentials file is public. Its keys give direct access to the cloud account.", _ROTATE),
    _x("/.npmrc", "npm configuration with a token", _HIGH, r"_authToken=|_auth=",
       "An npm configuration file with a registry token is public.", _ROTATE, deep_only=True),
    _x("/.htpasswd", "Password file", _HIGH, r"(?m)^[^:\s]+:(?:\{SHA\}|\$apr1\$|\$2[aby]\$)",
       "The web server's password file is public. The hashes in it can be cracked offline.", _ROTATE),
    _x("/wp-config.php.bak", "WordPress configuration backup", _CRIT, r"define\(\s*['\"]DB_PASSWORD['\"]",
       "A backup copy of the WordPress configuration is served as plain text, including the database password.", _ROTATE),
    _x("/wp-config.php.old", "WordPress configuration backup", _CRIT, r"define\(\s*['\"]DB_PASSWORD['\"]",
       "An old copy of the WordPress configuration is served as plain text, including the database password.", _ROTATE, deep_only=True),
    _x("/wp-config.php~", "WordPress configuration backup", _CRIT, r"define\(\s*['\"]DB_PASSWORD['\"]",
       "An editor backup of the WordPress configuration is served as plain text, including the database password.", _ROTATE, deep_only=True),
    _x("/backup.sql", "Database dump", _CRIT, r"-- MySQL dump|-- PostgreSQL database dump|^(?:CREATE TABLE|INSERT INTO) ",
       "A database export is downloadable. It can contain every user record and password hash.",
       "Remove it from the web root and store backups somewhere that is not served."),
    _x("/dump.sql", "Database dump", _CRIT, r"-- MySQL dump|-- PostgreSQL database dump|^(?:CREATE TABLE|INSERT INTO) ",
       "A database export is downloadable. It can contain every user record and password hash.",
       "Remove it from the web root and store backups somewhere that is not served."),
    _x("/database.sql", "Database dump", _CRIT, r"-- MySQL dump|-- PostgreSQL database dump|^(?:CREATE TABLE|INSERT INTO) ",
       "A database export is downloadable. It can contain every user record and password hash.",
       "Remove it from the web root and store backups somewhere that is not served.", deep_only=True),
    _x("/db.sql", "Database dump", _CRIT, r"-- MySQL dump|-- PostgreSQL database dump|^(?:CREATE TABLE|INSERT INTO) ",
       "A database export is downloadable. It can contain every user record and password hash.",
       "Remove it from the web root and store backups somewhere that is not served.", deep_only=True),
    _x("/id_rsa", "SSH private key", _CRIT, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
       "A private key is downloadable.", "Remove it, then replace the key pair everywhere it was trusted.", deep_only=True),
    _x("/.ssh/id_rsa", "SSH private key", _CRIT, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
       "A private key is downloadable.", "Remove it, then replace the key pair everywhere it was trusted.", deep_only=True),
    _x("/server.key", "TLS private key", _CRIT, r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
       "The server's private key is downloadable, which lets someone impersonate the site.",
       "Remove it, then reissue the certificate with a new key.", deep_only=True),
    _x("/appsettings.json", ".NET application settings", _HIGH, r"\"ConnectionStrings\"\s*:",
       "The .NET settings file is public, including its database connection strings.", _ROTATE, plain_text=False),
    _x("/config.json", "Configuration file with secrets", _HIGH,
       r"(?i)\"(?:api_?key|token|secret|password|passwd|access_key|secret_key|client_secret)\"\s*:\s*\"[^\"]{8,}\"",
       "A configuration file with credential-like values is public.", _ROTATE, plain_text=False),
    _x("/docker-compose.yml", "Docker Compose file", _MED, r"(?m)^services:",
       "The deployment file is public. It shows internal service names, ports and often passwords in environment sections.",
       "Remove it from the web root.", deep_only=True),
    _x("/phpinfo.php", "phpinfo() page", _MED, r"PHP Version.{0,4000}PHP Extension|PHP Extension.{0,4000}PHP Version",
       "A phpinfo page shows the full PHP configuration, file paths, loaded modules and environment variables.",
       "Delete the file.", cwe="CWE-200", plain_text=False),
    _x("/info.php", "phpinfo() page", _MED, r"PHP Version.{0,4000}PHP Extension|PHP Extension.{0,4000}PHP Version",
       "A phpinfo page shows the full PHP configuration, file paths, loaded modules and environment variables.",
       "Delete the file.", cwe="CWE-200", plain_text=False),
    _x("/server-status", "Apache server-status", _MED, r"Apache Server Status.{0,2000}Server Version",
       "The Apache status page is public. It lists live requests, client IP addresses and internal URLs.",
       "Restrict /server-status to localhost (`Require local`).", cwe="CWE-200", plain_text=False),
    _x("/nginx_status", "nginx status page", _LOW, r"Active connections:\s*\d+",
       "The nginx status page is public.", "Restrict it to localhost or your monitoring network.", cwe="CWE-200", deep_only=True),
    _x("/actuator/env", "Spring Boot environment endpoint", _HIGH, r"\"(?:activeProfiles|propertySources)\"\s*:",
       "The Spring Boot actuator exposes the application's environment and configuration properties without a login.",
       "Expose only `health` publicly (`management.endpoints.web.exposure.include=health`) and require authentication for the rest.",
       cwe="CWE-200", plain_text=False),
    _x("/actuator", "Spring Boot actuator index", _LOW, r"\"_links\"\s*:\s*\{.{0,400}\"self\"",
       "The Spring Boot actuator index is public and lists the management endpoints that are switched on.",
       "Expose only `health` publicly and require authentication for the rest.", cwe="CWE-200", plain_text=False),
    _x("/debug/pprof/", "Go profiling endpoint", _MED, r"Types of profiles available",
       "Go's profiling pages are public. They leak memory contents and stack traces and can be used to slow the service.",
       "Do not register net/http/pprof on the public listener.", cwe="CWE-200", plain_text=False),
    _x("/debug/vars", "Go expvar endpoint", _LOW, r"\"memstats\"\s*:.{0,200000}\"cmdline\"\s*:|\"cmdline\"\s*:.{0,200000}\"memstats\"\s*:",
       "Go's expvar page is public, including the process command line.", "Serve it on an internal listener only.",
       cwe="CWE-200", plain_text=False, deep_only=True),
    _x("/telescope/requests", "Laravel Telescope", _HIGH, r"<title>Telescope[^<]*</title>",
       "Laravel Telescope is public. It records every request, query, job and exception, including request bodies.",
       "Disable Telescope in production or restrict it with its authorisation gate.", cwe="CWE-200", plain_text=False),
    _x("/elmah.axd", "ELMAH error log", _HIGH, r"Error Log for ",
       "The ELMAH error log is public. It lists every unhandled exception with request details and cookies.",
       "Restrict elmah.axd to authenticated administrators.", cwe="CWE-200", plain_text=False, deep_only=True),
    _x("/metrics", "Prometheus metrics", _LOW, r"(?m)^# HELP \S+[^\n]*\n# TYPE \S+",
       "Application metrics are public. They reveal internal routes, traffic volumes and dependency names.",
       "Serve metrics on an internal port or require authentication.", cwe="CWE-200", deep_only=True),
    _x("/crossdomain.xml", "Permissive crossdomain.xml", _LOW, r"<allow-access-from\s+domain=\"\*\"",
       "A legacy cross-domain policy allows every site.", "Delete the file; Flash is no longer supported.",
       cwe="CWE-942", plain_text=False, deep_only=True),
)

_DS_STORE = "\x00\x00\x00\x01Bud1"
_LISTING = re.compile(r"<title>Index of /|<h1>Index of /|<title>Directory listing for /|\[To Parent Directory\]", re.IGNORECASE)
_SOURCE_MAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
_SENSITIVE_ACTUATORS = ("env", "heapdump", "threaddump", "configprops", "mappings", "httptrace", "logfile", "beans", "shutdown")


def _looks_html(body: str) -> bool:
    start = body[:600].lower()
    return "<html" in start or "<!doctype html" in start or "<body" in start


def proves(item: Exposure, response: Observation) -> bool:
    if response.status_code not in {200, 206}:
        return False
    body = response.body or ""
    if not body:
        return False
    if item.plain_text and (_looks_html(body) or response.content_type == "text/html"):
        return False
    return len(item.proof.findall(body)) >= item.min_matches


class ExposedFilesCheck(Check):
    id = "exposed-files"
    title = "Exposed files and admin endpoints"
    summary = "Public Git folders, .env files, database dumps, private keys, debug and management endpoints."
    kind = PROBE

    def run(self, ctx: CheckContext) -> list[Finding]:
        control = ctx.fetch(f"{ctx.origin}/rift-{secrets.token_hex(6)}")
        if control.status_code is None:
            ctx.note(self.id, "The control request failed, so exposed-file checks were skipped.")
            return []
        found: list[Finding] = []
        for item in EXPOSURES:
            if item.deep_only and not ctx.deep:
                continue
            url = ctx.origin + item.path
            response = ctx.fetch(url)
            if response.error and "Scan cancelled" in response.error:
                break
            if not proves(item, response) or proves(item, control):
                continue
            evidence = f"GET {item.path} returned HTTP {response.status_code} and the body matches the {item.label} format."
            severity = item.severity
            if item.path == "/actuator":
                names = sorted(set(re.findall(r"\"([a-z]+)\"\s*:\s*\{\s*\"href\"", response.body or "")) - {"self"})
                evidence += f" Endpoints listed: {', '.join(names[:15]) or 'none'}."
                if any(name in _SENSITIVE_ACTUATORS for name in names):
                    severity = _HIGH
            found.append(
                self.finding(
                    ctx,
                    url=url,
                    title=f"{item.label} is publicly accessible ({item.path})",
                    severity=severity,
                    evidence=evidence + " The contents were not stored.",
                    explanation=item.what,
                    remediation=item.fix,
                    cwe=item.cwe,
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        found.extend(self._ds_store(ctx, control))
        found.extend(self._source_maps(ctx))
        found.extend(self._listings(ctx))
        return found

    def _ds_store(self, ctx: CheckContext, control: Observation) -> list[Finding]:
        response = ctx.fetch(ctx.origin + "/.DS_Store")
        body = response.body or ""
        if response.status_code != 200 or not body.startswith(_DS_STORE) or (control.body or "").startswith(_DS_STORE):
            return []
        return [
            self.finding(
                ctx,
                url=ctx.origin + "/.DS_Store",
                title="macOS .DS_Store file is publicly accessible",
                severity=_LOW,
                evidence="GET /.DS_Store returned the Finder metadata file signature.",
                explanation="This file lists the names of other files in the folder, including ones that are not linked anywhere.",
                remediation="Delete .DS_Store files from the deployment and exclude them from future builds.",
                cwe="CWE-538",
                owasp="A05:2021 Security Misconfiguration",
            )
        ]

    def _source_maps(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        limit = 4 if ctx.deep else 2
        for script in ctx.scripts:
            if len(out) >= limit:
                break
            match = _SOURCE_MAP.search((script.body or "")[-2000:])
            if not match or match.group(1).startswith("data:"):
                continue
            target = urljoin(script.url, match.group(1))
            if urlsplit(target).netloc != urlsplit(ctx.origin).netloc:
                continue
            response = ctx.fetch(target)
            body = response.body or ""
            if response.status_code != 200 or '"sources"' not in body or '"version"' not in body:
                continue
            original = '"sourcesContent"' in body
            out.append(
                self.finding(
                    ctx,
                    url=target,
                    title="JavaScript source map is downloadable",
                    severity=_LOW if original else Severity.INFO.value,
                    evidence=f"GET {clip(target, 160)} returned a source map"
                    + (" that embeds the original source code." if original else "."),
                    explanation="Anyone can read the original, unminified frontend code, including comments, internal API routes and feature flags.",
                    remediation="Stop publishing .map files, or upload them privately to your error-tracking service.",
                    cwe="CWE-540",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        return out

    def _listings(self, ctx: CheckContext) -> list[Finding]:
        """Open the folders the site's own pages load files from and look for an index page."""

        folders: list[str] = []
        for page in ctx.documents:
            resources = parse_resources(page.body or "")
            references = [item["src"] for item in resources.scripts] + [item["href"] for item in resources.styles]
            references += resources.passive
            for reference in references:
                absolute = urljoin(page.url, reference)
                parts = urlsplit(absolute)
                if f"{parts.scheme}://{parts.netloc}" != ctx.origin or "/" not in parts.path.strip("/"):
                    continue
                folder = ctx.origin + parts.path.rsplit("/", 1)[0] + "/"
                if folder not in folders:
                    folders.append(folder)
        out: list[Finding] = []
        for folder in folders[: 8 if ctx.deep else 3]:
            response = ctx.fetch(folder)
            match = _LISTING.search(response.body or "") if response.status_code == 200 else None
            if match:
                out.append(
                    self.finding(
                        ctx,
                        url=folder,
                        title="Directory listing is enabled",
                        severity=_MED,
                        evidence=f"GET {clip(folder, 160)} returned an index page ({clip(match.group(0), 60)}).",
                        explanation="Anyone can browse the files in this folder, including backups and files that are not linked from the site.",
                        remediation="Disable directory indexes (`Options -Indexes` in Apache, `autoindex off` in nginx).",
                        cwe="CWE-548",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
        return out
