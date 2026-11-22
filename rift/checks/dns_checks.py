"""DNS-based checks: email spoofing protection (SPF, DMARC) and dangling subdomains.

These send DNS queries only. They need the optional `dnspython` package; when it
is missing the checks say so in the report instead of guessing.
"""

from __future__ import annotations

import re
from typing import Callable

from rift.checks.base import PROBE, Check, CheckContext, clip
from rift.models import Finding, Severity

# Lookup(name, record type) -> list of record strings, [] when the name has no such
# record, or None when the name does not exist at all (NXDOMAIN).
Lookup = Callable[[str, str], "list[str] | None"]

_TWO_PART_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz", "co.za", "org.za", "co.in", "net.in", "org.in",
        "co.jp", "ne.jp", "or.jp", "co.kr", "com.br", "com.mx", "com.ar", "com.co",
        "com.ng", "org.ng", "gov.ng", "edu.ng", "com.gh", "co.ke", "or.ke", "co.tz", "co.ug",
        "com.sg", "com.my", "com.hk", "com.tw", "com.cn", "com.tr", "com.sa", "com.eg",
        "co.il", "co.id", "co.th", "com.ph", "com.pk", "com.bd", "com.vn", "com.ua", "com.pl",
    }
)


def system_lookup(name: str, record: str) -> "list[str] | None":
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(name, record)
    except dns.resolver.NXDOMAIN:
        return None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    values: list[str] = []
    for item in answer:
        if record == "TXT":
            values.append(b"".join(item.strings).decode("utf-8", errors="replace"))
        else:
            values.append(str(item).rstrip("."))
    return values


def dns_available() -> bool:
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return False
    return True


def organisation_domain(host: str) -> str:
    """Best-effort registrable domain: example.co.uk, example.com."""

    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+|\[?[0-9a-fA-F:]+\]?", host))


class _DnsCheck(Check):
    kind = PROBE
    needs_pages = False
    lookup: Lookup | None = None

    def _resolver(self, ctx: CheckContext) -> Lookup | None:
        if self.lookup is not None:
            return self.lookup
        if _is_ip(ctx.host) or ctx.host in {"localhost"}:
            return None
        if not dns_available():
            ctx.note(self.id, "Skipped: install the `dnspython` package to enable DNS checks (it is in requirements.txt).")
            return None
        return system_lookup


class EmailAuthCheck(_DnsCheck):
    id = "email-auth"
    title = "Email spoofing protection"
    summary = "Missing or weak SPF and DMARC records, which let anyone send email that appears to come from the domain."

    def run(self, ctx: CheckContext) -> list[Finding]:
        lookup = self._resolver(ctx)
        if lookup is None:
            return []
        domain = organisation_domain(ctx.host)
        done = ctx.shared.setdefault("email-auth-done", set())
        if domain in done:  # one report per domain, not per origin
            return []
        done.add(domain)
        out: list[Finding] = []
        common = dict(
            url=f"dns:{domain}",
            cwe="CWE-290",
            owasp="A05:2021 Security Misconfiguration",
            reference="https://dmarc.org/overview/",
        )
        try:
            spf_records = [value for value in (lookup(domain, "TXT") or []) if value.lower().startswith("v=spf1")]
            dmarc_records = [value for value in (lookup(f"_dmarc.{domain}", "TXT") or []) if value.lower().startswith("v=dmarc1")]
        except Exception as exc:  # noqa: BLE001 - resolver trouble is a note, not a finding
            ctx.note(self.id, f"DNS lookup failed for {domain}: {exc.__class__.__name__}")
            return []
        if not spf_records:
            out.append(
                self.finding(
                    ctx,
                    title=f"No SPF record for {domain}",
                    severity=Severity.MEDIUM.value,
                    evidence=f"No TXT record starting with v=spf1 at {domain}.",
                    explanation="Without SPF, receiving mail servers cannot tell which servers are allowed to send email for this domain.",
                    remediation="Publish an SPF record listing your mail providers and ending in `-all`, for example `v=spf1 include:_spf.google.com -all`. If the domain sends no email, publish `v=spf1 -all`.",
                    **common,
                )
            )
        else:
            spf = spf_records[0].lower()
            if len(spf_records) > 1:
                out.append(
                    self.finding(
                        ctx,
                        title=f"More than one SPF record for {domain}",
                        severity=Severity.MEDIUM.value,
                        evidence="\n".join(clip(value, 160) for value in spf_records[:3]),
                        explanation="Mail servers treat multiple SPF records as an error and ignore all of them.",
                        remediation="Merge them into a single v=spf1 record.",
                        **common,
                    )
                )
            if re.search(r"(?:^|\s)\+?all\b", spf) and "-all" not in spf and "~all" not in spf and "?all" not in spf:
                out.append(
                    self.finding(
                        ctx,
                        title=f"SPF record for {domain} allows every sender",
                        severity=Severity.HIGH.value,
                        evidence=clip(spf_records[0], 200),
                        explanation="`+all` tells receivers that any server on the internet may send as this domain.",
                        remediation="End the record with `-all` (or `~all` while testing).",
                        **common,
                    )
                )
            elif "?all" in spf:
                out.append(
                    self.finding(
                        ctx,
                        title=f"SPF record for {domain} is neutral",
                        severity=Severity.LOW.value,
                        evidence=clip(spf_records[0], 200),
                        explanation="`?all` gives receivers no instruction for unlisted senders, so spoofed mail is not rejected.",
                        remediation="End the record with `-all` (or `~all` while testing).",
                        **common,
                    )
                )
        if not dmarc_records:
            out.append(
                self.finding(
                    ctx,
                    title=f"No DMARC record for {domain}",
                    severity=Severity.MEDIUM.value,
                    evidence=f"No TXT record starting with v=DMARC1 at _dmarc.{domain}.",
                    explanation=(
                        "Without DMARC, anyone can send email with this domain in the From line and most inboxes "
                        "will deliver it. That is how invoice fraud and phishing in your company's name works."
                    ),
                    remediation="Publish `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain` to start receiving reports, then move to `p=quarantine` and `p=reject`.",
                    **common,
                )
            )
        else:
            policy = re.search(r"\bp\s*=\s*(\w+)", dmarc_records[0].lower())
            if policy is None or policy.group(1) == "none":
                out.append(
                    self.finding(
                        ctx,
                        title=f"DMARC policy for {domain} does not block spoofed email",
                        severity=Severity.LOW.value,
                        evidence=clip(dmarc_records[0], 200),
                        explanation="`p=none` only asks for reports. Spoofed messages are still delivered.",
                        remediation="After reviewing the reports, raise the policy to `p=quarantine`, then `p=reject`.",
                        **common,
                    )
                )
        return out


# (service, CNAME suffixes, text that the provider's "nothing here" page contains).
# Strings are from the can-i-take-over-xyz project. An empty text means the signal
# is that the CNAME target no longer exists in DNS.
_TAKEOVER: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("AWS S3", ("s3.amazonaws.com", "amazonaws.com"), ("The specified bucket does not exist",)),
    ("GitHub Pages", ("github.io",), ("There isn't a GitHub Pages site here.",)),
    ("Heroku", ("herokuapp.com", "herokudns.com"), ("No such app",)),
    ("Bitbucket", ("bitbucket.io",), ("Repository not found",)),
    ("Ghost", ("ghost.io",), ("Site unavailable.", "Failed to resolve DNS path for this host")),
    ("Pantheon", ("pantheonsite.io",), ("404 error unknown site!",)),
    ("Readme.io", ("readme.io",), ("The creators of this project are still working on making everything perfect!",)),
    ("Read the Docs", ("readthedocs.io",), ("The link you have followed or the URL that you entered does not exist.",)),
    ("Help Scout", ("helpscoutdocs.com",), ("No settings were found for this company:",)),
    ("Helpjuice", ("helpjuice.com",), ("We could not find what you're looking for.",)),
    ("Surge.sh", ("surge.sh",), ("project not found",)),
    ("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable.",)),
    ("Tumblr", ("domains.tumblr.com",), ("Whatever you were looking for doesn't currently exist at this address",)),
    ("Netlify", ("netlify.app", "netlify.com"), ("Not Found - Request ID:",)),
    ("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"), ("The page you are looking for doesn't exist or has been moved.",)),
    ("Canny", ("cname.canny.io",), ("There is no such company. Did you enter the right URL?",)),
    ("Uberflip", ("read.uberflip.com",), ("The URL you've accessed does not provide a hub.",)),
    ("SurveySparrow", ("surveysparrow.com",), ("Account not found.",)),
    ("Agile CRM", ("agilecrm.com",), ("Sorry, this page is no longer available.",)),
    ("HatenaBlog", ("hatenablog.com",), ("404 Blog is not found",)),
    ("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), ()),
    (
        "Microsoft Azure",
        (
            "cloudapp.net", "cloudapp.azure.com", "azurewebsites.net", "blob.core.windows.net", "azure-api.net",
            "azureedge.net", "azurecontainer.io", "trafficmanager.net", "azurehdinsight.net",
        ),
        (),
    ),
    ("Discourse", ("trydiscourse.com",), ()),
)


def _matches_suffix(target: str, suffixes: tuple[str, ...]) -> bool:
    lowered = target.lower().rstrip(".")
    return any(lowered == suffix or lowered.endswith("." + suffix) for suffix in suffixes)


class TakeoverCheck(_DnsCheck):
    id = "subdomain-takeover"
    title = "Dangling subdomains"
    summary = "Hostnames whose DNS still points at a cloud resource that has been deleted and could be re-registered by someone else."

    def run(self, ctx: CheckContext) -> list[Finding]:
        lookup = self._resolver(ctx)
        if lookup is None:
            return []
        try:
            targets = lookup(ctx.host, "CNAME") or []
        except Exception as exc:  # noqa: BLE001
            ctx.note(self.id, f"DNS lookup failed for {ctx.host}: {exc.__class__.__name__}")
            return []
        if not targets:
            return []
        target = targets[0]
        bodies = " ".join((page.body or "")[:20000] for page in ctx.pages)
        for service, suffixes, texts in _TAKEOVER:
            if not _matches_suffix(target, suffixes):
                continue
            if texts:
                hit = next((text for text in texts if text in bodies), None)
                if hit is None:
                    return []
                evidence = f"{ctx.host} CNAME {target}\nThe page served contains the {service} placeholder text: \"{clip(hit, 100)}\""
            else:
                try:
                    exists = lookup(target, "A")
                except Exception:  # noqa: BLE001
                    return []
                if exists is not None:
                    return []
                evidence = f"{ctx.host} CNAME {target}\n{target} does not exist in DNS (NXDOMAIN)."
            return [
                self.finding(
                    ctx,
                    title=f"Subdomain points at an unclaimed {service} resource",
                    severity=Severity.HIGH.value,
                    evidence=evidence,
                    explanation=(
                        f"This hostname's DNS still points at {service}, but the resource behind it is gone. "
                        "If someone else can register that resource name, they can serve their own content on "
                        "your hostname, with access to cookies scoped to your domain."
                    ),
                    remediation=(
                        "Check in the provider's console whether the resource still belongs to you. If it does "
                        "not, delete the DNS record. Make removing DNS records part of decommissioning."
                    ),
                    cwe="CWE-350",
                    owasp="A05:2021 Security Misconfiguration",
                    reference="https://github.com/EdOverflow/can-i-take-over-xyz",
                    confidence="medium",
                )
            ]
        return []
