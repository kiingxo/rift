"""What the HTML itself loads and submits: mixed content, third-party scripts, forms."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from rift.checks.base import Check, CheckContext, clip, merge_by_title
from rift.models import Finding, Observation, Severity


class _Resources(HTMLParser):
    """Collect the tags that matter. Nothing is executed or fetched."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str]] = []
        self.styles: list[dict[str, str]] = []
        self.passive: list[str] = []
        self.frames: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.links: list[str] = []
        # <link rel="modulepreload">: scripts the page will run, listed ahead of time.
        self.preloads: list[str] = []
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script" and values.get("src"):
            self.scripts.append(values)
        elif tag == "link" and "stylesheet" in values.get("rel", "").lower() and values.get("href"):
            self.styles.append(values)
        elif tag == "link" and "modulepreload" in values.get("rel", "").lower() and values.get("href"):
            self.preloads.append(values["href"])
        elif tag in {"img", "audio", "video", "source"} and values.get("src"):
            self.passive.append(values["src"])
        elif tag in {"iframe", "frame", "embed"} and values.get("src"):
            self.frames.append(values["src"])
        elif tag == "object" and values.get("data"):
            self.frames.append(values["data"])
        elif tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").lower(), "password": False}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and values.get("type", "").lower() == "password":
            self._form["password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def parse_resources(body: str) -> _Resources:
    parser = _Resources()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML still yields what was parsed so far
        pass
    return parser


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


class ContentCheck(Check):
    id = "page-content"
    title = "Page content"
    summary = "Mixed content, third-party scripts without integrity hashes, and login forms sent in the clear."

    def run(self, ctx: CheckContext) -> list[Finding]:
        found: list[Finding] = []
        for page in ctx.documents:
            found.extend(self._page(ctx, page))
        return merge_by_title(found)

    def _page(self, ctx: CheckContext, page: Observation) -> list[Finding]:
        out: list[Finding] = []
        resources = parse_resources(page.body or "")
        page_https = page.url.startswith("https://")
        page_host = _host(page.url)

        def absolute(value: str) -> str:
            return urljoin(page.url, value.strip())

        if page_https:
            active = [absolute(item["src"]) for item in resources.scripts]
            active += [absolute(item["href"]) for item in resources.styles]
            active += [absolute(item) for item in resources.frames]
            insecure_active = [url for url in active if url.startswith("http://")]
            if insecure_active:
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="HTTPS page loads scripts, styles or frames over plain HTTP",
                        severity=Severity.MEDIUM.value,
                        evidence="\n".join(clip(url, 160) for url in insecure_active[:5]),
                        explanation=(
                            "Anyone on the network path can replace these files and run their own code inside "
                            "the page. Modern browsers block most of them, which also breaks the page."
                        ),
                        remediation="Load every script, stylesheet and frame over https://.",
                        cwe="CWE-319",
                        owasp="A02:2021 Cryptographic Failures",
                    )
                )
            insecure_passive = [absolute(item) for item in resources.passive]
            insecure_passive = [url for url in insecure_passive if url.startswith("http://")]
            if insecure_passive:
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="HTTPS page loads images or media over plain HTTP",
                        severity=Severity.LOW.value,
                        evidence="\n".join(clip(url, 160) for url in insecure_passive[:5]),
                        explanation="These requests are visible to and replaceable by anyone on the network path, and browsers show the page as not fully secure.",
                        remediation="Serve images and media over https://.",
                        cwe="CWE-319",
                        owasp="A02:2021 Cryptographic Failures",
                    )
                )
        unpinned: list[str] = []
        for item in resources.scripts:
            source = absolute(item["src"])
            if source.startswith(("http://", "https://")) and _host(source) != page_host and not item.get("integrity"):
                unpinned.append(source)
        if unpinned:
            hosts = sorted({_host(url) for url in unpinned})
            out.append(
                self.finding(
                    ctx,
                    url=page.url,
                    title="Third-party scripts load without Subresource Integrity",
                    severity=Severity.LOW.value,
                    evidence=f"{len(unpinned)} script(s) from: {', '.join(hosts[:8])}\n" + "\n".join(clip(url, 160) for url in unpinned[:4]),
                    explanation=(
                        "If one of these hosts is compromised or the file is changed, the new code runs on "
                        "this site with full access to the page. An `integrity` hash makes the browser refuse "
                        "a file that has changed."
                    ),
                    remediation=(
                        "For fixed-version files, add `integrity=\"sha384-…\" crossorigin=\"anonymous\"`. "
                        "For scripts that change by design (analytics, tag managers), restrict them with CSP and review the vendor."
                    ),
                    cwe="CWE-353",
                    owasp="A08:2021 Software and Data Integrity Failures",
                    confidence="medium",
                )
            )
        for form in resources.forms:
            if not form["password"]:
                continue
            action = absolute(str(form["action"])) if form["action"] else page.url
            if not page_https or action.startswith("http://"):
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="Password form is sent over plain HTTP",
                        severity=Severity.HIGH.value,
                        evidence=f"Form action: {clip(action, 160)} · page: {clip(page.url, 120)}",
                        explanation="The password travels unencrypted, so anyone on the network path can read it.",
                        remediation="Serve the login page and its form action over HTTPS only, and redirect HTTP to HTTPS.",
                        cwe="CWE-319",
                        owasp="A02:2021 Cryptographic Failures",
                    )
                )
            if form["method"] == "get":
                out.append(
                    self.finding(
                        ctx,
                        url=page.url,
                        title="Password form submits with GET",
                        severity=Severity.MEDIUM.value,
                        evidence=f"<form method=\"get\" action=\"{clip(str(form['action']), 120)}\"> with a password field",
                        explanation="The password ends up in the URL, so it is saved in browser history, server logs and proxy logs.",
                        remediation="Submit the form with `method=\"post\"`.",
                        cwe="CWE-598",
                        owasp="A04:2021 Insecure Design",
                    )
                )
        return out
