# Rift

**A read-only security checker for websites and APIs you own.**

Point Rift at your site and it looks at it the way an outsider would. Can people see things they shouldn't? Is a secret key sitting in your JavaScript? Is your `.git` folder public? Does the admin API answer without a login? Rift checks all of that and more, then tells you in plain language what it found, why it matters, and how to fix it.

It only ever *reads*. Rift never submits forms, never changes data and never tries to break in. That makes it safe to run against a real app, including staging and production, as long as the app is yours or you have written permission to test it.

Everything runs on your own computer. Rift doesn't call an AI model, and it doesn't send your targets or results anywhere.

Rift is made by [Blueprint Labs](https://github.com/Blueprintlabs-ai) and released under the MIT license.

---

## Contents

- [Quick start](#quick-start)
- [Your first scan](#your-first-scan)
- [What Rift looks for](#what-rift-looks-for)
- [Scanning the part behind the login](#scanning-the-part-behind-the-login)
- [How Rift stays safe](#how-rift-stays-safe)
- [Using it from the command line and in CI](#using-it-from-the-command-line-and-in-ci)
- [What Rift doesn't do](#what-rift-doesnt-do)
- [Try it on a practice site](#try-it-on-a-practice-site)
- [Contributing](#contributing)

---

## Quick start

### With Docker (easiest)

You only need [Docker](https://docs.docker.com/get-docker/) installed.

```bash
git clone https://github.com/kiingxo/rift.git
cd rift
docker compose up
```

Then open **<http://localhost:8600>** in your browser.

Your saved scans live in a Docker volume, so they survive restarts. To stop Rift, press `Ctrl+C` (or run `docker compose down`).

### With Python

You need Python 3.9 or newer.

```bash
git clone https://github.com/kiingxo/rift.git
cd rift
./run.sh
```

`run.sh` creates a virtual environment, installs the few dependencies Rift needs, and opens the console in your browser at <http://127.0.0.1:8600>.

On Windows, or if you'd rather do it by hand:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip
.venv/bin/python -m rift serve                 # Windows: .venv\Scripts\python
```

Either way, the console only listens on your own computer. Nobody else on your network can reach it.

---

## Your first scan

1. Open the console and go to **New scan**.
2. **Targets:** paste one or more addresses, one per line. For example, your app at `https://app.example.com/` and its API at `https://api.example.com/`.
3. **Depth:** *Fast* takes a minute or two. *Deep* reads more pages and tries more paths.
4. **Sign in:** leave this on *Not signed in* for your first scan. See [Scanning the part behind the login](#scanning-the-part-behind-the-login) for what it does.
5. **Checks:** all of them are on by default.
6. **Confirm scope:** tick the box to confirm you own these sites or have permission to test them, then start the scan.

You can watch the findings arrive while Rift works, and pause or cancel at any time. When it's done you get:

- **A grade (A to F)** and a breakdown by severity: critical, high, medium, low and info.
- **A list of findings.** Each one has the evidence Rift saw, an explanation of why it matters, and how to fix it. Each finding also carries its CWE and OWASP category, for people who track those.
- **Exports.** You can download an HTML report you can email, plus JSON, CSV and SARIF (which GitHub code scanning understands).

Every scan is saved, so you can open it again later from **Scan history**.

> A clean result means Rift's checks found nothing. It doesn't prove a site is secure. See [What Rift doesn't do](#what-rift-doesnt-do).

---

## What Rift looks for

| Area | What it catches |
| --- | --- |
| **Security headers** | Missing or weak HSTS, Content-Security-Policy, clickjacking protection, `nosniff`, Referrer-Policy and Permissions-Policy |
| **Cookies** | Session cookies missing `Secure`, `HttpOnly` or `SameSite` |
| **Page content** | Mixed HTTP/HTTPS content, third-party scripts without integrity hashes, password forms that send over plain HTTP |
| **Information leaks** | Software version banners, framework debug pages, stack traces, raw database errors, directory listings, internal IP addresses |
| **Exposed secrets** | API keys and tokens for about 20 providers, private keys and database passwords, found in pages or JavaScript |
| **JSON Web Tokens** | Tokens that are unsigned, never expire, last too long, or carry sensitive data |
| **HTTPS and TLS** | Untrusted or expiring certificates, old TLS versions, plain HTTP that doesn't redirect |
| **CORS** | APIs that let any website read their responses, sometimes along with the visitor's cookies |
| **Server configuration** | Dangerous HTTP methods, default pages, caching mistakes, a missing `security.txt` |
| **Exposed files** | Public `.git` folders, `.env` files, database dumps, backups, source maps, debug and admin endpoints |
| **APIs** | Public OpenAPI/Swagger files, "private" endpoints that answer without a login, sensitive fields in JSON, open GraphQL introspection |
| **Email spoofing** | Missing or weak SPF and DMARC records, which let others send email as your domain |
| **Dangling subdomains** | DNS still pointing at a deleted cloud resource that someone else could claim |
| **Open redirects** | Links on your site that can send visitors anywhere an attacker chooses |
| **Signed-in access** | With a test account: private data shown to anyone, private pages that caches may keep, session tokens leaking into URLs, and whether signing out really ends the session |

### How Rift avoids false alarms

A scanner that cries wolf gets ignored, so Rift tries hard to report only what it can show:

- **It needs evidence.** For example, an "exposed `.env` file" is only reported when the response actually looks like a `.env` file. Rift also requests a random path on the same site as a control. Single-page apps answer every address with the same page, and that page doesn't count as a hit.
- **Its probes have controls.** A CORS finding needs the server to trust an origin that can't exist. A redirect finding is checked against a same-site control.
- **Secrets are redacted.** Reports show only the first few characters and the length of any secret Rift finds.
- **One problem is one finding.** A header missing on 30 pages becomes a single finding that lists the 30 pages.

The test suite includes a deliberately well-configured site, and Rift has to report nothing against it.

---

## Scanning the part behind the login

Most of an app sits behind its login, and that's usually where the sensitive data is. Rift can scan that part using a **test account** you sign in to yourself. You never give Rift a password.

### How to do it

1. **Create a test account**, on a staging copy of your app if you have one. Never use a real customer's account.
2. **Sign in** to it in your normal browser.
3. **Copy its session.** Open developer tools (`F12`, or `Cmd+Option+I` on a Mac) and go to the **Network** tab. Click a request your app makes, and look at its *request headers*:
   - If the app uses cookies, copy the `Cookie` header.
   - If it uses tokens (most single-page apps and APIs do), copy the `Authorization` header. It usually looks like `Bearer eyJ...`.
4. **In Rift:** under **Sign in**, choose *Session cookie* or *Header or token*, and paste what you copied.
5. **Add some signed-in text:** something only that user can see, such as the test account's email address. Rift uses it to tell whether your session actually worked.

If your app's front end and API are on different addresses (say `app.example.com` and `api.example.com`), add both as targets. Rift only sends your session to the addresses you list. If it notices the app talking to a host you left out, it tells you and offers to scan again with that host added.

### What Rift does with it

- **Reads the signed-in part of the app.** It follows links from each page, and runs every check on those pages too.
- **Asks the same question twice.** Each private page or API address is requested once with your session and once without it. If your account's data still shows up without a login, anyone on the internet can see it, and Rift reports that as **critical**.
- **Understands JavaScript apps.** Apps built with React, Vue and similar frameworks keep their data behind an API, not in their HTML. Rift reads the app's JavaScript as text (it never runs it) and finds the API addresses the app itself calls. It then tests those addresses, asking for one record at a time.
- **Checks private pages aren't cached.** If a CDN stores an account page, other visitors could be shown it.
- **Looks for leaked session tokens** in URLs and in page HTML, and checks how strong the token itself is when it's a JWT.
- **Checks sign-out.** After the scan, sign out in your browser and press **"I signed out, check now"**. Rift tries your old session once. If it still works, signing out doesn't really end the session. That's a common and serious problem.

### What Rift won't open while signed in

While it holds your session, Rift acts as your test account. So it won't open addresses that look like they *do* something, such as signing out, deleting, cancelling, approving, sending a message or paying. It also skips addresses with placeholders it can't fill in (like `/patients/${id}`), as well as sign-in flows and live connections.

Nothing is hidden. Every address Rift skipped is listed in the results, with the reason, so you can check those by hand.

### Your session stays private

- It's sent only to the hosts you listed, and only with read-only requests.
- It's kept in memory and never written to disk. Every copy of it is replaced with `[session]` in findings, logs, saved scans and exports.
- Rift never keeps cookies that a site sets, so its "without the session" requests really are anonymous.

---

## How Rift stays safe

Rift is designed so that running it can't hurt the site you're scanning:

- **Read-only.** It only sends `GET`, `HEAD` and `OPTIONS` requests. The HTTP client refuses anything else, whatever a check asks for.
- **You confirm the scope.** Every scan needs your confirmation that you're allowed to test these sites, and it stays within the domains you gave it.
- **No surprises inside your network.** Localhost, private network addresses and cloud metadata endpoints (like `169.254.169.254`) are blocked. Rift checks DNS answers and pins each connection to a checked address, so DNS tricks can't redirect it.
- **Gentle by default.** At most 2 requests at a time per site, at least a quarter of a second apart, and 500 requests per site. You can change these per scan.
- **Small reads.** Pages are read up to 200 KB, so a large exposed file is detected without being downloaded. JavaScript files are read up to 4 MB.
- **It says who it is.** Requests carry the user agent `RiftScanner/2.0.0 (+https://github.com/kiingxo/rift)`, so the people running the site can see what's scanning them.

The console protects itself as well. Other websites open in your browser can't start scans through it, it refuses DNS rebinding, and it treats everything it shows from scanned sites as text, never as code.

> **Only scan what you own or have written permission to test.** Scanning other people's sites without permission may be illegal where you live, even when the scan only reads.

---

## Using it from the command line and in CI

Everything the console does also works from the terminal:

```bash
# One site, with an HTML report
python -m rift https://app.example.com --i-am-authorised --html report.html

# A list of sites (see urls.txt), a deeper scan, and a CI-friendly exit code
python -m rift urls.txt --mode deep --json report.json --sarif rift.sarif --fail-on high

# Signed in with a test account
export RIFT_TEST_HEADER='Authorization: Bearer eyJ...'
python -m rift https://app.example.com https://api.example.com --i-am-authorised --signed-in-text test@example.com

# Every check Rift has
python -m rift --list-checks
```

With Docker, put `docker compose run --rm rift` in front instead of `python -m rift`:

```bash
docker compose run --rm rift https://app.example.com --i-am-authorised
```

**In a CI pipeline:**
- `--fail-on high` makes Rift exit with status 1 when it finds anything high or critical, so the pipeline can block a release.
- `--sarif` writes a file that GitHub code scanning can show alongside your code.

---

## What Rift doesn't do

Because Rift never changes data and never sends attack payloads, some important things are out of its reach:

- **Injection testing:** SQL injection, cross-site scripting, template injection and SSRF.
- **Comparing two accounts:** whether user A can read or change user B's records (IDOR/BOLA). This is the top risk in the OWASP API Top 10.
- **Anything that writes:** checking whether someone can *change* or *delete* data they shouldn't.
- **Brute force, rate-limit testing, and running your app's JavaScript.**

For those, pair Rift with an active scanner such as [OWASP ZAP](https://www.zaproxy.org/) or [Burp Suite](https://portswigger.net/burp), run against a staging copy. For anything that matters, also get a proper penetration test. Rift is a fast first pass and a regular check-up, not a replacement for either.

---

## Try it on a practice site

The repository includes a deliberately broken site, plus a well-built twin of it, so you can see what findings look like without scanning anything real:

```bash
python -m tests.weak_site &                            # a weak site on http://127.0.0.1:8770
RIFT_ALLOW_INTERNAL=1 python -m rift serve             # "lab mode": allows scanning localhost
```

Then scan `http://127.0.0.1:8770/` in the console. Run `python -m tests.weak_site hardened` to try the well-built version, which should come back clean apart from "no HTTPS".

Lab mode only exists for local practice. Cloud metadata addresses stay blocked even in lab mode.

---

## Contributing

Issues and pull requests are welcome.

### Run the tests

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

The suite runs against local test sites and never contacts the internet. Here's what the main test files cover:

- `tests/test_checks.py`: each check, using hand-built responses.
- `tests/test_audit.py`: full scans, the command line and every report format, over real sockets.
- `tests/test_server.py`: the console's API and its protections.
- `tests/test_signed_in.py`: signed-in scanning, including a JavaScript app whose data sits behind its API. It also checks that the session never leaks into a report.

### Add a check

1. Create `rift/checks/your_check.py` with a `Check` subclass. Set its `id`, `title`, `summary` and `kind`. Use `PASSIVE` if it only reads pages Rift already fetched, and `PROBE` if it sends its own requests.
2. Return `Finding` objects from `run(ctx)`. Use `self.finding(ctx, ...)` so the check and domain are filled in for you.
3. Register it in `all_checks()` in `rift/checks/__init__.py`.
4. Add a test where it should fire and a test where it shouldn't, in `tests/test_checks.py`.

Checks can only send requests through `ctx.fetch`, so every new check automatically follows the scope and safety rules.

### Where things live

| Path | What it is |
| --- | --- |
| `rift/web/` | The console: plain HTML, CSS and JavaScript, no build step |
| `rift/server.py` | The console's local API: scans, history, exports |
| `rift/audit.py` | Collects pages and scripts, runs the checks, builds the report |
| `rift/checks/` | One file per check, plus the registry |
| `rift/endpoints.py` | Finds API addresses in an app's JavaScript and decides which are safe to read |
| `rift/session.py` | The test account's session: parsing, where it may go, scrubbing |
| `rift/http_client.py` | The read-only HTTP client: scope, DNS pinning, rate limits |
| `rift/safety.py` | Scope rules and the private-network block |
| `rift/audit_report.py` | HTML, JSON, CSV and SARIF reports, and the grade |
| `rift/cli.py` | The command line |
| `rift/engine.py` and friends | The open-redirect engine |
| `tests/weak_site.py` | The practice sites |

### Settings you can change

| Environment variable | What it does |
| --- | --- |
| `RIFT_DATA_DIR` | Where saved scans go (default: `scans/` in the project folder) |
| `RIFT_ALLOWLIST` | A file of domains you're always allowed to scan from the command line |
| `RIFT_ALLOW_INTERNAL=1` | Lab mode: allows localhost and private addresses |
| `RIFT_TEST_COOKIE` / `RIFT_TEST_HEADER` | A test account's session for command-line scans |

---

## License

MIT. See [LICENSE](LICENSE). Made by Blueprint Labs.
