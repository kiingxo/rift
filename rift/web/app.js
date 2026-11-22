/* Rift console frontend.
 *
 * Everything a scanned site controls (titles, URLs, evidence) reaches the page
 * through textContent only. Nothing here builds HTML from strings, so a hostile
 * target cannot inject markup into the console.
 */
(function () {
  "use strict";

  var TOKEN = document.querySelector('meta[name="rift-token"]').content;
  var SEVERITIES = ["critical", "high", "medium", "low", "info"];
  var view = document.getElementById("view");
  var toastBox = document.getElementById("toast");
  var meta = null;
  var pollTimer = null;
  var toastTimer = null;
  var renderToken = 0;

  // New-scan form state survives navigating away and back.
  var form = { targets: "", mode: "fast", checks: null, authorised: false, preview: null, limit: null, pace: null, timeout: null,
    auth: "none", cookie: "", header: "", marker: "" };
  // Results-view state.
  var ui = { scanId: null, severity: "all", check: "all", query: "", selected: null };

  // ---- helpers ---------------------------------------------------------------

  function h(tag, props) {
    var node = document.createElement(tag);
    var key;
    if (props) {
      for (key in props) {
        if (!Object.prototype.hasOwnProperty.call(props, key)) continue;
        var value = props[key];
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = value;
        else if (key.slice(0, 2) === "on") node.addEventListener(key.slice(2), value);
        else if (key === "checked" || key === "disabled" || key === "hidden" || key === "value") node[key] = value;
        else node.setAttribute(key, value === true ? "" : String(value));
      }
    }
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) child.forEach(function (item) { append(node, item); });
    else if (child instanceof Node) node.appendChild(child);
    else node.appendChild(document.createTextNode(String(child)));
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function api(method, path, body) {
    var options = { method: method, headers: { "X-Rift-Token": TOKEN }, cache: "no-store" };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(path, options).then(function (response) {
      if (response.ok) return response.json();
      return response.json().catch(function () { return {}; }).then(function (data) {
        var detail = data && data.detail;
        if (Array.isArray(detail)) detail = detail.map(function (item) { return item.msg; }).join("; ");
        throw new Error(detail || "Request failed (" + response.status + ")");
      });
    });
  }

  function toast(message, isError) {
    toastBox.textContent = message;
    toastBox.className = "toast" + (isError ? " error" : "");
    toastBox.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastBox.hidden = true; }, isError ? 7000 : 2600);
  }

  function fail(error) { toast(error.message || String(error), true); }

  function copy(text, label) {
    navigator.clipboard.writeText(text).then(function () { toast(label + " copied"); }, function () { toast("Copy failed", true); });
  }

  function when(iso) {
    var date = new Date(iso);
    if (isNaN(date.getTime())) return iso || "";
    return date.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function plural(count, word) { return count + " " + word + (count === 1 ? "" : "s"); }

  function checkTitle(id) {
    var found = meta.checks.filter(function (item) { return item.id === id; })[0];
    return found ? found.title : id;
  }

  function targetLabel(scan) {
    if (scan.domains && scan.domains.length) {
      return scan.domains.length > 2 ? scan.domains[0] + " +" + (scan.domains.length - 1) + " more" : scan.domains.join(", ");
    }
    return (scan.targets && scan.targets[0]) || "Scan";
  }

  function pathOf(url) {
    try {
      var parsed = new URL(url);
      return (parsed.pathname || "/") + parsed.search;
    } catch (error) { return url; }
  }

  function pill(severity) { return h("span", { class: "pill sev-" + severity, text: severity }); }

  function bar(summary, thin) {
    var label = SEVERITIES.map(function (name) { return (summary[name] || 0) + " " + name; }).join(", ");
    var box = h("div", { class: "bar" + (thin ? " thin" : ""), role: "img", "aria-label": label });
    var any = false;
    SEVERITIES.forEach(function (name) {
      var count = summary[name] || 0;
      if (!count) return;
      any = true;
      var segment = h("div", { class: "fill-" + name });
      segment.style.flex = count + " 1 0";
      box.appendChild(segment);
    });
    if (!any) {
      var none = h("div", { class: "fill-none" });
      none.style.flex = "1 1 0";
      box.appendChild(none);
    }
    return box;
  }

  function stopPolling() { clearTimeout(pollTimer); pollTimer = null; }

  function setNav(name) {
    Array.prototype.forEach.call(document.querySelectorAll(".nav a"), function (link) {
      if (link.getAttribute("data-nav") === name) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  }

  function show() {
    clear(view);
    for (var i = 0; i < arguments.length; i++) append(view, arguments[i]);
  }

  // A status line (crumb) sits above the title; a description sits below it.
  function header(title, sub, actions, mono) {
    var heading = h("h1", { class: mono ? "mono" : null, text: title });
    var above = sub && sub.classList && sub.classList.contains("crumb");
    return h("header", { class: "head" },
      h("div", { class: "head-text" }, above ? sub : null, heading, above ? null : sub),
      actions ? h("div", { class: "actions" }, actions) : null);
  }

  // ---- new scan --------------------------------------------------------------

  var previewTimer = null;

  function selectedChecks() {
    return form.checks === null ? meta.checks.map(function (item) { return item.id; }) : form.checks;
  }

  function renderNew() {
    setNav("new");
    stopPolling();
    var chosen = selectedChecks();
    var scopeBox = h("div");
    var startButton = h("button", { type: "button", class: "btn primary big", text: "Start scan", onclick: start });
    var countLabel = h("span", { class: "muted", text: "" });

    function sessionReady() {
      if (form.auth === "cookie") return form.cookie.trim().length > 0;
      if (form.auth === "header") return form.header.trim().length > 0;
      return true;
    }

    function refreshStart() {
      var ready = form.preview && form.preview.urls.length > 0 && form.authorised && selectedChecks().length > 0 && sessionReady();
      startButton.disabled = !ready;
      countLabel.textContent = " " + selectedChecks().length + " of " + meta.checks.length + " selected";
    }

    function drawScope() {
      clear(scopeBox);
      var preview = form.preview;
      if (!preview || (!preview.urls.length && !preview.excluded.length)) {
        scopeBox.appendChild(h("div", { class: "code muted", text: "Add a URL to see which domains the scan may contact." }));
      } else {
        scopeBox.appendChild(h("div", { class: "code domains" },
          preview.domains.length ? preview.domains.map(function (domain) { return h("div", { text: domain }); }) : h("div", { class: "muted", text: "None of these URLs can be scanned." })));
        if (preview.urls.length) {
          scopeBox.appendChild(h("div", { class: "small muted", text: plural(preview.urls.length, "URL") + ". Subdomains of these hosts are in scope. Every other host is refused, including redirect targets." }));
        }
        preview.excluded.forEach(function (item) {
          scopeBox.appendChild(h("div", { class: "excluded", text: "Not scanned: " + item.url + " (" + item.reason + ")" }));
        });
      }
      refreshStart();
    }

    function requestPreview() {
      clearTimeout(previewTimer);
      previewTimer = setTimeout(function () {
        api("POST", "/api/preview", { targets: form.targets }).then(function (data) { form.preview = data; drawScope(); }, fail);
      }, 250);
    }

    function start() {
      startButton.disabled = true;
      api("POST", "/api/scans", {
        targets: form.targets,
        mode: form.mode,
        checks: selectedChecks(),
        authorised: form.authorised,
        max_requests_per_domain: Number(form.limit || meta.defaults.max_requests_per_domain),
        min_interval_seconds: Number(form.pace || meta.defaults.min_interval_seconds),
        timeout_seconds: Number(form.timeout || meta.defaults.timeout_seconds),
        session_cookie: form.auth === "cookie" ? form.cookie : "",
        session_header: form.auth === "header" ? form.header : "",
        signed_in_text: form.auth !== "none" ? form.marker : ""
      }).then(function (data) {
        form.authorised = false;
        // The session lives in the server's memory for this scan only; the form forgets it.
        form.cookie = "";
        form.header = "";
        location.hash = "#/scan/" + data.id;
      }, function (error) { fail(error); refreshStart(); });
    }

    var textarea = h("textarea", {
      id: "targets", class: "targets", rows: "4", spellcheck: "false",
      placeholder: "https://app.example.com\nhttps://api.example.com/v1/status",
      oninput: function (event) { form.targets = event.target.value; requestPreview(); }
    });
    textarea.value = form.targets;

    var fileInput = h("input", { type: "file", accept: ".txt,text/plain", hidden: true, onchange: function (event) {
      var file = event.target.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        form.targets = (form.targets ? form.targets.replace(/\s+$/, "") + "\n" : "") + String(reader.result);
        textarea.value = form.targets;
        requestPreview();
      };
      reader.readAsText(file);
    } });

    function depthOption(mode, title, text) {
      return h("button", { type: "button", class: "option", role: "radio", "aria-checked": form.mode === mode ? "true" : "false",
        onclick: function () { form.mode = mode; renderNew(); } }, h("b", { text: title }), h("span", { text: text }));
    }

    function setChecks(ids) { form.checks = ids; renderNew(); }

    function authOption(kind, title, text) {
      return h("button", { type: "button", class: "option", role: "radio", "aria-checked": form.auth === kind ? "true" : "false",
        onclick: function () { form.auth = kind; renderNew(); } }, h("b", { text: title }), h("span", { text: text }));
    }

    function secretField(id, label, key, placeholder, hint) {
      var input = h("input", { id: id, class: "input mono", type: "password", autocomplete: "off", spellcheck: "false", placeholder: placeholder,
        oninput: function (event) { form[key] = event.target.value; refreshStart(); } });
      input.value = form[key];
      return h("div", { class: "field" }, h("label", { for: id, text: label }), input, h("span", { class: "hint", text: hint }));
    }

    var authFields = null;
    if (form.auth !== "none") {
      var markerInput = h("input", { id: "signed-in-text", class: "input", type: "text", autocomplete: "off", spellcheck: "false",
        placeholder: "The test account's email address", oninput: function (event) { form.marker = event.target.value; } });
      markerInput.value = form.marker;
      authFields = h("div", { class: "auth-fields" },
        form.auth === "cookie"
          ? secretField("session-cookie", "Session cookie", "cookie", "session=…; csrftoken=…",
            "Sign in to the test account in your browser, open developer tools, pick any request to this site under Network, and copy the value of its Cookie header.")
          : secretField("session-header", "Header", "header", "Authorization: Bearer eyJ…",
            "For APIs and single-page apps: copy the Authorization header (or the API key header) from a request the app makes while signed in."),
        h("div", { class: "field" }, h("label", { for: "signed-in-text", text: "Text only a signed-in user sees (recommended)" }), markerInput,
          h("span", { class: "hint", text: "Rift uses it to confirm the login worked, and to catch pages that show this account's data to anyone." })),
        h("div", { class: "small muted", text: "Use a test account, never a real customer's. The session is sent only to the hosts you are scanning, kept in memory, and never written to a report. While signed in, links that look like actions (sign out, delete, approve, archive and similar) are not opened." }));
    }

    var checkGrid = h("div", { class: "checks" }, meta.checks.map(function (check) {
      return h("label", { class: "check" },
        h("input", { type: "checkbox", checked: chosen.indexOf(check.id) !== -1, onchange: function (event) {
          var next = selectedChecks().filter(function (id) { return id !== check.id; });
          if (event.target.checked) next.push(check.id);
          form.checks = next;
          refreshStart();
        } }),
        h("span", { class: "check-text" },
          h("span", { class: "check-title" }, check.title, h("span", { class: "kind", text: check.kind })),
          h("span", { class: "check-sum", text: check.summary })));
    }));

    function numberField(label, key, fallback, min, max, step) {
      return h("label", { class: "field" }, label,
        h("input", { class: "input", type: "number", min: min, max: max, step: step, value: form[key] || fallback,
          oninput: function (event) { form[key] = event.target.value; } }));
    }

    show(
      header("New scan", h("div", { class: "muted", text: "Check a website or API you own, or have written permission to test." })),
      h("div", { class: "row" },
        h("div", { class: "col-main" },
          h("section", { class: "panel pad" },
            h("div", { class: "between" },
              h("label", { class: "step", for: "targets", text: "1. Targets" }),
              h("button", { type: "button", class: "btn sm", text: "Load a .txt file", onclick: function () { fileInput.click(); } })),
            textarea, fileInput,
            h("div", { class: "small muted", text: "One URL per line. Rift also reads a few pages and scripts each one links to on the same site." })),
          h("section", { class: "panel pad" },
            h("div", { class: "step", text: "2. Depth" }),
            h("div", { class: "depth", role: "radiogroup", "aria-label": "Scan depth" },
              depthOption("fast", "Fast", "Each URL, up to 4 linked pages and 8 scripts. The most common exposed paths."),
              depthOption("deep", "Deep", "Up to 12 linked pages and 20 scripts. The full path list and redirect payload catalogue."))),
          h("section", { class: "panel pad" },
            h("div", { class: "step", text: "3. Sign in (optional)" }),
            h("div", { class: "depth three", role: "radiogroup", "aria-label": "Login" },
              authOption("none", "Not signed in", "What anyone on the internet can see."),
              authOption("cookie", "Session cookie", "For most web apps. Paste a test account's cookie."),
              authOption("header", "Header or token", "For APIs: a bearer token or API key header.")),
            authFields),
          h("section", { class: "panel pad" },
            h("div", { class: "between" },
              h("div", { class: "step" }, "4. Checks", countLabel),
              h("div", { class: "actions" },
                h("button", { type: "button", class: "btn sm", text: "Select all", onclick: function () { setChecks(null); } }),
                h("button", { type: "button", class: "btn sm", text: "Passive only", onclick: function () {
                  setChecks(meta.checks.filter(function (item) { return item.kind === "passive"; }).map(function (item) { return item.id; }));
                } }))),
            checkGrid,
            h("div", { class: "small muted", text: "Passive checks read pages already fetched. Probe checks send a few extra read-only requests." }))),
        h("aside", { class: "panel side-panel col-side", "aria-label": "Scope and start" },
          h("div", { class: "step", text: "5. Confirm scope" }),
          h("div", { class: "label", text: "Domains this scan may contact" }),
          scopeBox,
          h("div", { class: "grid2" },
            numberField("Requests per domain", "limit", meta.defaults.max_requests_per_domain, 20, 5000, 10),
            numberField("Seconds between requests", "pace", meta.defaults.min_interval_seconds, 0.05, 5, 0.05),
            numberField("Timeout, seconds", "timeout", meta.defaults.timeout_seconds, 2, 30, 1),
            h("div", { class: "field" }, "Methods", h("div", { class: "fact-v", text: "GET, HEAD, OPTIONS" }))),
          h("div", { class: "small muted", text: form.auth === "none"
            ? "No cookies or credentials are sent. Never requested: private and cloud-metadata addresses, and logout, delete, payment or trading paths."
            : "The test account's session is sent only to the hosts above. Never requested: private and cloud-metadata addresses, and links that look like actions." }),
          h("label", { class: "confirm" },
            h("input", { type: "checkbox", checked: form.authorised, onchange: function (event) { form.authorised = event.target.checked; refreshStart(); } }),
            h("span", { text: meta.statement })),
          startButton,
          h("div", { class: "small muted", text: "The confirmation, the time and the domain list are written into every report." }))));

    drawScope();
    if (form.targets && !form.preview) requestPreview();
  }

  // ---- one scan --------------------------------------------------------------

  function openScan(id) {
    setNav("scan");
    stopPolling();
    var token = ++renderToken;
    if (id === "latest") {
      api("GET", "/api/scans").then(function (data) {
        if (token !== renderToken) return;
        if (data.scans.length) location.replace("#/scan/" + data.scans[0].id);
        else show(header("Findings"), h("div", { class: "panel empty" }, "No scans yet. ", h("a", { href: "#/new", text: "Start your first scan" }), "."));
      }, fail);
      return;
    }
    if (ui.scanId !== id) ui = { scanId: id, severity: "all", check: "all", query: "", selected: null };
    load();

    function load() {
      api("GET", "/api/scans/" + encodeURIComponent(id)).then(function (scan) {
        if (token !== renderToken) return;
        if (scan.state === "running" || scan.state === "paused") {
          renderRunning(scan);
          pollTimer = setTimeout(load, 1000);
        } else {
          renderResults(scan);
        }
      }, function (error) {
        if (token !== renderToken) return;
        show(header("Scan not found"), h("div", { class: "panel empty" }, error.message + " ", h("a", { href: "#/scans", text: "Back to scan history" })));
      });
    }
  }

  function control(scan, action) {
    api("POST", "/api/scans/" + scan.id + "/" + action).then(function () {
      if (action === "cancel") toast("Cancelling. Findings so far are kept.");
    }, fail);
  }

  function crumb(scan) {
    return h("div", { class: "crumb" },
      h("span", { class: "state " + scan.state, text: scan.state === "running" ? "Scanning" : scan.state.charAt(0).toUpperCase() + scan.state.slice(1) }),
      h("span", { text: (scan.mode === "deep" ? "Deep" : "Fast") + " scan · " + when(scan.created_at) }));
  }

  function renderRunning(scan) {
    var paused = scan.state === "paused";
    var serious = (scan.summary.critical || 0) + (scan.summary.high || 0);
    var fraction = Math.min(0.97, scan.progress.total ? scan.progress.done / scan.progress.total : 0);
    var progress = h("div", { class: "progress", role: "progressbar", "aria-label": "Scan progress", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": Math.round(fraction * 100) }, h("div"));
    progress.firstChild.style.width = Math.max(2, Math.round(fraction * 100)) + "%";
    var log = h("div", { class: "log" }, scan.logs.slice().reverse().map(function (line) {
      return h("div", null, h("time", { text: line.at }), line.text);
    }));
    show(
      header(targetLabel(scan), crumb(scan), [
        h("button", { type: "button", class: "btn", text: paused ? "Resume" : "Pause", onclick: function () { control(scan, paused ? "resume" : "pause"); } }),
        h("button", { type: "button", class: "btn danger", text: "Cancel scan", onclick: function () { control(scan, "cancel"); } })
      ], true),
      h("section", { class: "panel pad", "aria-label": "Progress" },
        h("div", { class: "between" },
          h("div", { class: "fact-v", text: paused ? "Paused" : "Working" }),
          h("div", { class: "muted", text: Math.round(scan.duration_seconds) + " s elapsed" })),
        progress,
        h("div", { class: "mono small wrap-any", text: scan.progress.detail }),
        h("div", { class: "tiles" },
          h("div", { class: "tile" }, h("div", { class: "tile-k", text: "Findings so far" }), h("div", { class: "tile-v", text: scan.summary.total })),
          h("div", { class: "tile" + (serious ? " alert" : "") }, h("div", { class: "tile-k", text: "Critical or high" }), h("div", { class: "tile-v", text: serious })),
          h("div", { class: "tile" }, h("div", { class: "tile-k", text: "Checks selected" }), h("div", { class: "tile-v", text: scan.checks.length })),
          h("div", { class: "tile" }, h("div", { class: "tile-k", text: "Targets" }), h("div", { class: "tile-v", text: scan.targets.length })))),
      h("div", { class: "row" },
        h("section", { class: "panel col-main", "aria-label": "Findings so far" },
          h("div", { class: "panel-head" }, "Findings so far ", h("span", { class: "muted", text: "· most severe first" })),
          scan.findings.length ? scan.findings.slice(0, 40).map(function (item) {
            return h("div", { class: "finding static" }, pill(item.severity),
              h("span", { class: "finding-text" }, h("span", { class: "finding-title", text: item.title })),
              h("span", { class: "finding-check", text: checkTitle(item.check) }));
          }) : h("div", { class: "empty", text: "Nothing yet." }),
          h("div", { class: "panel-foot", text: "Findings appear as each check finishes. Cancel keeps everything found so far." })),
        h("section", { class: "panel col-side", "aria-label": "Activity" },
          h("div", { class: "panel-head", text: "Activity" }), log)));
  }

  function exportReport(scan, kind) {
    fetch("/api/scans/" + scan.id + "/export/" + kind, { headers: { "X-Rift-Token": TOKEN }, cache: "no-store" }).then(function (response) {
      if (!response.ok) throw new Error("Export failed (" + response.status + ")");
      return response.blob();
    }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var link = h("a", { href: url, download: "rift-" + scan.id + "." + kind });
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    }).catch(fail);
  }

  function findingKey(item) { return item.check + "|" + item.title + "|" + item.url; }

  function findingText(item) {
    return [
      "[" + item.severity.toUpperCase() + "] " + item.title,
      "Where: " + item.url,
      [item.cwe, item.owasp].filter(Boolean).join(" · "),
      "",
      "What this means: " + item.explanation,
      "",
      "Evidence:",
      item.evidence,
      "",
      "How to fix it: " + item.remediation
    ].join("\n");
  }

  function renderResults(scan) {
    var summary = scan.summary;
    var serious = (summary.critical || 0) + (summary.high || 0);
    var listBox = h("div");
    var detailBox = h("aside", { class: "panel detail col-side", "aria-label": "Finding detail" });
    var chipBox = h("div", { class: "chips" });
    var footer = h("div", { class: "panel-foot" });

    function visible() {
      var query = ui.query.trim().toLowerCase();
      return scan.findings.filter(function (item) {
        if (ui.severity !== "all" && item.severity !== ui.severity) return false;
        if (ui.check !== "all" && item.check !== ui.check) return false;
        if (!query) return true;
        return (item.title + " " + item.url + " " + checkTitle(item.check) + " " + item.cwe).toLowerCase().indexOf(query) !== -1;
      });
    }

    function drawChips() {
      clear(chipBox);
      function chip(value, label) {
        return h("button", { type: "button", class: "chip", "aria-pressed": ui.severity === value ? "true" : "false", text: label,
          onclick: function () { ui.severity = value; drawChips(); drawList(); } });
      }
      chipBox.appendChild(chip("all", "All " + summary.total));
      SEVERITIES.forEach(function (name) {
        if (summary[name]) chipBox.appendChild(chip(name, name.charAt(0).toUpperCase() + name.slice(1) + " " + summary[name]));
      });
    }

    function drawDetail(item) {
      clear(detailBox);
      if (!item) {
        detailBox.appendChild(h("div", { class: "empty", text: scan.findings.length ? "Select a finding to see the evidence and the fix." : "Nothing to show." }));
        return;
      }
      append(detailBox, [
        h("div", { class: "tags" }, pill(item.severity), h("span", { class: "muted small", text: checkTitle(item.check) })),
        h("h2", { text: item.title }),
        h("div", { class: "tags" },
          item.cwe ? h("span", { class: "tag", text: item.cwe }) : null,
          item.owasp ? h("span", { class: "tag", text: item.owasp }) : null,
          h("span", { class: "tag", text: "Confidence " + item.confidence })),
        h("section", null, h("h3", { class: "label", text: "What this means" }), h("p", { text: item.explanation })),
        h("section", null, h("h3", { class: "label", text: "Where" }), h("div", { class: "code", text: item.url })),
        h("section", null, h("h3", { class: "label", text: "Evidence" }), h("pre", { class: "code", text: item.evidence || "—" }),
          h("div", { class: "small muted", text: "Secrets are shown shortened. File contents and field values are never stored." })),
        h("section", { class: "fix" }, h("h3", { class: "label", text: "How to fix it" }), h("p", { text: item.remediation })),
        item.affected_urls && item.affected_urls.length > 1 ? h("section", null,
          h("h3", { class: "label", text: "Affected pages (" + item.affected_urls.length + ")" }),
          h("ul", { class: "urls" }, item.affected_urls.slice(0, 100).map(function (url) { return h("li", { text: url }); }))) : null,
        item.reference ? h("div", { class: "small muted wrap-any", text: "Reference: " + item.reference }) : null,
        h("div", { class: "actions" },
          h("button", { type: "button", class: "btn", text: "Copy finding", onclick: function () { copy(findingText(item), "Finding"); } }),
          h("button", { type: "button", class: "btn", text: "Copy fix", onclick: function () { copy(item.remediation, "Fix"); } }))
      ]);
    }

    function drawList() {
      var items = visible();
      clear(listBox);
      if (!items.length) {
        listBox.appendChild(h("div", { class: "empty", text: scan.findings.length ? "No findings match these filters." : "No findings from the selected checks." }));
      }
      var selected = items.filter(function (item) { return findingKey(item) === ui.selected; })[0] || items[0] || null;
      ui.selected = selected ? findingKey(selected) : null;
      items.forEach(function (item) {
        listBox.appendChild(h("button", { type: "button", class: "finding", "aria-pressed": item === selected ? "true" : "false",
          onclick: function () { ui.selected = findingKey(item); drawList(); } },
          pill(item.severity),
          h("span", { class: "finding-text" },
            h("span", { class: "finding-title", text: item.title }),
            h("span", { class: "finding-path", text: (scan.domains.length > 1 ? item.domain + " " : "") + pathOf(item.url) })),
          h("span", { class: "finding-check", text: checkTitle(item.check) })));
      });
      footer.textContent = "Showing " + items.length + " of " + scan.findings.length + ", most severe first. One finding per issue per site; an issue on many pages is listed once with every affected page.";
      drawDetail(selected);
    }

    var checksPresent = [];
    scan.findings.forEach(function (item) { if (checksPresent.indexOf(item.check) === -1) checksPresent.push(item.check); });
    var checkSelect = h("select", { class: "select", "aria-label": "Filter by check", onchange: function (event) { ui.check = event.target.value; drawList(); } },
      h("option", { value: "all", text: "All checks" }),
      checksPresent.map(function (id) { return h("option", { value: id, text: checkTitle(id) }); }));
    checkSelect.value = ui.check;
    var searchInput = h("input", { id: "finding-search", class: "input", type: "search", placeholder: "Title, check or URL",
      oninput: function (event) { ui.query = event.target.value; drawList(); } });
    searchInput.value = ui.query;

    var session = scan.session;
    var banner = null;
    if (session && session.status === "rejected") banner = h("div", { class: "panel pad sev-medium", text: "The signed-in text was not found on any page, so the session probably did not work (expired, or the wrong cookie). Signed-in results are incomplete: sign in again, copy a fresh session and scan again." });
    if (session && session.status === "unconfirmed") banner = h("div", { class: "panel pad sev-medium", text: "Rift could not confirm the session worked: no page it read needed a login. If the app is built with JavaScript (React, Vue and similar), its data comes from an API: add the API's address as a target. Otherwise add a page that needs signing in (such as /account), fill in the signed-in text, and scan again." });
    if (session && session.status === "api-missing") {
      var missing = session.hosts_missing || [];
      banner = h("div", { class: "panel pad sev-medium" },
        h("p", { text: "This app loads its data from " + missing.join(", ") + ", which was not part of this scan, so your session was never sent there and the signed-in results are incomplete. Scan again with " + (missing.length > 1 ? "those hosts" : "that host") + " added. You will need to paste the session again." }),
        h("div", { class: "actions" },
          h("button", { type: "button", class: "btn primary", text: "Scan again with " + (missing.length > 1 ? "the API hosts" : missing[0]) + " added", onclick: function () {
            var targets = scan.targets.slice();
            missing.forEach(function (host) { var url = "https://" + host + "/"; if (targets.indexOf(url) < 0) targets.push(url); });
            form.targets = targets.join("\n"); form.mode = scan.mode; form.checks = scan.checks.slice(); form.preview = null; form.authorised = false;
            form.auth = session.method === "cookie" ? "cookie" : "header";
            location.hash = "#/new";
          } })));
    }
    if (scan.state === "cancelled") banner = h("div", { class: "panel pad sev-medium", text: "This scan was cancelled before it finished. The results below are partial." });
    if (scan.state === "failed") banner = h("div", { class: "panel pad sev-critical", text: "The scan stopped on an error: " + scan.error });

    var extras = [];
    var signOut = session ? signOutPanel(scan) : null;
    if (scan.notes.length) {
      extras.push(h("details", { class: "panel" },
        h("summary", { text: "Checks that were skipped or limited (" + scan.notes.length + ")" }),
        h("div", { class: "inner" }, scan.notes.map(function (note) {
          return h("div", { class: "note wrap-any" }, h("b", { text: checkTitle(note.check) }), " · ", h("span", { class: "mono small", text: note.url }), h("div", { class: "muted", text: note.detail }));
        }))));
    }
    var skipped = (session && session.skipped_addresses) || [];
    if (skipped.length) {
      extras.push(h("details", { class: "panel" },
        h("summary", { text: "Addresses not opened while signed in (" + skipped.length + ")" }),
        h("div", { class: "inner" },
          h("p", { class: "muted", text: "Rift found these in the app's JavaScript but did not send your session to them, because opening them could change data, send something, or start a sign-in step. Check them by hand if they matter." }),
          skipped.map(function (item) {
            return h("div", { class: "note wrap-any" }, h("span", { class: "mono small", text: item.url }), h("div", { class: "muted", text: "Skipped: " + item.reason }));
          }))));
    }
    extras.push(h("details", { class: "panel" },
      h("summary", { text: "What was read (" + plural(scan.pages.length, "page") + ", " + plural(scan.scripts.length, "script") + ")" }),
      h("div", { class: "inner" }, h("pre", { class: "code", text: scan.pages.concat(scan.scripts).join("\n") || "Nothing" }))));

    show(
      header(targetLabel(scan), crumb(scan), [
        h("button", { type: "button", class: "btn", text: "Export HTML", disabled: scan.state === "failed", onclick: function () { exportReport(scan, "html"); } }),
        h("button", { type: "button", class: "btn", text: "JSON", disabled: scan.state === "failed", onclick: function () { exportReport(scan, "json"); } }),
        h("button", { type: "button", class: "btn", text: "CSV", disabled: scan.state === "failed", onclick: function () { exportReport(scan, "csv"); } }),
        h("button", { type: "button", class: "btn", text: "SARIF", disabled: scan.state === "failed", onclick: function () { exportReport(scan, "sarif"); } }),
        h("button", { type: "button", class: "btn primary", text: "Scan again", onclick: function () {
          form.targets = scan.targets.join("\n"); form.mode = scan.mode; form.checks = scan.checks.slice(); form.preview = null; form.authorised = false;
          location.hash = "#/new";
        } })
      ], true),
      banner,
      h("section", { class: "summary", "aria-label": "Summary" },
        h("div", { class: "panel grade-card" },
          h("div", { class: "grade grade-" + scan.grade, text: scan.grade }),
          h("div", null, h("div", { class: "fact-k", text: "Grade" }), h("div", { class: "score", text: scan.score + " / 100" }))),
        h("div", { class: "panel dist-card" },
          h("div", { class: "between small muted" },
            h("span", { text: plural(summary.total, "finding") + " by severity" }),
            h("span", { text: serious ? serious + " need action now" : "No critical or high findings" })),
          bar(summary, false),
          h("div", { class: "legend" }, SEVERITIES.map(function (name) {
            return h("div", null, h("b", { class: "ink-" + name, text: summary[name] || 0 }), " " + name);
          }))),
        h("div", { class: "panel facts" },
          h("div", null, h("div", { class: "fact-k", text: "Depth" }), h("div", { class: "fact-v", text: scan.mode === "deep" ? "Deep scan" : "Fast scan" })),
          h("div", null, h("div", { class: "fact-k", text: "Checks run" }), h("div", { class: "fact-v", text: scan.checks.length + " of " + meta.checks.length })),
          h("div", null, h("div", { class: "fact-k", text: "Requests" }), h("div", { class: "fact-v", text: scan.requests_sent })),
          h("div", null, h("div", { class: "fact-k", text: "Duration" }), h("div", { class: "fact-v", text: Math.round(scan.duration_seconds) + " s" })),
          h("div", null, h("div", { class: "fact-k", text: "Login" }), h("div", { class: "fact-v", text: session ? "Test account" : "Not signed in" })),
          session ? h("div", null, h("div", { class: "fact-k", text: "Private pages" }), h("div", { class: "fact-v", text: session.private_pages || 0 })) : null,
          session && session.script_addresses ? h("div", null, h("div", { class: "fact-k", text: "API addresses from scripts" }), h("div", { class: "fact-v", text: (session.script_answers || 0) + " of " + session.script_addresses + " answered" })) : null)),
      signOut,
      h("div", { class: "row" },
        h("section", { class: "panel col-main", "aria-label": "Findings" },
          h("div", { class: "filters" }, chipBox, checkSelect,
            h("div", { class: "search" }, h("label", { class: "small muted", for: "finding-search", text: "Search" }), searchInput)),
          listBox, footer),
        detailBox),
      extras,
      h("div", { class: "small muted", text: "A clean result means these checks found nothing. It is not proof that a site is secure. The grade is a summary aid: any critical finding is an F, and any high finding caps it at C." }));

    drawChips();
    drawList();
  }

  function signOutPanel(scan) {
    var ended = scan.session.session_end;
    if (!ended && !scan.session_check_open) return null;
    var panel = h("section", { class: "panel pad", "aria-label": "Sign-out check" },
      h("div", { class: "between" },
        h("h2", { class: "step", text: "Does signing out end the session?" }),
        ended ? h("span", { class: "pill sev-" + (ended.result === "passed" ? "info" : ended.result === "failed" ? "high" : "medium"),
          text: ended.result === "passed" ? "passed" : ended.result === "failed" ? "failed" : "unclear" }) : null));
    if (ended) panel.appendChild(h("p", { class: "muted", text: ended.detail }));
    if (scan.session_check_open) {
      var button = h("button", { type: "button", class: "btn primary", text: ended ? "Check again" : "I signed out, check now", onclick: function () {
        button.disabled = true;
        api("POST", "/api/scans/" + scan.id + "/session-end").then(function (data) {
          toast(data.detail, data.result === "failed");
          renderResults(data.scan);
        }, function (error) { button.disabled = false; fail(error); });
      } });
      append(panel, [
        h("ol", { class: "steps" },
          h("li", { text: "In your browser, sign out of the test account with the app's own Sign out button." }),
          h("li", { text: "Come back here and press the button. Rift sends one request to a private page with the old session." })),
        h("div", { class: "actions" }, button,
          h("span", { class: "small muted", text: "If the old session still works, anyone who copied it stays signed in. Available for an hour after the scan." }))
      ]);
    }
    return panel;
  }

  // ---- history and catalogue -------------------------------------------------

  function renderHistory() {
    setNav("scans");
    stopPolling();
    var token = ++renderToken;
    api("GET", "/api/scans").then(function (data) {
      if (token !== renderToken) return;
      var head = header("Scan history",
        h("div", { class: "muted", text: "Saved on this machine. Reports hold shortened evidence only, never raw secrets." }),
        h("a", { class: "btn primary", href: "#/new", text: "New scan" }));
      if (!data.scans.length) {
        show(head, h("div", { class: "panel empty" }, "No scans yet. ", h("a", { href: "#/new", text: "Start your first scan" }), "."));
        return;
      }
      var rows = data.scans.map(function (scan) {
        var active = scan.state === "running" || scan.state === "paused";
        var serious = [];
        if (scan.summary.critical) serious.push(h("b", { class: "ink-critical", text: scan.summary.critical + " critical" }));
        if (scan.summary.high) serious.push(h("b", { class: "ink-high", text: scan.summary.high + " high" }));
        var other = scan.summary.total - (scan.summary.critical || 0) - (scan.summary.high || 0);
        var line = h("div", { class: "small" });
        serious.forEach(function (node, index) { if (index) line.appendChild(document.createTextNode(" · ")); line.appendChild(node); });
        line.appendChild(document.createTextNode((serious.length ? " · " : "") + other + " other"));
        return h("tr", null,
          h("td", null, active ? h("span", { class: "state " + scan.state, text: scan.state }) : h("span", { class: "grade sm grade-" + scan.grade, text: scan.grade })),
          h("td", null, h("a", { class: "target-link", href: "#/scan/" + scan.id, text: targetLabel(scan) }),
            h("div", { class: "small muted", text: plural(scan.targets.length, "URL") + " · " + plural(scan.checks.length, "check") + (scan.signed_in ? " · signed in" : "") + (scan.state === "cancelled" ? " · cancelled" : scan.state === "failed" ? " · failed" : "") })),
          h("td", null, bar(scan.summary, true), line),
          h("td", { text: scan.mode === "deep" ? "Deep" : "Fast" }),
          h("td", { text: scan.requests_sent || "—" }),
          h("td", null, when(scan.created_at), h("div", { class: "small muted", text: Math.round(scan.duration_seconds) + " s" })),
          h("td", { class: "right" },
            h("a", { class: "btn sm", href: "#/scan/" + scan.id, text: "Open" }),
            h("button", { type: "button", class: "btn sm ghost", text: "Delete", disabled: active, onclick: function () {
              if (!window.confirm("Delete this scan and its saved report?")) return;
              api("DELETE", "/api/scans/" + scan.id).then(renderHistory, fail);
            } })));
      });
      show(head, h("section", { class: "panel table-box", "aria-label": "Scans" },
        h("table", null,
          h("thead", null, h("tr", null,
            h("th", { scope: "col", text: "Grade" }), h("th", { scope: "col", text: "Target" }), h("th", { scope: "col", text: "Findings" }),
            h("th", { scope: "col", text: "Depth" }), h("th", { scope: "col", text: "Requests" }), h("th", { scope: "col", text: "When" }),
            h("th", { scope: "col" }, h("span", { class: "visually-hidden", text: "Actions" })))),
          h("tbody", null, rows))));
    }, fail);
  }

  function renderChecks() {
    setNav("checks");
    stopPolling();
    ++renderToken;
    show(
      header("Check catalogue", h("div", { class: "muted", text: meta.checks.length + " checks. Every finding carries a CWE and an OWASP Top 10 or OWASP API Top 10 category." })),
      h("section", { class: "panel pad" },
        h("div", { class: "checks" }, meta.checks.map(function (check) {
          return h("div", { class: "check" }, h("span", { class: "check-text" },
            h("span", { class: "check-title" }, check.title, h("span", { class: "kind", text: check.kind })),
            h("span", { class: "check-sum", text: check.summary }),
            h("span", { class: "mono small muted", text: check.id })));
        })),
        h("div", { class: "small muted", text: "Passive checks read pages already fetched. Probe checks send a few extra read-only requests." })),
      h("section", { class: "panel pad" },
        h("h2", { class: "step", text: "What Rift does not do" }),
        h("p", { class: "muted", text: "It never logs in by itself, submits forms, or sends requests that change data. Given a test account's session, it also reads the signed-in part of the app. It does not yet compare two accounts (one user reading another user's data), and it does no injection testing, brute force, or anything that executes JavaScript. Use it alongside a penetration test, not instead of one." })));
  }

  // ---- routing ---------------------------------------------------------------

  function route() {
    var hash = location.hash.replace(/^#\/?/, "");
    var parts = hash.split("/");
    toastBox.hidden = true;
    if (parts[0] === "scan" && parts[1]) openScan(parts[1]);
    else if (parts[0] === "scans") renderHistory();
    else if (parts[0] === "checks") renderChecks();
    else { ++renderToken; renderNew(); }
    view.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }

  api("GET", "/api/meta").then(function (data) {
    meta = data;
    document.getElementById("version").textContent = data.version;
    document.getElementById("lab").hidden = !data.lab_mode;
    document.title = data.name;
    window.addEventListener("hashchange", route);
    route();
  }, function (error) {
    show(h("div", { class: "panel empty", text: "The console could not start: " + error.message }));
  });
})();
