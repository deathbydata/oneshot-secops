# oneshot-secops

Single-file, offline triage tools for the log files that land on a security analyst's desk with no SIEM attached: an export from a customer's firewall, a web server's access logs from a third party, a zip handed over at the start of an incident.

Each tool is one HTML file. Open it in a browser, drop the logs on it, and start asking questions. Nothing is installed, nothing is uploaded, and the page cannot make network requests.

| Tool | File | Version | For |
|---|---|---|---|
| FortiGate log triage | `fortigate-log-triage.html` | 1.4.2 | FortiGate traffic, UTM and event logs |
| Web access log triage | `web-log-triage.html` | 1.10.0 | Apache and nginx access logs |

The version and the fingerprint of the running script are shown under **About** in each tool, and recorded in every case summary it exports.

## Why

One-shot log analysis usually means one of two bad options: load customer data into a tool you don't control, or grep. These tools sit in between. They give you a timeline, filters, pivots and a set of first-look heuristics, while keeping the evidence on your machine and leaving a record of exactly what you looked at.

They are triage aids, not detection products. Every lead they raise is a question to verify against the logs.

## Quick start

1. Download the HTML file for the log type you have.
2. Open it in a current Chromium-based browser (Edge or Chrome) straight from disk.
3. Drag the log files onto the page, or use **Open log files**. Plain text and `.gz` are both fine.
4. Not sure where to start? **Load sample data** in either tool loads a synthetic dataset (documentation-range IP addresses only) with a short attack story in it.

Developed and tested in Chromium. Firefox and Safari have not been tested.

## What they do

Common to both tools:

- **Format detection per line**, so mixed files work, with a preview of any lines that were not recognised.
- **SHA-256 of every file as it loads**, computed in the page without holding the file in memory.
- **Timeline** with drag-to-select time ranges.
- **Filter language**: `field=value`, `!=`, `~contains`, `>`/`<`, comma lists, CIDR (`ip=10.0.0.0/8`), wildcards, free text. Click any value to filter to it; shift-click to exclude it.
- **Top values** per field, **heuristic leads** with a "look first / review" level, and an **events table** with resizable, movable columns, paging and a detail drawer.
- **Source cards** (firewalls or sites) with rename, show only, exclude and unload, each source addressable as `source=S1`.
- **Exports**: filtered CSV (formula-injection safe), plus a **Markdown case summary** containing file hashes, scope, active filters, unloaded sources, data-quality warnings, sources, leads and top flows or conversations.

### FortiGate log triage

- Reads FortiGate `key=value` (syslog or GUI download), FortiAnalyzer-style quoted CSV exports, and FortiGate CEF.
- Identifies the device model from the serial number, with inferred notes such as the FortiOS build from `logver`, FortiAnalyzer origin and VDOM layout. These are clearly labelled as inference.
- Leads include:
  - authentication failures followed by success
  - admin login failures and configuration changes
  - IPS and AV hits that were not blocked
  - port scans and internal host sweeps
  - inbound connections to published (DNAT) services
  - DMZ-to-internal traffic
  - high-risk applications allowed
  - large transfers to external addresses
- **Communication matrix**: unique flows per log source with sessions, bytes, first and last seen, and policy.

### Web access log triage

- Reads Apache and nginx Common and Combined formats, `vhost_combined`, syslog-prefixed lines and extra fields. An extra numeric field can be treated as response time; the tool shows which field and unit it assumed, and lets you change both.
- Checks every decoded URL for SQL injection, XSS, path traversal, system-file references, remote include and SSRF, command injection, Log4Shell, web shells, sensitive files and admin probes, plus attack-tool user agents and malformed, proxy or unusual-method requests.
- Every pattern match explains itself on hover: the text that matched, what the pattern looks for, why it may be harmless, and a reference (OWASP, MITRE ATT&CK, CISA).
- Leads include:
  - attack patterns that got a 2xx response
  - possible web shell use
  - repeated login attempts
  - scanning
  - parameter enumeration
  - request-rate peaks
  - server-error clusters
  - large and slow responses
  - user-agent anomalies
- **Conversations**: requests grouped into sessions per client, user agent and site, with a readable transcript for each.

Formats not supported yet: IIS / W3C extended, and JSON access logs. These lines are counted and reported, never silently dropped.

## Security model

These tools exist to handle untrusted, attacker-influenced data on an analyst's workstation, so the page is built to fail closed.

- **No network.** The Content-Security-Policy blocks all fetches, images, fonts and frames (`default-src 'none'`, `connect-src 'none'`). Reference links in explainers open an external page in a new tab only when you click them, and never carry log data.
- **One script, pinned by hash.** The CSP allows exactly one inline script, identified by its SHA-256. Injected scripts and inline event handlers are refused, and so is a modified copy of the file until its hash is updated. The same hash is shown under About and recorded in every case summary.
- **Untrusted text stays text.** Every value from a log is HTML-escaped before display. Invisible and direction-changing Unicode characters are shown as visible markers (`⟦U+202E⟧`), so one value cannot impersonate another.
- **Exports are defended too.** CSV cells that could run as spreadsheet formulas are neutralised. In the Markdown summary, log values are escaped and URLs defanged (`hxxps[://]`), so a summary pasted into a ticketing system cannot carry live HTML or links.
- **Hostile input is bounded.** Lines over 64 KB are skipped and flagged as corrupt or tampered. The parsers run in linear time. Lookup tables do not inherit built-in object properties.
- **No storage.** Nothing is written to browser storage. Names, filters and unloads last only for the session.

Known gaps:

- Inline styles are allowed (`style-src 'unsafe-inline'`) because the layout uses style attributes.
- Trusted Types is not used.
- The tools are only as safe as the browser running them.

The design has been reviewed and attacked with crafted payload files, but by its own authors. Independent review is welcome; see Reporting issues below.

## Limits worth knowing

- **Leads are heuristics.** No lead is not the same as no problem, and a lead is not a finding until you have verified it.
- **A 2xx response is not success.** Many applications answer 200 to anything. Compare response sizes and read what the client did next.
- **Access logs never contain request bodies.** Most form-based attacks, and the content of login attempts, are invisible to the web tool.
- **Proxies hide clients.** Behind a load balancer or CDN, the client field is the proxy, and per-client leads and conversations collapse. Check where the real client address is logged before trusting them.
- **Time zones.** Lines without a UTC offset are read as UTC and flagged. Confirm the device or server time zone before building a timeline.
- **Memory.** Everything is held in memory. A few hundred MB is fine in a desktop browser; beyond 1.5 million events or requests, the rest are counted and skipped.

## Handling evidence

- **Keep logs out of git.** Never commit log files, exports or case summaries to this or any repository. The included `.gitignore` covers the common names; it is a safety net, not a policy.
- **Treat summaries as evidence.** Case summaries and CSV exports contain the same customer data as the logs. Store them where the logs live.
- **Record hashes on receipt.** Hashes are computed over the bytes as loaded; for `.gz` files that is the compressed file. If a provider hashed the uncompressed log, the values will not match. Ask what they hashed before calling it a mismatch.
- **Unloading is not removal.** Unloading a source is recorded in the summary, but if a source must be out of scope for good, get the file re-exported without it, so the recorded hash matches what you analysed.

## Verifying your copy

Open **About** in the tool and note the script SHA-256. It must equal the hash pinned in the page's CSP:

```sh
python3 tools/pin-csp-hash.py --check fortigate-log-triage.html web-log-triage.html
```

Release notes should list the SHA-256 of each released HTML file, so a downloaded copy can be checked with `sha256sum` (Linux/macOS) or `Get-FileHash -Algorithm SHA256` (PowerShell).

## Changing the tools

Each file is self-contained: CSS, HTML and one script block. After editing the script:

1. Bump `TOOL_VERSION` and add a `CHANGELOG` entry; both sit at the top of the script.
2. Re-pin the CSP hash, or the page will refuse to run:

   ```sh
   python3 tools/pin-csp-hash.py fortigate-log-triage.html web-log-triage.html
   ```

3. Load the sample data in each tool and check there are no console errors or CSP violations.

A pre-commit hook that stops stale hashes reaching the repository (save as `.git/hooks/pre-commit` and make it executable):

```sh
#!/bin/sh
python3 tools/pin-csp-hash.py --check fortigate-log-triage.html web-log-triage.html || {
  echo "CSP script hash is out of date. Run: python3 tools/pin-csp-hash.py <file>"; exit 1; }
```

The two tools share a fair amount of code: hashing, escaping, the filter language, column handling and source controls. Until that is factored out, a fix to shared behaviour needs applying to both files.

## Repository layout

```
fortigate-log-triage.html   FortiGate log triage tool
web-log-triage.html         Web access log triage tool
tools/pin-csp-hash.py       Pins or checks the CSP script hash
.gitignore                  Keeps logs, exports and summaries out of git
README.md
```

## Reporting issues

Bugs and feature requests: open a GitHub issue. **Never attach real logs.** Reproduce with the sample data, or with a few lines rewritten to use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example` domains.

Security issues, such as a way to run script from a log file or to get data out of the page: report them privately through this repository's **Security** tab (Report a vulnerability), not in a public issue.

## Licence

No licence has been chosen yet. Until one is added, all rights are reserved by default.

## Disclaimer

Provided as is, without warranty. These tools support an analyst's judgement; they do not replace it, and they are not a substitute for a SIEM, EDR or a forensic process.
