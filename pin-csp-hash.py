#!/usr/bin/env python3
"""Pin (or check) the Content-Security-Policy script hash in oneshot-secops tool files.

Each tool is a single HTML file whose CSP allows exactly one inline script, identified by its SHA-256.
Any edit to that script changes the hash, and the browser will refuse to run the page until the CSP is updated.

  python3 tools/pin-csp-hash.py fortigate-log-triage.html web-log-triage.html          # update in place
  python3 tools/pin-csp-hash.py --check fortigate-log-triage.html web-log-triage.html  # exit 1 if out of date
"""
import base64
import hashlib
import re
import sys

OPEN, CLOSE = '<scr' + 'ipt>', '</scr' + 'ipt>'   # split so this file never contains the literal tags
CSP_RE = re.compile(r"script-src 'sha256-[A-Za-z0-9+/=]+'")


def expected(html: str, path: str) -> str:
    if html.count(OPEN) != 1 or html.lower().count(CLOSE) != 1:
        sys.exit(f"{path}: expected exactly one inline script block")
    body = html.split(OPEN, 1)[1].split(CLOSE, 1)[0]
    return "sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()


def main(argv):
    check = "--check" in argv
    files = [a for a in argv if a != "--check"]
    if not files:
        sys.exit(__doc__)
    stale = False
    for path in files:
        with open(path, encoding="utf-8") as f:
            html = f.read()
        want = expected(html, path)
        found = CSP_RE.findall(html)
        if len(found) != 1:
            sys.exit(f"{path}: expected exactly one script-src sha256 entry in the CSP, found {len(found)}")
        current = found[0].split("'")[1]
        if current == want:
            print(f"{path}: OK {want}")
            continue
        if check:
            print(f"{path}: STALE (CSP has {current}, script is {want})")
            stale = True
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(CSP_RE.sub(f"script-src '{want}'", html))
        print(f"{path}: pinned {want}")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
