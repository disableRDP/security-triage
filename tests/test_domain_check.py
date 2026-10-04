#!/usr/bin/env python3
"""Offline tests for scripts/domain_check.py. No real network: feeds are tiny fixtures in the
real abuse.ch formats and RDAP is a local fake server. Hosts use the made-up TLD .zz.

usage: python tests/test_domain_check.py
"""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "scripts", "domain_check.py")
failures = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        failures.append(msg)


def write_feeds(d, age_days=0):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "urlhaus_hostfile.txt"), "w").write(
        "# abuse.ch URLhaus Host file\n127.0.0.1\tbad-host.zz\n127.0.0.1\tother-bad.zz\n")
    open(os.path.join(d, "urlhaus_online.txt"), "w").write(
        "http://45.33.32.156:8080/bin.sh\nhttps://raw.githubusercontent.com/evil/repo/main/x.sh\n")
    tf = {"1": [{"ioc_value": "sub.tf-bad.zz", "ioc_type": "domain", "threat_type": "payload_delivery",
                 "malware_printable": "ClearFake", "confidence_level": 90, "is_compromised": True}]}
    json.dump(tf, open(os.path.join(d, "threatfox_domains.json"), "w"))
    if age_days:
        t = time.time() - age_days * 86400
        for f in os.listdir(d):
            os.utime(os.path.join(d, f), (t, t))


def run(target, feeds, **env):
    out = os.path.join(tempfile.mkdtemp(), "out.json")
    e = dict(os.environ, TRIAGE_FEED_DIR=feeds)
    e.pop("TRIAGE_DOMAIN_LOOKUP", None)
    e.update({k: str(v) for k, v in env.items()})
    p = subprocess.run([sys.executable, TOOL, target, out], capture_output=True, text=True, env=e)
    if p.returncode != 0:
        print(p.stderr)
    return json.load(open(out)) if os.path.exists(out) else None


def kinds(r):
    return sorted((f["kind"], f["host"]) for f in r["findings"])


# ---- target with matches and decoys
target = tempfile.mkdtemp()
os.makedirs(os.path.join(target, "src"))
open(os.path.join(target, "src", "a.py"), "w").write("\n".join([
    'A = "http://bad-host.zz/payload"',
    'B = "http://45.33.32.156:8080/bin.sh"',
    'C = "http://45.33.32.156:9999/other"',
    'D = "https://sub.tf-bad.zz/a"',
    'E = "https://x.sub.tf-bad.zz/a"',
    'F = "https://tf-bad.zz/parent-only"',
    'G = "http://github.com@other-bad.zz/x"',
    'H = "http://bad-host.zz@github.com/x"',
    'I = "https://raw.githubusercontent.com/evil/repo/main/x.sh"',
    'J = "https://raw.githubusercontent.com/good/repo/main/x.sh"',
    'K = ["http://localhost/", "http://127.0.0.1/", "http://10.1.1.1/", "https://example.com/", "http://${HOST}/x", "https://svc.internal/x"]',
]) + "\n")
open(os.path.join(target, "src", "blob.bin"), "wb").write(bytes([0, 1]) + b"http://bad-host.zz")

# 1. no feeds, no opt-in: skipped, and says so (never a silent clean)
r = run(target, tempfile.mkdtemp())
check(r and r["status"] == "skipped" and "NOT checked" in r["detail"], "no feeds -> skipped with an explanation")

# 2. matches and decoys
feeds = os.path.join(tempfile.mkdtemp(), "feeds")
write_feeds(feeds)
r = run(target, feeds)
got = kinds(r)
check(("known-bad-host", "bad-host.zz") in got, "URLhaus host matched")
check(("known-bad-url", "45.33.32.156") in got, "exact URLhaus URL matched")
check(("known-bad-ip", "45.33.32.156") in got, "IP literal matched at host level")
check(("known-bad-host", "sub.tf-bad.zz") in got and ("known-bad-host", "x.sub.tf-bad.zz") in got, "ThreatFox IOC and its subdomain matched")
check(not any(h == "tf-bad.zz" for _, h in got), "parent of a listed subdomain is NOT a match")
check(("known-bad-host", "other-bad.zz") in got, "'github.com@other-bad.zz' resolves to the bad host (userinfo trick)")
check(not any(h == "github.com" for _, h in got), "'bad-host.zz@github.com' is github.com, not a match")
check(("known-bad-url", "raw.githubusercontent.com") in got and sum(1 for k, h in got if h == "raw.githubusercontent.com") == 1,
      "a listed raw.githubusercontent.com URL matches only by exact URL, not the whole host")
tfx = [f for f in r["findings"] if f["source"] == "threatfox"][0]
check("COMPROMISED" in tfx["detail"] and "ClearFake" in tfx["detail"], "ThreatFox finding says the site is compromised and names the malware")
check(r["status"] == "ran", f"fresh complete feeds, no gaps -> ran (got {r['status']}: {r['detail'][:120]})")
check(not any(h in ("localhost", "127.0.0.1", "10.1.1.1", "example.com", "svc.internal") for _, h in got)
      and not any("$" in d for d in r["domains"]), "placeholders, loopback, private and reserved hosts ignored")
check(all(f["refs"] for f in r["findings"]) and r["findings"][0]["refs"][0].startswith("src/a.py:"), "findings carry file:line references")

# 3. stale feed -> partial; missing feed -> partial
stale = os.path.join(tempfile.mkdtemp(), "feeds"); write_feeds(stale, age_days=30)
r = run(target, stale)
check(r["status"] == "partial" and "days old" in r["detail"], "stale feed -> partial, with the age stated")
os.remove(os.path.join(feeds, "threatfox_domains.json"))
r = run(target, feeds)
check(r["status"] == "partial" and "threatfox_domains.json missing" in r["detail"], "one feed missing -> partial (the others still match)")
check(("known-bad-host", "bad-host.zz") in kinds(r), "remaining feeds still match when one is missing")
write_feeds(feeds)

# 4. RDAP age lookups against a local fake registry
old = (datetime.now(timezone.utc) - timedelta(days=4000)).strftime("%Y-%m-%dT%H:%M:%SZ")
new = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
RECORDS = {"newbie-fixture.zz": new, "veteran-fixture.zz": old}
hits = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.rsplit("/", 1)[-1]
        hits.append(name)
        if name in RECORDS:
            body = json.dumps({"events": [{"eventAction": "registration", "eventDate": RECORDS[name]}]}).encode()
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_address[1]}"
t2 = tempfile.mkdtemp()
open(os.path.join(t2, "x.js"), "w").write("\n".join([
    'fetch("https://newbie-fixture.zz/a")', 'fetch("https://www.veteran-fixture.zz/b")',
    'fetch("https://ghost-fixture.zz/c")', 'fetch("https://someone.github.io/d")',
    'fetch("https://api.github.com/e")', 'fetch("https://1.2.3.4/f")']) + "\n")
feeds2 = os.path.join(tempfile.mkdtemp(), "feeds"); write_feeds(feeds2)
r = run(t2, feeds2, TRIAGE_DOMAIN_LOOKUP=1, TRIAGE_RDAP_BASE=base)
# TRIAGE_DOMAIN_LOOKUP=1 would also refresh the (fresh) feeds: they are fresh, so no network is touched.
got = kinds(r)
check(("newly-registered", "newbie-fixture.zz") in got, "domain registered 2 days ago flagged newly-registered")
check(not any(h == "veteran-fixture.zz" or h.endswith(".veteran-fixture.zz") for _, h in got), "old domain not flagged")
check("github.io" not in " ".join(hits) and "github.com" not in " ".join(hits) and "1.2.3.4" not in hits,
      f"shared-hosting, well-known and IP hosts are never sent to RDAP (queried: {hits})")
check("www.veteran-fixture.zz" not in hits and "veteran-fixture.zz" in hits, "the registrable domain is queried, not the subdomain")
check(r["status"] == "partial" and "ghost-fixture.zz" not in r["detail"] and "HTTP 404" in r["detail"], "RDAP 404 reported as a coverage gap (not clean)")
check("age not evaluable for" in r["detail"] and "shared-hosting" in r["detail"], "unevaluable hosts are counted in the detail")
hits.clear()
r = run(t2, feeds2, TRIAGE_DOMAIN_LOOKUP=1, TRIAGE_RDAP_BASE=base, TRIAGE_DOMAIN_MAX=1, TRIAGE_FEED_DIR=tempfile.mkdtemp())
check(r["status"] in ("skipped", "partial"), "lookup cap run completes")
r = run(t2, feeds2, TRIAGE_DOMAIN_LOOKUP=1, TRIAGE_RDAP_BASE=base, TRIAGE_DOMAIN_MAX=1)
check(len(set(hits)) <= 2 and "not queried (limit 1" in r["detail"] and r["status"] == "partial", "TRIAGE_DOMAIN_MAX caps lookups and reports the rest as a gap")
# without the opt-in nothing is queried
hits.clear()
r = run(t2, feeds2, TRIAGE_RDAP_BASE=base)
check(not hits and "age lookup off" in r["detail"], "no RDAP query without TRIAGE_DOMAIN_LOOKUP=1")
srv.shutdown()

# 5. robustness: a huge single line, weird bytes, deep tree
t3 = tempfile.mkdtemp()
open(os.path.join(t3, "min.js"), "w").write('x="' + "http://a.b.c/" * 20000 + '"')
open(os.path.join(t3, "weird.txt"), "wb").write(b"http://" + bytes(range(1, 256)) + b" https://" + b"a" * 5000 + b".com/")
t0 = time.time()
r = run(t3, feeds2)
check(r is not None and time.time() - t0 < 20, "hostile line shapes finish quickly without crashing")

print("\nFAILED: %d" % len(failures) if failures else "\nall passed")
sys.exit(1 if failures else 0)
