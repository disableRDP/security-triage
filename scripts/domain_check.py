#!/usr/bin/env python3
"""Tier 5: domain reputation. Static lookup only: never contacts a domain found in the target.

usage: domain_check.py <target_dir> <out_json>

1. Extract every host referenced by a URL in the target's text files.
2. Match them against locally cached threat feeds (abuse.ch URLhaus + ThreatFox). Offline, private.
3. Only with TRIAGE_DOMAIN_LOOKUP=1: refresh stale/missing feeds and ask RDAP for the registration
   date of each registrable domain (newly registered = a weak signal). That tells the feed hosts
   and the registries which domains the target mentions, which is why it is opt-in.

Writes {"status", "detail", ...} to <out_json>; status is ran / partial / skipped, the same
vocabulary as every other tier. Silence never means clean: anything not checked is counted.

Env: TRIAGE_FEED_DIR (default ~/.cache/security-triage/feeds), TRIAGE_DOMAIN_LOOKUP=1,
     TRIAGE_FEED_MAX_AGE_DAYS (7), TRIAGE_DOMAIN_NEW_DAYS (30), TRIAGE_DOMAIN_MAX (40 RDAP
     lookups), TRIAGE_RDAP_BASE (https://rdap.org).
"""
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

FEEDS = {
    "urlhaus_hostfile.txt": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "urlhaus_online.txt": "https://urlhaus.abuse.ch/downloads/text_online/",
    "threatfox_domains.json": "https://threatfox.abuse.ch/export/json/domains/recent/",
}
MAX_FILE_BYTES = 5_000_000
MAX_FILES = 60_000
MAX_HOSTS = 5_000
MAX_REFS = 3
FEED_MAX_BYTES = 25_000_000

# Text before the host ends at whitespace, quotes, brackets and other characters that cannot be in one.
URL_RE = re.compile(r"""(?i)\b(?:https?|wss?|ftp)://([^\s/"'<>\\)\]}`,;|{$%*^]{1,255})""")
HOST_OK = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")
RESERVED_SUFFIX = (".localhost", ".test", ".invalid", ".example", ".local", ".internal", ".lan", ".home.arpa")
RESERVED_HOSTS = {"example.com", "example.org", "example.net", "localhost"}
# eTLD+1 an attacker cannot register: not worth an RDAP query.
WELL_KNOWN = {
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org", "npmjs.com", "npmjs.org",
    "pypi.org", "pythonhosted.org", "python.org", "nodejs.org", "rubygems.org", "crates.io", "golang.org",
    "go.dev", "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.net", "azure.com",
    "amazon.com", "amazonaws.com", "apple.com", "mozilla.org", "w3.org", "wikipedia.org", "anthropic.com",
    "openai.com", "docker.com", "docker.io", "mit.edu", "gnu.org", "apache.org", "readthedocs.io", "stackoverflow.com",
    "creativecommons.org", "schema.org", "json-schema.org", "mozilla.com", "ietf.org", "cloudflare.com",
    "shields.io", "twitter.com", "x.com", "linkedin.com", "youtube.com", "facebook.com", "reddit.com",
}
# Anyone can create a subdomain here, so the domain's age says nothing about the host. Feed matching still applies.
SHARED_HOSTING = (
    "github.io", "githubusercontent.com", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
    "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com", "onrender.com", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "loca.lt", "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blogspot.com",
    "glitch.me", "repl.co", "replit.app", "fly.dev", "railway.app", "surge.sh", "duckdns.org", "no-ip.org",
)
TWO_LEVEL_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp",
    "or.jp", "com.br", "com.cn", "com.hk", "com.sg", "com.tw", "com.mx", "co.in", "co.za", "co.kr", "com.tr",
    "com.ar", "com.ua", "com.my", "com.vn", "co.id", "com.ph", "com.pk", "co.il", "com.sa", "com.eg",
}


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def parse_host(authority):
    """host from the authority part of a URL, or None. Handles userinfo ('a.com@evil.com' is evil.com)."""
    a = authority.rsplit("@", 1)[-1]
    if a.startswith("["):
        return None  # IPv6 literal: not looked up
    host = a.split(":", 1)[0].strip(".").lower()
    if not host or "." not in host:
        return None
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host if HOST_OK.match(host) else None


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def ignorable(host):
    if host in RESERVED_HOSTS or host.endswith(RESERVED_SUFFIX):
        return True
    if is_ip(host):
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    return False


def extract(target):
    """-> (hosts: {host: {"refs": [...], "urls": set()}}, coverage: {...})"""
    hosts, cov = {}, {"files": 0, "binary_or_unreadable": 0, "too_large": 0, "file_cap_hit": False, "host_cap_hit": False}
    for dp, dns, fns in os.walk(target):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            path = os.path.join(dp, fn)
            if os.path.islink(path):
                continue
            if cov["files"] >= MAX_FILES:
                cov["file_cap_hit"] = True
                return hosts, cov
            try:
                size = os.path.getsize(path)
                if size > MAX_FILE_BYTES:
                    cov["too_large"] += 1
                    continue
                with open(path, "rb") as fh:
                    head = fh.read(4096)
                    if bytes([0]) in head:
                        cov["binary_or_unreadable"] += 1
                        continue
                    data = head + fh.read()
            except OSError:
                cov["binary_or_unreadable"] += 1
                continue
            cov["files"] += 1
            if b"://" not in data:
                continue  # most files: no URL at all, so skip the decode and the regex
            rel = os.path.relpath(path, target).replace(os.sep, "/")
            text = data.decode("utf-8", "replace")
            line, last = 1, 0
            for m in URL_RE.finditer(text):
                line += text.count(chr(10), last, m.start())
                last = m.start()
                host = parse_host(m.group(1))
                if not host or ignorable(host):
                    continue
                if host not in hosts and len(hosts) >= MAX_HOSTS:
                    cov["host_cap_hit"] = True
                    continue
                ent = hosts.setdefault(host, {"refs": [], "urls": set()})
                if len(ent["refs"]) < MAX_REFS and f"{rel}:{line}" not in ent["refs"]:
                    ent["refs"].append(f"{rel}:{line}")
                if len(ent["urls"]) < 5:
                    ent["urls"].add(normalize_url(m.group(0), text[m.start():m.start() + 400]))
    return hosts, cov


def normalize_url(prefix, text):
    """Lowercased scheme+host plus the path as written, up to whitespace/quote; fragment and query dropped."""
    m = re.match(r"""(?i)(\w+://[^\s"'<>\\)\]}`,;|]+)""", text)
    u = (m.group(1) if m else prefix).split("#", 1)[0].split("?", 1)[0]
    scheme, _, rest = u.partition("://")
    host, _, path = rest.partition("/")
    return f"{scheme.lower()}://{host.rsplit('@', 1)[-1].lower()}/{path}".rstrip("/")


def feed_dir():
    d = os.environ.get("TRIAGE_FEED_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "security-triage", "feeds")
    os.makedirs(d, exist_ok=True)
    return d


def refresh_feeds(fdir, max_age_days, notes):
    """Fetch missing or stale feeds. Feed hosts only; never a domain from the target."""
    for name, url in FEEDS.items():
        p = os.path.join(fdir, name)
        if os.path.exists(p) and (time.time() - os.path.getmtime(p)) < max_age_days * 86400:
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "security-triage/1 (feed refresh)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read(FEED_MAX_BYTES + 1)
            if len(body) > FEED_MAX_BYTES or not body:
                raise ValueError("empty or over the size cap")
            tmp = p + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(body)
            os.replace(tmp, p)
            notes.append(f"refreshed {name} ({len(body)} bytes)")
        except Exception as e:  # noqa: BLE001 - a failed refresh must degrade, not crash the pipeline
            notes.append(f"could not refresh {name}: {type(e).__name__}")


def load_feeds(fdir, max_age_days):
    """-> (data, problems). problems = feeds missing / stale / unparsable (each makes the tier partial)."""
    data = {"hostfile": set(), "online_urls": set(), "online_ips": set(), "threatfox": {}}
    problems, ages = [], {}
    for name in FEEDS:
        p = os.path.join(fdir, name)
        if not os.path.exists(p):
            problems.append(f"{name} missing")
            continue
        age = (time.time() - os.path.getmtime(p)) / 86400
        ages[name] = round(age, 1)
        if age > max_age_days:
            problems.append(f"{name} is {age:.0f} days old (limit {max_age_days})")
        try:
            if name == "urlhaus_hostfile.txt":
                for line in open(p, encoding="utf-8", errors="replace"):
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        data["hostfile"].add(parts[1].lower())
            elif name == "urlhaus_online.txt":
                for line in open(p, encoding="utf-8", errors="replace"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    u = normalize_url(line, line)
                    data["online_urls"].add(u)
                    h = parse_host(u.partition("://")[2].partition("/")[0])
                    if h and is_ip(h):
                        data["online_ips"].add(h)
            else:
                for entries in json.load(open(p, encoding="utf-8")).values():
                    for e in entries:
                        if e.get("ioc_type") == "domain" and e.get("ioc_value"):
                            data["threatfox"][e["ioc_value"].lower()] = e
        except Exception as e:  # noqa: BLE001
            problems.append(f"{name} unparsable ({type(e).__name__})")
    return data, problems, ages


def match_feeds(hosts, feeds):
    findings = []
    for host, ent in sorted(hosts.items()):
        refs = ent["refs"]
        if host in feeds["hostfile"]:
            findings.append({"kind": "known-bad-host", "host": host, "source": "urlhaus-hostfile", "refs": refs,
                             "detail": "listed in the abuse.ch URLhaus host file (hosts serving malware)"})
        for u in sorted(ent["urls"]):
            if u in feeds["online_urls"]:
                findings.append({"kind": "known-bad-url", "host": host, "source": "urlhaus-online", "refs": refs,
                                 "detail": f"exact URL is currently listed as online malware distribution: {u}"})
        if is_ip(host) and host in feeds["online_ips"]:
            findings.append({"kind": "known-bad-ip", "host": host, "source": "urlhaus-online", "refs": refs,
                             "detail": "IP address currently hosts a URL listed by URLhaus (a different path may be benign, but a literal IP in code is rarely legitimate)"})
        for cand in suffixes(host):
            e = feeds["threatfox"].get(cand)
            if e:
                findings.append({"kind": "known-bad-host", "host": host, "source": "threatfox", "refs": refs,
                                 "detail": f"ThreatFox IOC {cand}: {e.get('malware_printable') or e.get('malware')} / {e.get('threat_type')}, "
                                           f"confidence {e.get('confidence_level')}, "
                                           + ("a COMPROMISED legitimate site (the domain itself may be innocent)" if e.get("is_compromised") else "attacker-registered")})
                break
    return findings


def suffixes(host):
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def registrable(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def rdap_age(domain, base, cache, fdir):
    """-> (registered datetime or None, reason). Cached on disk: a registration date does not change."""
    if domain in cache:
        c = cache[domain]
        return (datetime.fromisoformat(c["registered"]) if c.get("registered") else None), c.get("reason", "cached")
    try:
        req = urllib.request.Request(f"{base.rstrip('/')}/domain/{domain}", headers={"User-Agent": "security-triage/1", "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return None, "rate-limited"
        return None, f"RDAP HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, f"RDAP failed ({type(e).__name__})"
    for ev in d.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                continue
            cache[domain] = {"registered": dt.isoformat()}
            return dt, "ok"
    cache[domain] = {"registered": None, "reason": "RDAP record has no registration event"}
    return None, "RDAP record has no registration event"


def age_checks(hosts, findings, notes, fdir):
    base = os.environ.get("TRIAGE_RDAP_BASE", "https://rdap.org")
    new_days, cap = env_int("TRIAGE_DOMAIN_NEW_DAYS", 30), env_int("TRIAGE_DOMAIN_MAX", 40)
    cpath = os.path.join(fdir, "rdap_cache.json")
    try:
        cache = json.load(open(cpath, encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    unevaluable = {"shared-hosting": 0, "well-known": 0, "ip-literal": 0}
    todo = {}
    for host, ent in hosts.items():
        if is_ip(host):
            unevaluable["ip-literal"] += 1
            continue
        reg = registrable(host)
        if any(host == s or host.endswith("." + s) for s in SHARED_HOSTING):
            unevaluable["shared-hosting"] += 1
        elif reg in WELL_KNOWN:
            unevaluable["well-known"] += 1
        else:
            todo.setdefault(reg, []).append(host)
    checked, failed, skipped_cap = 0, {}, 0
    now = datetime.now(timezone.utc)
    for n, (reg, members) in enumerate(sorted(todo.items())):
        if checked >= cap:
            skipped_cap = len(todo) - n
            break
        fresh = reg not in cache
        dt, why = rdap_age(reg, base, cache, fdir)
        checked += 1
        if why == "rate-limited":
            failed["rate-limited"] = failed.get("rate-limited", 0) + 1
            skipped_cap = len(todo) - n - 1
            break
        if dt is None:
            failed[why] = failed.get(why, 0) + 1
        else:
            days = (now - dt).days
            if days < new_days:
                refs = sorted({r for h in members for r in hosts[h]["refs"]})[:MAX_REFS]
                findings.append({"kind": "newly-registered", "host": members[0] if len(members) == 1 else reg, "source": "rdap", "refs": refs,
                                 "detail": f"{reg} was registered {days} day(s) ago ({dt.date()}). Weak on its own: new domains are normal for new projects"})
        if fresh:
            time.sleep(0.3)
    try:
        json.dump(cache, open(cpath, "w", encoding="utf-8"))
    except OSError:
        pass
    parts = [f"{checked} registrable domain(s) queried"]
    if any(unevaluable.values()):
        parts.append("age not evaluable for " + ", ".join(f"{v} {k}" for k, v in unevaluable.items() if v))
    gaps = []
    if skipped_cap:
        gaps.append(f"{skipped_cap} domain(s) not queried (limit {cap}; raise TRIAGE_DOMAIN_MAX)")
    if failed:
        gaps.append("RDAP could not answer for " + ", ".join(f"{v} ({k})" for k, v in failed.items()))
    notes.append("age: " + "; ".join(parts))
    return gaps


def main():
    target, out = sys.argv[1], sys.argv[2]
    lookup = os.environ.get("TRIAGE_DOMAIN_LOOKUP") == "1"
    max_age = env_int("TRIAGE_FEED_MAX_AGE_DAYS", 7)
    notes, gaps = [], []
    fdir = feed_dir()
    hosts, cov = extract(target)
    report = {"domains_extracted": len(hosts), "files_scanned": cov["files"]}
    if cov["too_large"]:
        gaps.append(f"{cov['too_large']} file(s) over {MAX_FILE_BYTES // 1_000_000} MB not read")
    if cov["binary_or_unreadable"]:
        notes.append(f"{cov['binary_or_unreadable']} binary/unreadable file(s) not read")
    if cov["file_cap_hit"]:
        gaps.append(f"file cap ({MAX_FILES}) reached, remaining files not read")
    if cov["host_cap_hit"]:
        gaps.append(f"host cap ({MAX_HOSTS}) reached, further hosts not checked")

    if lookup:
        refresh_feeds(fdir, max_age, notes)
    feeds, problems, ages = load_feeds(fdir, max_age)
    report["feed_age_days"] = ages
    findings = []
    if not ages:
        status_detail = (f"{len(hosts)} domain(s) extracted but NOT checked: no threat feeds cached in {fdir}. "
                         "Set TRIAGE_DOMAIN_LOOKUP=1 to download them (and enable age lookups); that sends nothing about the target to the feed hosts, "
                         "but RDAP age lookups do tell the registries which domains it mentions.")
        report.update(status="skipped", detail=status_detail, findings=[], domains=sorted(hosts))
        json.dump(report, open(out, "w", encoding="utf-8"), indent=2)
        return
    findings += match_feeds(hosts, feeds)
    gaps += problems
    if lookup:
        gaps += age_checks(hosts, findings, notes, fdir)
    else:
        notes.append("domain-age lookup off (opt-in: TRIAGE_DOMAIN_LOOKUP=1)")
    kinds = {}
    for f in findings:
        kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
    summary = (f"{len(hosts)} domain(s) extracted from {cov['files']} file(s); "
               + (", ".join(f"{v} {k}" for k, v in sorted(kinds.items())) if kinds else "no feed match")
               + ". " + "; ".join(notes))
    status = "partial" if gaps else "ran"
    if gaps:
        summary += ". COVERAGE GAPS: " + "; ".join(gaps)
    report.update(status=status, detail=summary, findings=findings, domains=sorted(hosts))
    json.dump(report, open(out, "w", encoding="utf-8"), indent=2)


if __name__ == "__main__":
    main()
