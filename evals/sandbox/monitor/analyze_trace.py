#!/usr/bin/env python3
"""Turn strace output from a sandboxed skill run into a short list of indicators.

usage: analyze_trace.py <out_dir>

<out_dir> holds one <script>.trace per script plus exit_codes.txt, as written by
run_under_strace.sh. Prints JSON. Standard library only so it can run anywhere.

This reports what the script *attempted*, not what would have succeeded: the
sandbox has no network, so a connect() fails but is still logged.
"""
import json
import os
import re
import sys

LINE = re.compile(r"^(\d+)\s+(\w+)\((.*)$")
SEVERITY = {"clean": 0, "review": 1, "high": 2}

CRED_PATH = re.compile(
    r"(/\.aws/|/\.ssh/|/\.netrc$|/\.git-credentials$|/\.docker/config\.json$|/\.kube/config$"
    r"|/\.npmrc$|/\.pypirc$|/etc/shadow$|/\.config/gh/|/\.gnupg/|/Login Data$|/Cookies$)"
)
PERSIST_PATH = re.compile(
    r"(/\.bashrc$|/\.bash_profile$|/\.profile$|/\.zshrc$|/etc/cron|crontab|/authorized_keys$"
    r"|/\.config/autostart/|/etc/systemd/|/etc/rc\.local$|/etc/profile)"
)
ENV_PROBE = re.compile(r"^(/sys/class/net|/proc/net/|/sys/devices/virtual/dmi|/proc/self/status$)")
ALLOWED_WRITE = ("/workspace", "/tmp", "/out", "/var/tmp", "/dev/null", "/dev/tty", "/dev/shm")
RISKY_EXEC = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "telnet", "ftp",
              "crontab", "sudo", "su", "nsenter"}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")
SOCKADDR = re.compile(
    r'sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), '
    r'(?:sin_addr=inet_addr\("([^"]+)"\)|sin6_addr=inet_pton\(AF_INET6, "([^"]+)"\))'
)
URL = re.compile(r'https?://([^/\s"\\]+)')


def is_loopback(addr):
    return addr.startswith("127.") or addr == "::1"


def analyze(trace_path):
    iocs, seen = [], set()

    def add(kind, severity, detail):
        key = (kind, detail)
        if key not in seen:
            seen.add(key)
            iocs.append({"kind": kind, "severity": severity, "detail": detail})

    cred_read = external = False
    with open(trace_path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            m = LINE.match(raw)
            if not m:
                continue
            _, call, rest = m.groups()
            result = raw.rsplit(" = ", 1)[-1].strip() if " = " in raw else "unfinished"

            if call in ("openat", "open", "creat"):
                pm = re.search(r'"([^"]+)"', rest)
                if not pm:
                    continue
                path = pm.group(1)
                writes = call == "creat" or any(f in rest for f in WRITE_FLAGS)
                if writes:
                    if PERSIST_PATH.search(path):
                        add("persistence-write", "high", f"{path} ({result})")
                    elif not path.startswith(ALLOWED_WRITE):
                        add("write-outside-workspace", "high", f"{path} ({result})")
                elif CRED_PATH.search(path):
                    cred_read = True
                    add("credential-read", "review", f"{path} ({result})")
                elif ENV_PROBE.search(path):
                    add("environment-probe", "review", path)
            elif call == "connect":
                sm = SOCKADDR.search(rest)
                if not sm:
                    continue  # AF_UNIX etc.
                port, v4, v6 = sm.groups()
                addr = v4 or v6
                if is_loopback(addr):
                    continue
                external = True
                kind = "dns-lookup-attempt" if port == "53" else "external-connect-attempt"
                add(kind, "review", f"{addr}:{port} ({result})")
            elif call == "execve":
                em = re.match(r'"([^"]+)", \[(.*?)\](?:,|\))', rest)
                if not em:
                    continue
                exe = os.path.basename(em.group(1))
                if exe in RISKY_EXEC:
                    external = external or exe in {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "telnet", "ftp"}
                    hosts = sorted(set(URL.findall(em.group(2))))
                    add("network-tool-exec", "review", f"{exe}" + (f" -> {', '.join(hosts)}" if hosts else ""))

    if cred_read and external:
        add("exfiltration-pattern", "high", "read credential files and attempted external network access")
    verdict = max((i["severity"] for i in iocs), key=lambda s: SEVERITY.get(s, 0), default="clean")
    return {"verdict": verdict, "iocs": iocs}


def main(out_dir):
    codes = {}
    cpath = os.path.join(out_dir, "exit_codes.txt")
    if os.path.exists(cpath):
        for line in open(cpath, encoding="utf-8"):
            m = re.match(r"(\S+) exit=(\d+)", line.strip())
            if m:
                codes[m.group(1)] = int(m.group(2))
    scripts, coverage = {}, []
    for name in sorted(f[:-6] for f in os.listdir(out_dir) if f.endswith(".trace")):
        res = analyze(os.path.join(out_dir, name + ".trace"))
        if codes.get(name) in (124, 137):
            coverage.append(f"{name} did not finish before the timeout; anything it did afterwards was not observed")
        scripts[name] = res
    if not scripts:
        coverage.append("no runnable scripts were found, so nothing was executed")
    overall = max((s["verdict"] for s in scripts.values()), key=lambda s: SEVERITY[s], default="clean")
    print(json.dumps({"verdict": overall, "coverage_gaps": coverage, "scripts": scripts}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
