#!/usr/bin/env python3
"""Containment probe: run INSIDE the sandbox, as the same unprivileged user the
suspect scripts run as, before any suspect code is executed.

Prints JSON {"contained": bool, "checks": [...]} and exits 0 only if every
check passed. A check that cannot be evaluated counts as a failure: a sandbox
that has not been verified is not trusted.

Network checks require a real response (an HTTP status line, a DNS answer, an
ICMP echo reply), not a TCP handshake, which a transparent proxy completes for
every destination. Env: PROBE_HOST_PORT = port of a listener on the host, so
"can reach the host" is tested for real rather than assumed.
"""
import json
import os
import socket
import struct
import sys

checks = []


def check(name, ok, detail):
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def status_field(name):
    try:
        for line in open("/proc/self/status"):
            if line.startswith(name + ":"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def can_write(path, tag):
    p = os.path.join(path, f".probe-{tag}")
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        os.unlink(p)
        return True
    except OSError:
        return False


def http_reached(host, port):
    s = socket.socket()
    s.settimeout(3)
    try:
        if s.connect_ex((host, port)) != 0:
            return False
        s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        return s.recv(100).startswith(b"HTTP/")
    except OSError:
        return False
    finally:
        s.close()


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    t = (t >> 16) + (t & 0xFFFF)
    return ~(t + (t >> 16)) & 0xFFFF


def icmp_reply(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return False  # cannot even open one: nothing to leak through
    s.settimeout(3)
    hdr = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    pkt = struct.pack("!BBHHH", 8, 0, checksum(hdr + b"PROBE"), 1, 1) + b"PROBE"
    try:
        s.sendto(pkt, (host, 0))
        return bool(s.recvfrom(256)[0])
    except OSError:
        return False
    finally:
        s.close()


def gateway_guess():
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[0] != "lo" and int(f[2], 16):
                return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except OSError:
        pass
    return None


# --- identity and hardening: the properties the sandbox is supposed to have ---
check("not-root", os.geteuid() != 0 and os.getuid() != 0, f"euid={os.geteuid()} uid={os.getuid()}")
capeff = status_field("CapEff")
check("no-capabilities", capeff is not None and int(capeff, 16) == 0, f"CapEff={capeff}")
nnp = status_field("NoNewPrivs")
check("no-new-privileges", nnp == "1", f"NoNewPrivs={nnp}")

pids = None
for p in ("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"):
    try:
        pids = open(p).read().strip()
        break
    except OSError:
        continue
check("pids-limit", pids is not None and pids != "max", f"pids.max={pids}")

w = can_write("/etc", "root")
check("rootfs-read-only", not w, "write to /etc " + ("succeeded" if w else "refused"))
for mount in ("/trace", "/target"):
    if os.path.isdir(mount):
        w = can_write(mount, "m")
        check(f"{mount}-not-writable", not w, f"script user write to {mount} " + ("succeeded" if w else "refused"))

# --- network: no interface beyond loopback, and nothing real answers ---
try:
    ifaces = [l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:]]
except OSError:
    ifaces = None
check("only-loopback-interface", ifaces is not None and set(ifaces) <= {"lo"}, f"interfaces={ifaces}")

port = int(os.environ.get("PROBE_HOST_PORT", "0") or 0)
hosts = [h for h in {gateway_guess(), "172.17.0.1", "host.docker.internal"} if h]
if port:
    hit = [h for h in hosts if http_reached(h, port)]
    check("host-listener-unreachable", not hit, f"reached host listener via {hit}" if hit else f"tried {sorted(hosts)}:{port}")
else:
    check("host-listener-unreachable", False, "PROBE_HOST_PORT not set: host reachability was not tested")
check("public-http-unreachable", not http_reached("1.1.1.1", 80), "1.1.1.1:80")
try:
    ip = socket.gethostbyname("example.com")
    check("dns-unresolvable", False, f"example.com resolved to {ip}")
except OSError:
    check("dns-unresolvable", True, "example.com did not resolve")
check("icmp-no-reply", not icmp_reply("1.1.1.1"), "1.1.1.1")

contained = all(c["ok"] for c in checks)
print(json.dumps({"contained": contained, "checks": checks}, indent=2))
sys.exit(0 if contained else 1)
