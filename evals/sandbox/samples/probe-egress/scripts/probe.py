# Isolation probe: reports what the sandbox lets this process actually reach.
# A completed TCP handshake proves little: a transparent proxy completes handshakes
# for every destination. So each target also gets an HTTP request, and "REACHED"
# means a real HTTP response came back from the destination.
import socket, struct

def gateway_guess():
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[0] == "lo":
                continue
            dest, gw = int(f[1], 16), int(f[2], 16)
            if gw:
                return socket.inet_ntoa(struct.pack("<L", gw))
            if dest:
                return socket.inet_ntoa(struct.pack("<L", dest + 0x01000000))
    except OSError:
        pass
    return None

def http_probe(host, port):
    s = socket.socket(); s.settimeout(3)
    try:
        if s.connect_ex((host, port)) != 0:
            return "handshake=no"
        s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = s.recv(100)
        if data.startswith(b"HTTP/"):
            return "handshake=yes RESPONSE=" + data.split(b"\r\n")[0].decode(errors="replace")
        return "handshake=yes response=none" if not data else "handshake=yes response=non-HTTP"
    except OSError as e:
        return f"handshake=yes then {type(e).__name__}"
    finally:
        s.close()

def checksum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    t = (t >> 16) + (t & 0xFFFF)
    return ~(t + (t >> 16)) & 0xFFFF

def icmp_probe(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as e:
        return f"no unprivileged ICMP socket ({e})"
    s.settimeout(3)
    payload = b"CANARY-PAYLOAD"
    hdr = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    pkt = struct.pack("!BBHHH", 8, 0, checksum(hdr + payload), 1, 1) + payload
    try:
        s.sendto(pkt, (host, 0))
        data, _ = s.recvfrom(256)
        return "ECHO REPLY RECEIVED (covert channel open)" if data else "no reply"
    except OSError as e:
        return f"no reply ({type(e).__name__})"
    finally:
        s.close()

gw = gateway_guess()
print("PROBE host-gateway", f"{gw}:8099" if gw else "(no route)", http_probe(gw, 8099) if gw else "no route")
print("PROBE public-http  1.1.1.1:80", http_probe("1.1.1.1", 80))
print("PROBE public-icmp  1.1.1.1", icmp_probe("1.1.1.1"))
