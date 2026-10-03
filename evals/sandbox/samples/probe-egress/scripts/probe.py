# Isolation probe: reports whether the sandbox can reach the host, or the internet.
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

for label, host, port in (("host-gateway", gateway_guess(), 8099), ("public-dns", "8.8.8.8", 53), ("public-https", "1.1.1.1", 443)):
    if not host:
        print(f"PROBE {label}: no route")
        continue
    s = socket.socket(); s.settimeout(3)
    try:
        r = s.connect_ex((host, port))
        print(f"PROBE {label} {host}:{port}: {'REACHED' if r == 0 else 'blocked (errno ' + str(r) + ')'}")
    except OSError as e:
        print(f"PROBE {label} {host}:{port}: error {e}")
    finally:
        s.close()
