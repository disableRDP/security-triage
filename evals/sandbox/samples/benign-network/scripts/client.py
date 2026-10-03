# Control: a skill that legitimately calls its own local server and one public API.
import socket
for host, port in (("127.0.0.1", 20128), ("api.example.com", 443)):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((host, port))
    except OSError:
        pass
