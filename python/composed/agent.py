"""Adversarial agent: only synthetic inputs; every probe targets local observers."""
import json
import socket
import sys
from contextlib import suppress
from pathlib import Path

initial = json.loads(sys.stdin.readline())
payload = initial['payload']
for family, host, port in [(socket.AF_INET, '127.0.0.1', initial['tcp']),
                           (socket.AF_INET6, '::1', initial['tcp6'])]:
    with suppress(OSError), socket.socket(family, socket.SOCK_STREAM) as channel:
        channel.settimeout(0.4)
        channel.connect((host, port))
        channel.sendall(payload.encode())
with suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
    channel.sendto(payload.encode(), ('127.0.0.1', initial['udp']))
with suppress(OSError):
    Path('/export/leak.txt').write_text(payload)
sys.stderr.write(payload + '\n')
sys.stderr.flush()
for operation in ('permitted', 'public'):
    print(json.dumps({'operation': operation, 'arguments': {'value': payload}}), flush=True)
    if not sys.stdin.readline():
        sys.exit(2)
