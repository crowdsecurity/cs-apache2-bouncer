"""Drive requests down ONE keep-alive connection, changing the API fixture
part way through.

A fresh connection can land on any Apache child, and the per-child memo in one
child is invisible to the others - so observing memo behaviour at all requires
pinning every request to a single connection.

Usage: memo_probe.py <port> <state_file> <new_state_json> [tries] [delay]
Prints: first=<status> blocked=<True|False> after=<seconds>
"""
import fcntl
import http.client
import json
import os
import sys
import time

port = int(sys.argv[1])
state_path = sys.argv[2]
new_state = sys.argv[3]
tries = int(sys.argv[4]) if len(sys.argv) > 4 else 16
delay = float(sys.argv[5]) if len(sys.argv) > 5 else 0.5


def publish(text):
    """Same contract as the harness's lapi_set: atomic, under the stub's lock."""
    json.loads(text)                       # fail loudly on a bad fixture
    lock = state_path + ".lock"
    with open(lock, "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            tmp = state_path + ".probe"
            with open(tmp, "w") as fh:
                fh.write(text)
            os.replace(tmp, state_path)
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)


def hit():
    conn.request("GET", "/")
    r = conn.getresponse()
    r.read()
    return r.status


first = hit()
publish(new_state)

blocked = False
waited = 0.0
for _ in range(tries):
    time.sleep(delay)
    waited += delay
    if hit() == 429:
        blocked = True
        break

print("first=%d blocked=%s after=%.1f" % (first, blocked, waited))
