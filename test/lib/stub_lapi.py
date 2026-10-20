"""Stub CrowdSec local API, enough for the bouncer's two endpoints.

Usage: stub_lapi.py <port> <state_file>

The state file is JSON the test rewrites between requests, so a test can change
what the API says without restarting anything:

    {"decisions": [ {...}, ... ],   # served as "new" on the next stream pull
     "deleted":   [ {...}, ... ],
     "live":      [ {...} ],        # served by /v1/decisions
     "status":    200,              # force an HTTP status
     "delay":     0.0,              # stall before responding
     "startup_seen": 0,             # written by us: counts startup=true pulls
     "pulls": 0}                    # written by us: counts stream pulls

Decisions handed out as "new" are cleared after a pull unless "sticky" is set,
which mirrors the real API: a startup pull repeats everything, an incremental
one only reports changes.
"""
import fcntl
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:
    # ThreadingHTTPServer landed in python 3.7; EL8 ships 3.6, and it is the
    # same two ingredients the stdlib combines.
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
from urllib.parse import urlparse, parse_qs

port = int(sys.argv[1])
state_path = sys.argv[2]
lock_path = state_path + ".lock"

# A pull is a read-modify-write: it reports the pending decisions and then
# clears them. Without holding a lock across the whole thing, a test writing
# the next fixture in between has its write overwritten by the state we had
# already read. The threading lock covers our own ThreadingHTTPServer workers,
# the flock covers the test harness writing from another process.
_threads = threading.Lock()


@contextmanager
def state_locked():
    with _threads:
        with open(lock_path, "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lk, fcntl.LOCK_UN)


def load():
    try:
        with open(state_path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save(state):
    tmp = state_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, state_path)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        state = load()
        url = urlparse(self.path)
        query = parse_qs(url.query)

        delay = float(state.get("delay", 0))
        if delay:
            time.sleep(delay)

        forced = int(state.get("status", 200))
        if forced != 200:
            self.send_response(forced)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if url.path == "/v1/decisions/stream":
            startup = query.get("startup", ["false"])[0] == "true"

            # Re-read inside the lock: the copy above was taken without it and
            # may already be stale.
            with state_locked():
                state = load()
                state["pulls"] = int(state.get("pulls", 0)) + 1
                if startup:
                    state["startup_seen"] = \
                        int(state.get("startup_seen", 0)) + 1

                new = state.get("decisions", [])
                deleted = state.get("deleted", [])
                payload = {"new": new, "deleted": deleted}

                # An incremental pull reports changes once; a startup pull
                # repeats the full set, which is what makes takeover safe.
                if not startup and not state.get("sticky"):
                    state["decisions"] = []
                    state["deleted"] = []
                save(state)
            self.reply(200, payload)
            return

        if url.path == "/v1/decisions":
            live = state.get("live", [])
            self.reply(200, live if live else None)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
