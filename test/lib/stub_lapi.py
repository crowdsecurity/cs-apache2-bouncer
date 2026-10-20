"""Stub CrowdSec local API, enough for the bouncer's two endpoints.

Usage: stub_lapi.py <port> <state_file>

The state file is JSON the test rewrites between requests, so a test can change
what the API says without restarting anything:

    {"decisions": [ {...}, ... ],   # served as "new" on the next stream pull
     "deleted":   [ {...}, ... ],
     "live":      [ {...} ],        # served by /v1/decisions
     "status":    200,              # force an HTTP status
     "delay":     0.0,              # stall before responding
     "metrics_status": 201,         # force a status for /v1/usage-metrics
     "record_headers": false,       # keep the headers we are sent, per endpoint
     "startup_seen": 0,             # written by us: counts startup=true pulls
     "pulls": 0,                    # written by us: counts stream pulls
     "req_headers": {...},          # written by us: headers, keyed by endpoint
     "metrics": [ {...}, ... ],     # written by us: each payload, decoded
     "metrics_raw": [ "..." ],      # written by us: each payload, verbatim
     "metrics_posts": 0}            # written by us: counts metrics pushes

The raw bodies are kept as well as the decoded ones because the two mistakes
that actually break this payload - an empty array serialised as {}, and an
unescaped label - both survive a round trip through json.loads.

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

    def record_headers(self, state, where):
        """Keep the headers the module sent, for the endpoint it sent them to.

        Opt-in: the live endpoint is otherwise read-only, and recording would
        turn every lookup into a locked read-modify-write. Caller holds the
        lock and saves.
        """
        seen = state.setdefault("req_headers", {}).setdefault(where, {})
        for h in ("user-agent", "x-api-key"):
            if self.headers.get(h) is not None:
                seen[h] = self.headers.get(h)

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
                if state.get("record_headers"):
                    self.record_headers(state, "stream")

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
            if state.get("record_headers"):
                with state_locked():
                    state = load()
                    self.record_headers(state, "decisions")
                    save(state)
            live = state.get("live", [])
            self.reply(200, live if live else None)
            return

        self.not_found()

    def do_POST(self):
        state = load()
        url = urlparse(self.path)

        delay = float(state.get("delay", 0))
        if delay:
            time.sleep(delay)

        if url.path != "/v1/usage-metrics":
            self.not_found()
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length).decode("utf-8", "replace") if length \
            else ""

        # Read-modify-write under the lock, like the stream pull: a test
        # rewriting the fixture between pushes must not lose a recorded one.
        with state_locked():
            state = load()
            state["metrics_posts"] = int(state.get("metrics_posts", 0)) + 1
            state.setdefault("metrics_raw", []).append(raw)
            state.setdefault("metrics_headers", {})
            # Only the headers a test asserts on; the rest is curl's business.
            for h in ("x-api-key", "content-type", "user-agent"):
                if self.headers.get(h) is not None:
                    state["metrics_headers"][h] = self.headers.get(h)
            try:
                state.setdefault("metrics", []).append(json.loads(raw))
            except ValueError:
                # Recorded as unparseable rather than dropped: a test asserting
                # on the payload shape should fail loudly, not see nothing.
                state.setdefault("metrics", []).append({"_unparseable": raw})
            forced = int(state.get("metrics_status", 201))
            save(state)

        # 201 Created is what the real local API answers.
        self.send_response(forced)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def not_found(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
