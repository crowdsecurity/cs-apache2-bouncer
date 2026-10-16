"""Stub AppSec component, implementing the bouncer-facing protocol.

Usage: stub_appsec.py <port> <state_file>

The state file is JSON the test rewrites between requests:

    {"action": "allow"|"ban"|"captcha"|"challenge"|"<custom>",
     "status": 200|403,            # what the bouncer receives
     "http_status": 200,           # what the browser should receive
     "body": "<html>...",          # user_body_content
     "cookies": ["a=1; Path=/"],   # user_cookies
     "headers": {"X": ["v"]},      # user_headers
     "raw": "...",                 # send this body verbatim, ignoring the rest
     "delay": 0.0,
     "require_key": "..."}         # 401 unless the key matches

It records what it was sent so a test can assert on the forwarded request:

    {"seen": {"uri":..., "verb":..., "ip":..., "host":..., "ua":...,
              "version":..., "txid":..., "method":..., "body_len":...,
              "headers": {...},         # every header it received
              "header_order": [...]}}
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
state_path = sys.argv[2]


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

    def record(self, state, body_len):
        h = {k.lower(): v for k, v in self.headers.items()}
        state["seen"] = {
            "uri": h.get("x-crowdsec-appsec-uri"),
            "verb": h.get("x-crowdsec-appsec-verb"),
            "ip": h.get("x-crowdsec-appsec-ip"),
            "host": h.get("x-crowdsec-appsec-host"),
            "ua": h.get("x-crowdsec-appsec-user-agent"),
            "version": h.get("x-crowdsec-appsec-http-version"),
            "txid": h.get("x-crowdsec-appsec-transaction-id"),
            "key": h.get("x-crowdsec-appsec-api-key"),
            "method": self.command,
            "body_len": body_len,
            "headers": h,
            "header_order": [k for k, _ in self.headers.items()],
            "header_count": len(self.headers),
        }
        state["calls"] = int(state.get("calls", 0)) + 1
        save(state)

    def handle_one(self):
        state = load()
        length = self.headers.get("Content-Length")
        body = b""
        if length:
            try:
                body = self.rfile.read(int(length))
            except (ValueError, OSError):
                body = b""
        self.record(state, len(body))

        if state.get("delay"):
            time.sleep(float(state["delay"]))

        want = state.get("require_key")
        if want and self.headers.get("X-Crowdsec-Appsec-Api-Key") != want:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        status = int(state.get("status", 200))
        if "raw" in state:
            payload = state["raw"].encode()
        else:
            doc = {"action": state.get("action", "allow"),
                   "http_status": int(state.get("http_status", 200))}
            if state.get("body") is not None:
                doc["user_body_content"] = state["body"]
            if state.get("cookies"):
                doc["user_cookies"] = state["cookies"]
            if state.get("headers"):
                doc["user_headers"] = state["headers"]
            payload = json.dumps(doc).encode()

        self.send_response(status)
        # Deliberately no Content-Type: the real engine sets none, so a client
        # that gates parsing on application/json would break against it.
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = handle_one
    do_POST = handle_one
    do_PUT = handle_one
    do_DELETE = handle_one
    do_PATCH = handle_one

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
