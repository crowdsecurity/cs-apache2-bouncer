"""Stub CrowdSec endpoint for the functional tests.

Usage: stub_endpoint.py <port> <mode> <arg> [delay]

  body  <json>   serve <json> with a Content-Length
  sized <bytes>  serve <bytes> of filler using chunked encoding, so no size is
                 announced -- which is why the response ceiling has to be
                 enforced in the write callback rather than by MAXFILESIZE
  slow  <json>   serve <json>, but only after [delay] seconds
"""
import sys
import time
try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:
    # ThreadingHTTPServer landed in python 3.7; EL8 ships 3.6, and it is the
    # same two ingredients the stdlib combines.
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

port = int(sys.argv[1])
mode = sys.argv[2]
arg = sys.argv[3]
delay = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self):
        if mode == "sized":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            total, block = int(arg), b"x" * 4096
            sent = 0
            while sent < total:
                take = min(len(block), total - sent)
                self.wfile.write(b"%x\r\n" % take + block[:take] + b"\r\n")
                sent += take
            self.wfile.write(b"0\r\n\r\n")
            return

        if mode == "slow":
            time.sleep(delay)
        body = arg.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.respond()

    def do_POST(self):
        length = self.headers.get("Content-Length")
        if length:
            try:
                self.rfile.read(int(length))
            except (ValueError, OSError):
                pass
        self.respond()

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
