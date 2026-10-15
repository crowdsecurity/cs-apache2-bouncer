#!/usr/bin/env bash
# Shared helpers for the functional tests: a throwaway Apache instance and a
# stub LAPI. Everything lives under one temp dir so a failed run leaves a tree
# you can inspect, and a successful one leaves nothing.

harness_init() {
    HARNESS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/csapache.XXXXXX")"
    APACHE_PORT="$(harness_free_port)"
    LAPI_PORT="$(harness_free_port)"
    MODULE="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/.libs/mod_crowdsec.so"
    [ -f "$MODULE" ] || { echo "module not built: $MODULE (run: apxs -c mod_crowdsec.c)" >&2; return 1; }
    mkdir -p "$HARNESS_DIR"/{logs,htdocs,run}
    echo origin-ok > "$HARNESS_DIR/htdocs/index.html"
}

harness_cleanup() {
    [ -n "${APACHE_PID:-}" ] && kill "$APACHE_PID" 2>/dev/null
    [ -n "${LAPI_PID:-}" ] && kill "$LAPI_PID" 2>/dev/null
    # apache forks children; the pidfile is the reliable handle
    [ -f "$HARNESS_DIR/run/httpd.pid" ] && kill "$(cat "$HARNESS_DIR/run/httpd.pid")" 2>/dev/null
    wait 2>/dev/null
    [ -n "${HARNESS_KEEP:-}" ] || rm -rf "$HARNESS_DIR"
}

harness_free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

# Stub LAPI. $1 is the body served for every /v1/decisions query, so a test
# picks "null" for a clean IP or a decision array for a banned one.
lapi_start() {
    local body="$1"
    python3 - "$LAPI_PORT" "$body" <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, body = int(sys.argv[1]), sys.argv[2].encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
    LAPI_PID=$!
    harness_wait_port "$LAPI_PORT"
}

harness_wait_port() {
    local port="$1" i=0
    while [ "$i" -lt 100 ]; do
        python3 -c "import socket,sys;s=socket.socket()
try:
    s.connect(('127.0.0.1',$port)); sys.exit(0)
except OSError:
    sys.exit(1)" && return 0
        i=$((i + 1)); sleep 0.05
    done
    echo "port $port never came up" >&2
    return 1
}

# Writes a config with $1 spliced into the vhost, so each test states only the
# directives it is actually about.
apache_start() {
    local extra="$1"
    cat > "$HARNESS_DIR/httpd.conf" <<CONF
ServerRoot "$HARNESS_DIR"
ServerName localhost
PidFile "$HARNESS_DIR/run/httpd.pid"
Listen 127.0.0.1:$APACHE_PORT
ErrorLog "$HARNESS_DIR/logs/error.log"
LogLevel info crowdsec_module:trace1
DocumentRoot "$HARNESS_DIR/htdocs"

LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so
LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so
LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so
LoadModule crowdsec_module $MODULE

<Directory "$HARNESS_DIR/htdocs">
    Require all granted
</Directory>

CrowdsecURL http://127.0.0.1:$LAPI_PORT
CrowdsecAPIKey testkey
$extra
CONF
    apache2 -f "$HARNESS_DIR/httpd.conf" -k start 2>"$HARNESS_DIR/logs/start.err" || {
        echo "apache failed to start:" >&2; cat "$HARNESS_DIR/logs/start.err" >&2
        sed -n '1,40p' "$HARNESS_DIR/logs/error.log" >&2 2>/dev/null
        return 1
    }
    harness_wait_port "$APACHE_PORT"
}

# Echoes the status code for GET /.
http_status() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/${1:-}"
}
