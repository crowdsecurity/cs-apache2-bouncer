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
    # Targets for the internal-redirect tests: mod_rewrite without [R] and
    # ErrorDocument both reach their target through an internal redirect.
    mkdir -p "$HARNESS_DIR/htdocs/guarded" "$HARNESS_DIR/htdocs/open"
    echo guarded-ok > "$HARNESS_DIR/htdocs/guarded/index.html"
    echo open-ok > "$HARNESS_DIR/htdocs/open/index.html"
    echo denied-doc > "$HARNESS_DIR/htdocs/denied.html"
}

harness_cleanup() {
    [ -n "${APACHE_PID:-}" ] && kill "$APACHE_PID" 2>/dev/null
    [ -n "${LAPI_PID:-}" ] && kill "$LAPI_PID" 2>/dev/null
    [ -n "${APPSEC_PID:-}" ] && kill "$APPSEC_PID" 2>/dev/null
    # apache forks children; the pidfile is the reliable handle
    [ -f "$HARNESS_DIR/run/httpd.pid" ] && kill "$(cat "$HARNESS_DIR/run/httpd.pid")" 2>/dev/null
    wait 2>/dev/null
    [ -n "${HARNESS_KEEP:-}" ] || rm -rf "$HARNESS_DIR"
}

# Stops just Apache, leaving the stub API and its state in place.
harness_cleanup_apache() {
    if [ -f "$HARNESS_DIR/run/httpd.pid" ]; then
        apache2 -f "$HARNESS_DIR/httpd.conf" -k stop 2>/dev/null
        local i=0
        while [ -f "$HARNESS_DIR/run/httpd.pid" ] && [ "$i" -lt 50 ]; do
            i=$((i + 1)); sleep 0.1
        done
    fi
}

harness_free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

# Stub CrowdSec endpoint.
#   lapi_start <body>                 serve <body> for every request
#   lapi_start_sized <bytes>          serve <bytes> of filler, chunked
#   lapi_start_slow <body> <delay_s>  respond only after a delay
# The sized and slow variants exist so the response ceiling and the timeout get
# exercised against a real socket rather than a mock.
lapi_start() { lapi_spawn "body" "$1"; }
lapi_start_sized() { lapi_spawn "sized" "$1"; }
lapi_start_slow() { lapi_spawn "slow" "$1" "${2:-2}"; }

lapi_spawn() {
    python3 "$(dirname "${BASH_SOURCE[0]}")/stub_endpoint.py" \
        "$LAPI_PORT" "$@" &
    LAPI_PID=$!
    harness_wait_port "$LAPI_PORT"
}

# Full stub local API, driven by a JSON state file the tests rewrite between
# requests. See test/lib/stub_lapi.py.
lapi_api_start() {
    LAPI_STATE="$HARNESS_DIR/lapi-state.json"
    echo '{}' > "$LAPI_STATE"
    python3 "$(dirname "${BASH_SOURCE[0]}")/stub_lapi.py" \
        "$LAPI_PORT" "$LAPI_STATE" &
    LAPI_PID=$!
    harness_wait_port "$LAPI_PORT"
}

# Stub AppSec component. See test/lib/stub_appsec.py.
appsec_start() {
    APPSEC_PORT="$(harness_free_port)"
    APPSEC_STATE="$HARNESS_DIR/appsec-state.json"
    echo '{"action":"allow","http_status":200}' > "$APPSEC_STATE"
    python3 "$(dirname "${BASH_SOURCE[0]}")/stub_appsec.py" \
        "$APPSEC_PORT" "$APPSEC_STATE" &
    APPSEC_PID=$!
    harness_wait_port "$APPSEC_PORT"
}

appsec_set() { echo "$1" > "$APPSEC_STATE"; }

# appsec_seen <field>   what the module actually forwarded
appsec_seen() {
    python3 -c 'import json,sys
d=json.load(open(sys.argv[1])).get("seen") or {}
v=d.get(sys.argv[2])
print("" if v is None else v)' "$APPSEC_STATE" "$1"
}

appsec_calls() {
    python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("calls",0))' \
        "$APPSEC_STATE"
}

# appsec_has_header <name>  / appsec_header <name>
appsec_has_header() {
    python3 -c 'import json,sys
d=json.load(open(sys.argv[1])).get("seen") or {}
print("yes" if sys.argv[2].lower() in (d.get("headers") or {}) else "no")'         "$APPSEC_STATE" "$1"
}
appsec_header() {
    python3 -c 'import json,sys
d=json.load(open(sys.argv[1])).get("seen") or {}
print((d.get("headers") or {}).get(sys.argv[2].lower(),""))'         "$APPSEC_STATE" "$1"
}

# lapi_set <json>   replace the whole state
#
# Publishes by rename, so the stub can never read a half-written file, and
# takes the stub's lock so the write cannot land inside a pull's
# load/modify/save and be overwritten by the state it had already read.
lapi_set() {
    local tmp="$LAPI_STATE.new.$$"

    printf '%s' "$1" > "$tmp"
    (
        flock 9
        mv -f "$tmp" "$LAPI_STATE"
    ) 9>"$LAPI_STATE.lock"
}

# lapi_get <key>    read one key back (counters the stub maintains)
lapi_get() {
    python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' \
        "$LAPI_STATE" "$1"
}

# A ban decision for one value, as the API would render it.
decision() {
    printf '{"duration":"%s","id":1,"origin":"cscli","scenario":"manual","scope":"%s","type":"ban","value":"%s"}' \
        "${3:-1h0m0s}" "$2" "$1"
}

# Waits until the module reports the stream as loaded, so a test does not race
# the first poll.
wait_primed() {
    local i=0
    while [ "$i" -lt 150 ]; do
        if curl -fsS --max-time 5 \
            "http://127.0.0.1:$APACHE_PORT/crowdsec-status" 2>/dev/null \
            | grep -q "^primed: yes"; then
            return 0
        fi
        i=$((i + 1)); sleep 0.1
    done
    echo "stream never primed; status was:" >&2
    curl -sS --max-time 5 "http://127.0.0.1:$APACHE_PORT/crowdsec-status" >&2 || true
    sed -n "s/^/  log: /p" "$HARNESS_DIR/logs/error.log" | tail -20 >&2
    return 1
}

# Set HARNESS_NO_LAPI=1 to omit CrowdsecURL, for the AppSec-only configuration.
# Injecting it unconditionally hid a real bug: child_init created no curl
# handles without it, so an AppSec-only install inspected nothing.

# Directives that give us several child processes, spelled for whichever MPM
# is active: prefork counts servers, event and worker count threads.
mpm_many_children() {
    case "${HARNESS_MPM:-prefork}" in
    prefork)
        printf 'StartServers 4\nMinSpareServers 4\nMaxSpareServers 4\n'
        ;;
    *)
        printf 'StartServers 4\nThreadsPerChild 2\nMinSpareThreads 8\nMaxSpareThreads 8\n'
        ;;
    esac
}

status_field() {
    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/crowdsec-status" \
        | sed -n "s/^$1: //p"
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
    local lapi_line="CrowdsecURL http://127.0.0.1:$LAPI_PORT"

    if [ -n "${HARNESS_NO_LAPI:-}" ]; then
        lapi_line="# CrowdsecURL omitted: HARNESS_NO_LAPI is set"
    fi
    cat > "$HARNESS_DIR/httpd.conf" <<CONF
ServerRoot "$HARNESS_DIR"
# mod_cgid and the file-based mutexes put their sockets here; without it they
# try /var/run/apache2 and fail for a non-root instance.
DefaultRuntimeDir "$HARNESS_DIR/run"
ServerName localhost
PidFile "$HARNESS_DIR/run/httpd.pid"
Listen 127.0.0.1:$APACHE_PORT
# also on v6 loopback, so the IPv6 decision path gets exercised for real
Listen [::1]:$APACHE_PORT
ErrorLog "$HARNESS_DIR/logs/error.log"
LogLevel ${HARNESS_LOGLEVEL:-info crowdsec_module:trace1}
DocumentRoot "$HARNESS_DIR/htdocs"

LoadModule mpm_${HARNESS_MPM:-prefork}_module /usr/lib/apache2/modules/mod_mpm_${HARNESS_MPM:-prefork}.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so
LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so
LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so
LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so
LoadModule crowdsec_module $MODULE

<Directory "$HARNESS_DIR/htdocs">
    Require all granted
</Directory>

# Introspection for the tests: primed state, pull counts, retention.
<Location /crowdsec-status>
    SetHandler crowdsec-status
    Crowdsec off
</Location>

$lapi_line
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
# Sends bytes verbatim and prints the response. curl cannot produce an
# authority-form request line, which is the shape the CONNECT gating test needs.
raw_request() {
    python3 - "$APACHE_PORT" "$1" <<'PYEOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.sendall(sys.argv[2].encode())
out = b""
while True:
    try:
        c = s.recv(65536)
    except socket.timeout:
        break
    if not c:
        break
    out += c
s.close()
sys.stdout.write(out.decode("latin1", "replace"))
PYEOF
}

http_status() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/${1:-}"
}
