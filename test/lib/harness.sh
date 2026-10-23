#!/usr/bin/env bash
# Shared helpers for the functional tests: a throwaway Apache instance and a
# stub LAPI. Everything lives under one temp dir so a failed run leaves a tree
# you can inspect, and a successful one leaves nothing.

harness_init() {
    HARNESS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/csapache.XXXXXX")"
    APACHE_PORT="$(harness_free_port)"
    LAPI_PORT="$(harness_free_port)"
    # Overridable so a regression can be replayed against an older build of
    # the module: a test that passes against the version that had the bug is
    # testing nothing.
    MODULE="${MODULE:-$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/.libs/mod_crowdsec.so}"
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

# lapi_header <endpoint> <name>   one header the module sent us, where
# <endpoint> is "stream" or "decisions". Needs record_headers in the state
# before the request that should be captured.
lapi_header() {
    python3 -c '
import json, sys
d = (json.load(open(sys.argv[1])).get("req_headers") or {}).get(sys.argv[2]) or {}
print(d.get(sys.argv[3].lower(), ""))' "$LAPI_STATE" "$1" "$2"
}

# lapi_patch <key> <json value>   change one key, leaving the rest alone
#
# lapi_set replaces the whole file, which also discards the pushes the stub has
# recorded - so a test that flips a knob mid-run has to merge instead.
lapi_patch() {
    python3 -c '
import fcntl, json, os, sys
state, key, raw = sys.argv[1], sys.argv[2], sys.argv[3]
with open(state + ".lock", "w") as lk:
    fcntl.flock(lk, fcntl.LOCK_EX)
    try:
        with open(state) as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        d = {}
    d[key] = json.loads(raw)
    tmp = state + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(d, fh)
    os.replace(tmp, state)' "$LAPI_STATE" "$1" "$2"
}

# --- usage metrics ------------------------------------------------------
# How many pushes the stub has recorded, 0 rather than empty before the first.
metrics_posts() {
    python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as fh:
        print(int(json.load(fh).get("metrics_posts", 0)))
except (OSError, ValueError):
    print(0)' "$LAPI_STATE"
}

# Waits until at least <n> metrics pushes have been recorded, so a test does
# not race the reporting window.
wait_metrics() {
    local want="${1:-1}" i=0

    while [ "$i" -lt 300 ]; do
        if [ "$(metrics_posts)" -ge "$want" ]; then
            return 0
        fi
        i=$((i + 1)); sleep 0.1
    done
    echo "only $(metrics_posts) metrics pushes, wanted $want" >&2
    sed -n "s/^/  log: /p" "$HARNESS_DIR/logs/error.log" | tail -20 >&2
    return 1
}

# metric_item <index> <name> [label=value ...]
# The value of one item from a recorded payload, or "" if it is not there.
# <index> is 0 for the first push, -1 for the most recent.
metric_item() {
    local idx="$1" name="$2"; shift 2
    python3 -c '
import json, sys
state, idx, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
want = dict(a.split("=", 1) for a in sys.argv[4:])
pushes = json.load(open(state)).get("metrics") or []
if not pushes or idx >= len(pushes) or idx < -len(pushes):
    print(""); raise SystemExit
comp = (pushes[idx].get("remediation_components") or [{}])[0]
for window in comp.get("metrics") or []:
    for it in window.get("items") or []:
        if it.get("name") != name:
            continue
        labels = it.get("labels") or {}
        if all(labels.get(k) == v for k, v in want.items()):
            print(it.get("value")); raise SystemExit
print("")' "$LAPI_STATE" "$idx" "$name" "$@"
}

# metric_item_max <name> [label=value ...]
# The largest value any recorded push reported for this item, or "" if none
# did. For assertions where which push carried the number is a race.
metric_item_max() {
    local name="$1"; shift
    python3 -c '
import json, sys
state, name = sys.argv[1], sys.argv[2]
want = dict(a.split("=", 1) for a in sys.argv[3:])
best = None
for push in json.load(open(state)).get("metrics") or []:
    for comp in push.get("remediation_components") or []:
        for window in comp.get("metrics") or []:
            for it in window.get("items") or []:
                if it.get("name") != name:
                    continue
                labels = it.get("labels") or {}
                if all(labels.get(k) == v for k, v in want.items()):
                    v = it.get("value")
                    if best is None or v > best:
                        best = v
print("" if best is None else best)' "$LAPI_STATE" "$name" "$@"
}

# metric_meta <index> <field>   e.g. window_size_seconds
metric_meta() {
    python3 -c '
import json, sys
state, idx, field = sys.argv[1], int(sys.argv[2]), sys.argv[3]
pushes = json.load(open(state)).get("metrics") or []
if not pushes or idx >= len(pushes) or idx < -len(pushes):
    print(""); raise SystemExit
comp = (pushes[idx].get("remediation_components") or [{}])[0]
w = (comp.get("metrics") or [{}])[0]
print((w.get("meta") or {}).get(field, ""))' "$LAPI_STATE" "$1" "$2"
}

# metric_component <index> <field>  e.g. type, version, utc_startup_timestamp
metric_component() {
    python3 -c '
import json, sys
state, idx, field = sys.argv[1], int(sys.argv[2]), sys.argv[3]
pushes = json.load(open(state)).get("metrics") or []
if not pushes or idx >= len(pushes) or idx < -len(pushes):
    print(""); raise SystemExit
comp = (pushes[idx].get("remediation_components") or [{}])[0]
v = comp.get(field)
print("" if v is None else json.dumps(v) if isinstance(v, (dict, list))
      else v)' "$LAPI_STATE" "$1" "$2"
}

# metric_raw <index>   the payload exactly as it went out
metric_raw() {
    python3 -c '
import json, sys
raws = json.load(open(sys.argv[1])).get("metrics_raw") or []
idx = int(sys.argv[2])
print(raws[idx] if raws and -len(raws) <= idx < len(raws) else "")' \
        "$LAPI_STATE" "$1"
}

metric_header() {
    python3 -c '
import json, sys
h = json.load(open(sys.argv[1])).get("metrics_headers") or {}
print(h.get(sys.argv[2].lower(), ""))' "$LAPI_STATE" "$1"
}

# One counter line out of CrowdsecStatus. Avoids status_field because the
# labels carry braces, which sed would read as an interval expression.
status_metric() {
    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/crowdsec-status" \
        | grep -F "$1: " | cut -d' ' -f2-
}

# A ban decision for one value, as the API would render it.
decision() {
    printf '{"duration":"%s","id":1,"origin":"cscli","scenario":"manual","scope":"%s","type":"ban","value":"%s"}' \
        "${3:-1h0m0s}" "$2" "$1"
}

# decision_typed <value> <scope> <type> [duration] [id]
# Like decision(), but with another type, and an id of its own: the store tells
# decisions for the same network apart by id, so a test with several needs
# them to differ.
decision_typed() {
    printf '{"duration":"%s","id":%s,"origin":"cscli","scenario":"manual","scope":"%s","type":"%s","value":"%s"}' \
        "${4:-1h0m0s}" "${5:-1}" "$2" "$3" "$1"
}

# decision_from <value> <scope> <origin> [scenario] [duration]
# Like decision(), but with the origin the metrics attribute the block to. A
# blocklist decision is origin "lists" plus the list name in scenario.
decision_from() {
    printf '{"duration":"%s","id":1,"origin":"%s","scenario":"%s","scope":"%s","type":"ban","value":"%s"}' \
        "${5:-1h0m0s}" "$3" "${4:-manual}" "$2" "$1"
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
# For regressions.bats: mod_alias and mod_headers reproduce the redirect and
# ProxyPreserveHost reports, the auth chain reproduces the basic-auth ones.
# Loaded for every test because LoadModule fails hard on a missing file, so
# splicing it per test would mean restating this whole block.
LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
LoadModule auth_basic_module /usr/lib/apache2/modules/mod_auth_basic.so
LoadModule authn_core_module /usr/lib/apache2/modules/mod_authn_core.so
LoadModule authn_file_module /usr/lib/apache2/modules/mod_authn_file.so
LoadModule authz_user_module /usr/lib/apache2/modules/mod_authz_user.so
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

# harness_request [path] [curl args...]
# Echoes the status code and keeps the response, so a test can assert on the
# status and the headers of the *same* request. The cold-cache regressions need
# that: a second request is served from the memo and no longer reproduces.
harness_request() {
    local path="${1:-}"
    shift || true
    curl -s -D "$HARNESS_DIR/resp.head" -o "$HARNESS_DIR/resp.body" \
        -w '%{http_code}' --max-time 10 "$@" \
        "http://127.0.0.1:$APACHE_PORT/$path"
}

# resp_header <name>   from the last harness_request, empty if absent
resp_header() {
    tr -d '\r' < "$HARNESS_DIR/resp.head" | sed -n "s/^$1: //Ip"
}

# A password file for the basic-auth tests. {SHA} rather than htpasswd's own
# format so this needs no apache2-utils.
harness_passwd() {
    python3 -c 'import base64, hashlib, sys
print("%s:{SHA}%s" % (sys.argv[1], base64.b64encode(
    hashlib.sha1(sys.argv[2].encode()).digest()).decode()))' \
        "$1" "$2" > "$HARNESS_DIR/passwd"
}
