#!/usr/bin/env bats
# Legacy "Satisfy Any" must not be able to override a verdict.
#
# Under Satisfy Any, Apache reads a refusal from an access_checker hook as "this
# route did not pass, try authentication instead", and an authorization that
# grants the request then serves it. A verdict delivered from that hook was
# therefore advisory wherever Satisfy Any was in effect - including from an
# .htaccess under AllowOverride AuthConfig, which a site owner controls. A ban
# was served, a WAF block was served, and a challenge page had the origin's
# response written after it.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
    appsec_start
    lapi_set "{\"live\": [$(decision 127.0.0.1 Ip)]}"
}

teardown() {
    harness_cleanup
}

ACCESS_COMPAT="LoadModule access_compat_module /usr/lib/apache2/modules/mod_access_compat.so"

# Crowdsec on for the whole site, plus whatever the test adds to <Location />.
lapi_conf() {
    cat <<CONF
$ACCESS_COMPAT
<Location />
    Crowdsec on
    $1
</Location>
$2
CONF
}

appsec_conf() {
    cat <<CONF
$ACCESS_COMPAT
CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
<Location />
    Crowdsec off
    CrowdsecAppsec on
    $1
</Location>
$2
CONF
}

challenge_state() {
    cat <<'JSON'
{"status":403,"action":"challenge","http_status":200,
 "body":"<html><body>solve me</body></html>",
 "cookies":["__crowdsec_challenge=abc; Path=/; HttpOnly"],
 "headers":{"Content-Type":["text/html"]}}
JSON
}

# --- the local API's ban ------------------------------------------------

@test "control: a banned client is refused under the default Satisfy All" {
    apache_start "$(lapi_conf)"
    run harness_request
    [ "$output" = 429 ]
}

@test "Satisfy Any does not let a banned client through" {
    apache_start "$(lapi_conf 'Satisfy Any')"
    run harness_request
    [ "$output" = 429 ]
    run cat "$HARNESS_DIR/resp.body"
    [[ "$output" != *"origin-ok"* ]]
}

@test "Satisfy Any with an Allow the banned client passes still refuses it" {
    # The office-or-password recipe. Under Satisfy Any a passing access check
    # ends the access phase early, so a verdict anywhere in that phase - not
    # just in access_checker - is skipped for a client inside the Allow.
    harness_passwd alice secret
    apache_start "$(lapi_conf "Order deny,allow
    Deny from all
    Allow from 127.0.0.1
    AuthType Basic
    AuthName test
    AuthUserFile $HARNESS_DIR/passwd
    Require valid-user
    Satisfy Any")"
    run harness_request
    [ "$output" = 429 ]
}

@test "Satisfy Any with valid credentials does not let a banned client through" {
    harness_passwd alice secret
    apache_start "$(lapi_conf "AuthType Basic
    AuthName test
    AuthUserFile $HARNESS_DIR/passwd
    Require valid-user
    Satisfy Any")"
    run harness_request "" -u alice:secret
    [ "$output" = 429 ]
}

@test "Satisfy Any from an .htaccess does not let a banned client through" {
    # The one route that needs no access to the server config.
    echo 'Satisfy Any' > "$HARNESS_DIR/htdocs/.htaccess"
    apache_start "$(lapi_conf '' "<Directory \"$HARNESS_DIR/htdocs\">
    AllowOverride AuthConfig
</Directory>")"
    run harness_request
    [ "$output" = 429 ]
}

@test "control: RequireAny refuses a banned client" {
    harness_passwd alice secret
    apache_start "$(lapi_conf "AuthType Basic
    AuthName test
    AuthUserFile $HARNESS_DIR/passwd
    <RequireAny>
        Require ip 127.0.0.1
        Require valid-user
    </RequireAny>" "LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so")"
    run harness_request
    [ "$output" = 429 ]
}

# --- AppSec -------------------------------------------------------------

@test "Satisfy Any does not let a WAF block through" {
    appsec_set '{"status":403,"action":"ban","http_status":403}'
    apache_start "$(appsec_conf 'Satisfy Any')"
    run harness_request
    [ "$output" = 429 ]
    run cat "$HARNESS_DIR/resp.body"
    [[ "$output" != *"origin-ok"* ]]
}

@test "under Satisfy Any the challenge is the whole response, framed correctly" {
    # The interstitial is written and DONE returned. Read as "not passed", the
    # handler ran as well and the origin's page went out appended to the
    # challenge, inside one response: the challenged client got the content.
    # The framing checks are here because a body written from two places is
    # where a Content-Length mismatch, and a desynced keep-alive, would come
    # from.
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf 'Satisfy Any')"
    run python3 - "$APACHE_PORT" <<'PYEOF'
import socket, sys

s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"

def response():
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(65536)
        if not c:
            sys.exit("connection closed in headers")
        buf += c
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    hdr = {k.lower(): v.strip() for k, v in
           (l.split(":", 1) for l in lines[1:] if ":" in l)}
    n = int(hdr["content-length"])
    while len(rest) < n:
        c = s.recv(65536)
        if not c:
            sys.exit("connection closed in body")
        rest += c
    return lines[0], rest[:n], rest[n:]

s.sendall(req)
status, body, extra = response()
print("status1:", status)
print("body1:", body.decode("latin1"))
# Anything past Content-Length before we ask again is a framing error.
s.settimeout(1)
try:
    extra += s.recv(65536)
except socket.timeout:
    pass
print("extra:", len(extra))
s.settimeout(5)
s.sendall(req)
status, _, _ = response()
print("status2:", status)
PYEOF
    [ "$status" -eq 0 ]
    [[ "$output" == *"status1: HTTP/1.1 200"* ]]
    [[ "$output" == *$'body1: <html><body>solve me</body></html>\n'* ]]
    [[ "$output" == *"extra: 0"* ]]
    [[ "$output" == *"status2: HTTP/1.1 200"* ]]
    [[ "$output" != *"origin-ok"* ]]
}

@test "under Satisfy Any the challenge prefix still never reaches the origin" {
    mkdir -p "$HARNESS_DIR/htdocs/crowdsec-internal/challenge"
    echo origin-asset > "$HARNESS_DIR/htdocs/crowdsec-internal/challenge/x"
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf '' "<Directory \"$HARNESS_DIR/htdocs\">
    Satisfy Any
</Directory>")"
    run harness_request crowdsec-internal/challenge/x
    [ "$output" = 404 ]
    run cat "$HARNESS_DIR/resp.body"
    [[ "$output" != *"origin-asset"* ]]
}

@test "under Satisfy Any an allowed POST still reaches the handler whole" {
    mkdir -p "$HARNESS_DIR/cgi"
    cat > "$HARNESS_DIR/cgi/echo" <<'CGI'
#!/usr/bin/env python3
import hashlib, sys
data = sys.stdin.buffer.read()
print("Content-Type: text/plain")
print()
print("len=%d" % len(data))
print("md5=%s" % hashlib.md5(data).hexdigest())
CGI
    chmod +x "$HARNESS_DIR/cgi/echo"
    head -c 100000 /dev/urandom > "$HARNESS_DIR/payload"
    want="md5=$(md5sum "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf 'Satisfy Any' "LoadModule cgid_module /usr/lib/apache2/modules/mod_cgid.so
ScriptAlias /echo \"$HARNESS_DIR/cgi/echo\"
<Directory \"$HARNESS_DIR/cgi\">
    Require all granted
    Options +ExecCGI
</Directory>")"
    run curl -s --max-time 15 -X POST --data-binary "@$HARNESS_DIR/payload" \
        "http://127.0.0.1:$APACHE_PORT/echo"
    [[ "$output" == *"len=100000"* ]]
    [[ "$output" == *"$want"* ]]
    [ "$(appsec_seen body_len)" = 100000 ]
}
