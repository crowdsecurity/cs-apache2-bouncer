#!/usr/bin/env bats
# Request bodies: forwarding them for inspection, putting them back for the
# real handler, and the limit.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
    appsec_start
    # A CGI that reports what it actually received, so "the handler still sees
    # the body" is measured rather than assumed.
    mkdir -p "$HARNESS_DIR/cgi"
    cat > "$HARNESS_DIR/cgi/echo" <<'CGI'
#!/usr/bin/env python3
import hashlib, os, sys
# Read to EOF rather than trusting CONTENT_LENGTH: a chunked request has none,
# and the point of these tests is what actually arrives.
data = sys.stdin.buffer.read()
print("Content-Type: text/plain")
print()
print("len=%d" % len(data))
print("md5=%s" % hashlib.md5(data).hexdigest())
CGI
    chmod +x "$HARNESS_DIR/cgi/echo"
}

teardown() {
    harness_cleanup
}

body_conf() {
    cat <<CONF
LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so
LoadModule cgid_module /usr/lib/apache2/modules/mod_cgid.so
ScriptAlias /echo "$HARNESS_DIR/cgi/echo"
<Directory "$HARNESS_DIR/cgi">
    Require all granted
    Options +ExecCGI
</Directory>
CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecCacheTimeout 1s
Crowdsec Off
CrowdsecAppsec On
$1
CONF
}

post_echo() {
    curl -s --max-time 15 -X POST --data-binary "@$1" \
        "http://127.0.0.1:$APACHE_PORT/echo"
}

@test "a small body is inspected and still reaches the handler intact" {
    # This is the one that breaks PHP if it is wrong: we consume the body to
    # inspect it, so it has to be put back.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf)"
    head -c 4096 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run post_echo "$HARNESS_DIR/payload"
    [[ "$output" == *"len=4096"* ]]
    [[ "$output" == *"md5=$want"* ]]
    [ "$(appsec_seen body_len)" = 4096 ]
}

@test "a 64k body round-trips byte for byte" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf)"
    head -c 65536 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run post_echo "$HARNESS_DIR/payload"
    [[ "$output" == *"len=65536"* ]]
    [[ "$output" == *"md5=$want"* ]]
    [ "$(appsec_seen body_len)" = 65536 ]
}

@test "the handler still gets the body when the request was not inspected" {
    # appsec off: nothing consumes the body, so this is the control for the
    # test above.
    apache_start "$(body_conf 'CrowdsecAppsec Off')"
    head -c 4096 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run post_echo "$HARNESS_DIR/payload"
    [[ "$output" == *"md5=$want"* ]]
}

@test "a body over the limit is blocked by default" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf 'CrowdsecAppsecBodyLimit 8k')"
    head -c 65536 /dev/urandom > "$HARNESS_DIR/payload"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST \
        --data-binary "@$HARNESS_DIR/payload" \
        "http://127.0.0.1:$APACHE_PORT/echo"
    [ "$output" = 429 ]
    grep -q "exceeds CrowdsecAppsecBodyLimit" "$HARNESS_DIR/logs/error.log"
}

@test "bypass lets an oversized body through and the handler still gets all of it" {
    # The documented bypass: anyone can evade inspection by padding. The
    # handler must still receive the whole body, prefix and remainder both.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf 'CrowdsecAppsecBodyLimit 8k
CrowdsecAppsecBodyLimitAction bypass')"
    head -c 65536 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run post_echo "$HARNESS_DIR/payload"
    [[ "$output" == *"len=65536"* ]]
    [[ "$output" == *"md5=$want"* ]]
    grep -q "is NOT inspected" "$HARNESS_DIR/logs/error.log"
}

@test "a body exactly at the limit is inspected, not dropped" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf 'CrowdsecAppsecBodyLimit 8192')"
    head -c 8192 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run post_echo "$HARNESS_DIR/payload"
    [[ "$output" == *"md5=$want"* ]]
    [ "$(appsec_seen body_len)" = 8192 ]
}

@test "a limit of zero forwards no body but still inspects the request" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf 'CrowdsecAppsecBodyLimit 0')"
    head -c 4096 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run post_echo "$HARNESS_DIR/payload"
    # the handler is unaffected
    [[ "$output" == *"md5=$want"* ]]
    # and the engine saw the request, just not its body
    [ "$(appsec_calls)" -ge 1 ]
    [ "$(appsec_seen body_len)" = 0 ]
    [ "$(appsec_seen method)" = "GET" ]
}

@test "a body-borne payload can be blocked" {
    # The reason body inspection exists at all.
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    apache_start "$(body_conf)"
    printf 'q=%s' "' OR 1=1--" > "$HARNESS_DIR/payload"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST \
        --data-binary "@$HARNESS_DIR/payload" \
        "http://127.0.0.1:$APACHE_PORT/echo"
    [ "$output" = 429 ]
    [ "$(appsec_seen body_len)" -gt 0 ]
}

@test "a chunked body with no Content-Length is inspected and replayed" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf)"
    head -c 20000 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    run curl -s --max-time 15 -X POST -H "Transfer-Encoding: chunked" \
        --data-binary "@$HARNESS_DIR/payload" \
        "http://127.0.0.1:$APACHE_PORT/echo"
    [[ "$output" == *"md5=$want"* ]]
    [ "$(appsec_seen body_len)" = 20000 ]
}

@test "LimitRequestBody still applies and reports 413" {
    # Apache's own limit lives below ours, and the status for hitting it has
    # to come through rather than being reported as a generic failure.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf 'LimitRequestBody 1024')"
    head -c 4096 /dev/urandom > "$HARNESS_DIR/payload"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST \
        --data-binary "@$HARNESS_DIR/payload" \
        "http://127.0.0.1:$APACHE_PORT/echo"
    [ "$output" = 413 ]
}

@test "a gzipped body is inflated for the handler" {
    # Our replay filter sits in front of HTTP_IN rather than at resource
    # level, so anything that transforms the body between the handler and the
    # protocol still runs. At the wrong priority the handler would receive raw
    # compressed bytes.
    [ -f /usr/lib/apache2/modules/mod_deflate.so ] || skip "no mod_deflate"
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(body_conf 'LoadModule deflate_module /usr/lib/apache2/modules/mod_deflate.so
<Location /echo>
    SetInputFilter DEFLATE
</Location>')"
    head -c 10000 /dev/urandom > "$HARNESS_DIR/payload"
    want="$(md5sum < "$HARNESS_DIR/payload" | cut -d' ' -f1)"
    gzip -c "$HARNESS_DIR/payload" > "$HARNESS_DIR/payload.gz"
    run curl -s --max-time 15 -X POST -H "Content-Encoding: gzip" \
        --data-binary "@$HARNESS_DIR/payload.gz" \
        "http://127.0.0.1:$APACHE_PORT/echo"
    # the handler must see the plaintext
    [[ "$output" == *"md5=$want"* ]]
}
