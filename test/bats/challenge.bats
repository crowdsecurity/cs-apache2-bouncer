#!/usr/bin/env bats
# The bot-detection challenge: relaying the interstitial, its cookies and
# headers, the internal endpoints, and the ways it must fail closed.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
    appsec_start
}

teardown() {
    harness_cleanup
}

appsec_conf() {
    cat <<CONF
CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecCacheTimeout 1s
Crowdsec Off
CrowdsecAppsec On
$1
CONF
}

# A challenge verdict with a body, two cookies and a CSP.
challenge_state() {
    cat <<'JSON'
{"status":403,"action":"challenge","http_status":200,
 "body":"<html><body>solve me</body></html>",
 "cookies":["__crowdsec_challenge=abc; Path=/; HttpOnly; SameSite=Lax",
            "__crowdsec_other=def; Path=/"],
 "headers":{"Content-Security-Policy":["default-src 'self'; script-src 'self' 'unsafe-inline'"],
            "Cache-Control":["no-cache, no-store"],
            "Content-Type":["text/html"]}}
JSON
}

@test "the interstitial is served with the browser's status, not ours" {
    # We receive 403; the browser must get http_status, which is 200 here.
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf)"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/"
    [ "$output" = 200 ]
}

@test "the interstitial body is what reaches the client" {
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf)"
    run curl -s --max-time 10 "http://127.0.0.1:$APACHE_PORT/"
    [[ "$output" == *"solve me"* ]]
    # and not the origin's page
    [[ "$output" != *"origin-ok"* ]]
}

@test "each cookie is its own Set-Cookie header" {
    # Comma-joining them would corrupt the attributes, and overwriting would
    # lose all but the last.
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf)"
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/' | grep -ci '^set-cookie:'"
    [ "$output" = 2 ]
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/' | grep -i '^set-cookie:' | head -1"
    [[ "$output" == *"__crowdsec_challenge=abc"* ]]
    [[ "$output" == *"HttpOnly"* ]]
}

@test "the engine's CSP replaces the operator's, it does not join it" {
    # The two header tables are merged by concatenation with no
    # de-duplication, so both would go on the wire and the browser would
    # enforce their intersection, giving a blank page.
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf)
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
Header always set Content-Security-Policy \"default-src 'none'\""
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/' | grep -ci '^content-security-policy:'"
    [ "$output" = 1 ]
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/' | grep -i '^content-security-policy:'"
    [[ "$output" == *"unsafe-inline"* ]]
    [[ "$output" != *"'none'"* ]]
}

@test "the content type comes from the engine" {
    # A table entry would be silently overwritten from r->content_type, which
    # is NULL this early, leaving no Content-Type at all and the browser
    # sniffing.
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf)"
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/' | grep -i '^content-type:'"
    [[ "$output" == *"text/html"* ]]
}

@test "a javascript asset keeps its own content type" {
    appsec_set '{"status":403,"action":"challenge","http_status":200,
                "body":"console.log(1)",
                "headers":{"Content-Type":["application/javascript"]}}'
    apache_start "$(appsec_conf)"
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/crowdsec-internal/challenge/pow-worker.js' | grep -i '^content-type:'"
    [[ "$output" == *"application/javascript"* ]]
}

@test "a 307 with a Location is relayed as a redirect" {
    # Granting a challenge cookie answers 307, so assuming 200 would break it.
    appsec_set '{"status":403,"action":"challenge","http_status":307,
                "body":"redirecting",
                "cookies":["__crowdsec_challenge=ok; Path=/"],
                "headers":{"Location":["/welcome"]}}'
    apache_start "$(appsec_conf)"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/"
    [ "$output" = 307 ]
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/' | grep -i '^location:'"
    [[ "$output" == *"/welcome"* ]]
}

@test "a challenge with no body fails closed to a block" {
    # Only the engine can produce a challenge page. Nothing to serve means the
    # request must not be let through.
    appsec_set '{"status":403,"action":"challenge","http_status":200}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 429 ]
    grep -q "could not be served; blocking instead" \
        "$HARNESS_DIR/logs/error.log"
}

@test "the challenge endpoints are inspected even where Crowdsec is off" {
    # These live outside whatever <Location> enabled appsec, so without the
    # carve-out the origin would 404 them and a challenged visitor would be
    # stuck for good.
    appsec_set "$(challenge_state)"
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec Off
CrowdsecAppsec Off"
    for p in challenge.js pow-worker.js fpscanner.js custom.js submit; do
        run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
            "http://127.0.0.1:$APACHE_PORT/crowdsec-internal/challenge/$p"
        [ "$output" = 200 ]
    done
    [ "$(appsec_calls)" -ge 5 ]
}

@test "the whole prefix is carved out, not just today's endpoint names" {
    # Matching the engine's individual asset names would leave a route it
    # gains later unforwarded, and a challenged visitor waiting for it.
    appsec_set "$(challenge_state)"
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec Off
CrowdsecAppsec Off"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/crowdsec-internal/challenge/anything-else"
    [ "$output" = 200 ]
    [ "$(appsec_calls)" -ge 1 ]
}

@test "the carve-out stops at the prefix" {
    # The prefix ends in a slash, so a sibling directory is not carved out and
    # a per-directory off still holds there.
    appsec_set "$(challenge_state)"
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec Off
CrowdsecAppsec Off"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/crowdsec-internal/challenge-elsewhere/submit"
    [ "$output" = 404 ]
    [ "$(appsec_calls)" = 0 ]
}

@test "a traversal cannot dodge the carve-out check" {
    appsec_set "$(challenge_state)"
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec Off
CrowdsecAppsec Off"
    # r->uri is already decoded and collapsed when the check runs
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 --path-as-is \
        "http://127.0.0.1:$APACHE_PORT/x/../crowdsec-internal/challenge/submit"
    [ "$output" = 200 ]
    [ "$(appsec_calls)" -ge 1 ]
}

@test "a path under the prefix the engine declines is refused, not proxied" {
    # If the engine says allow for one of its own endpoints, the origin still
    # has nothing to serve there, so passing it on would be wrong.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec Off
CrowdsecAppsec Off"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/crowdsec-internal/challenge/submit"
    [ "$output" = 404 ]
    grep -q "did not answer it" "$HARNESS_DIR/logs/error.log"
}

@test "the submit endpoint is forwarded as a POST with its body" {
    appsec_set '{"status":403,"action":"challenge","http_status":200,
                "body":"{\"status\":\"ok\"}",
                "cookies":["__crowdsec_challenge=solved; Path=/"],
                "headers":{"Content-Type":["application/json"]}}'
    apache_start "$(appsec_conf)"
    run curl -s --max-time 10 -X POST \
        --data "f=abc&r=0123456789abcdef0123456789abcdef&n=1" \
        "http://127.0.0.1:$APACHE_PORT/crowdsec-internal/challenge/submit"
    [[ "$output" == *'"status":"ok"'* ]]
    [ "$(appsec_seen method)" = "POST" ]
    [ "$(appsec_seen body_len)" -gt 30 ]
}

@test "a relayed cookie lets the next request through" {
    # The module never parses or mints these; it relays them and keeps
    # forwarding the browser's Cookie header, which is how a solved challenge
    # is recognised.
    appsec_set "$(challenge_state)"
    apache_start "$(appsec_conf)"
    cookiejar="$HARNESS_DIR/jar"
    curl -s -o /dev/null -c "$cookiejar" --max-time 10 \
        "http://127.0.0.1:$APACHE_PORT/"
    grep -q "__crowdsec_challenge" "$cookiejar"

    # now the engine accepts the solved client
    appsec_set '{"action":"allow","http_status":200}'
    run curl -s -b "$cookiejar" --max-time 10 "http://127.0.0.1:$APACHE_PORT/"
    [[ "$output" == *"origin-ok"* ]]
    # and the cookie really was forwarded for inspection
    [[ "$(appsec_header Cookie)" == *"__crowdsec_challenge"* ]]
}

@test "a header the engine must not set is dropped" {
    appsec_set '{"status":403,"action":"challenge","http_status":200,
                "body":"x",
                "headers":{"Server":["evil/1.0"],"Transfer-Encoding":["chunked"],
                           "X-Fine":["kept"]}}'
    apache_start "$(appsec_conf)"
    run bash -c "curl -sD- -o /dev/null --max-time 10 'http://127.0.0.1:$APACHE_PORT/'"
    [[ "$output" == *"X-Fine: kept"* ]]
    [[ "$output" != *"evil/1.0"* ]]
}
