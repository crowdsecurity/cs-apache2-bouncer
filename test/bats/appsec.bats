#!/usr/bin/env bats
# AppSec: what gets forwarded, what each verdict does, and the body limit.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
    appsec_start
}

teardown() {
    harness_cleanup
}

# AppSec on, local API decisions off, so each test isolates one thing.
appsec_conf() {
    cat <<CONF
CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecCacheTimeout 1s
Crowdsec Off
CrowdsecAppsec On
$1
CONF
}

@test "allow lets the request reach the origin" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 200 ]
    [ "$(appsec_calls)" -ge 1 ]
}

@test "ban blocks with the configured code" {
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    apache_start "$(appsec_conf 'CrowdsecBlockedHTTPCode 403')"
    [ "$(http_status)" = 403 ]
}

@test "ban uses 429 when no code is configured" {
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 429 ]
}

@test "the raw request target is forwarded, not the normalised one" {
    # By this phase Apache has already percent-decoded r->uri and collapsed
    # its ".." segments, and r->uri never held the query string at all. Each
    # of these would come out different if we sent that instead:
    #   /a/../b    -> /b        (collapsed)
    #   /sp%20ace  -> /sp ace   (decoded)
    #   ?x=1&y=%41 -> gone
    # and the engine takes its arguments from this header, not from the URL we
    # connect to.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"

    curl -s -o /dev/null --max-time 10 --path-as-is \
        "http://127.0.0.1:$APACHE_PORT/a/../b?x=1&y=%41"
    [ "$(appsec_seen uri)" = "/a/../b?x=1&y=%41" ]

    curl -s -o /dev/null --max-time 10 "http://127.0.0.1:$APACHE_PORT/sp%20ace"
    [ "$(appsec_seen uri)" = "/sp%20ace" ]
}

@test "an encoded slash is refused by Apache before we see it" {
    # AllowEncodedSlashes is off by default, so Apache answers these itself.
    # Worth pinning: it means such a request reaches neither AppSec nor the
    # origin, rather than being inspected in a normalised form.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 --path-as-is \
        "http://127.0.0.1:$APACHE_PORT/a/%2e%2e%2fb"
    [ "$output" = 404 ]
    [ "$(appsec_calls)" = 0 ]
}

@test "the control headers carry the client's details" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 -H "User-Agent: probe/1.0" \
        -H "Host: example.test" "http://127.0.0.1:$APACHE_PORT/"
    [ "$(appsec_seen ip)" = "127.0.0.1" ]
    [ "$(appsec_seen verb)" = "GET" ]
    [ "$(appsec_seen ua)" = "probe/1.0" ]
    # the Host as the client wrote it, not Apache's lowercased hostname
    [ "$(appsec_seen host)" = "example.test" ]
    # exactly two digits, per the protocol
    [ "$(appsec_seen version)" = "11" ]
}

@test "the client's own headers are forwarded verbatim" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 -H "X-Probe: value" \
        -H "Cookie: a=1" "http://127.0.0.1:$APACHE_PORT/"
    [ "$(appsec_header X-Probe)" = "value" ]
    # the Cookie header must keep flowing or a solved challenge is forgotten
    [ "$(appsec_header Cookie)" = "a=1" ]
}

@test "curl's own headers are suppressed so the fingerprint is not perturbed" {
    # Each header libcurl adds changes the set and count the engine hashes, so
    # the same request relayed by this module would fingerprint differently
    # from one relayed by any other component.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 --header "Accept:" \
        "http://127.0.0.1:$APACHE_PORT/"
    [ "$(appsec_has_header Accept)" = no ]
    [ "$(appsec_has_header Expect)" = no ]
    [ "$(appsec_has_header Content-Type)" = no ]
}

@test "a client cannot set the control headers itself" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 \
        -H "X-Crowdsec-Appsec-Ip: 1.2.3.4" \
        -H "X-Crowdsec-Appsec-Uri: /spoofed" \
        "http://127.0.0.1:$APACHE_PORT/real"
    [ "$(appsec_seen ip)" = "127.0.0.1" ]
    [ "$(appsec_seen uri)" = "/real" ]
}

@test "a request with no body is forwarded as GET" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 "http://127.0.0.1:$APACHE_PORT/"
    [ "$(appsec_seen method)" = "GET" ]
    [ "$(appsec_seen body_len)" = 0 ]
}

@test "a request with a body is forwarded as POST with the body" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 -X POST --data "name=value&x=1" \
        "http://127.0.0.1:$APACHE_PORT/"
    [ "$(appsec_seen method)" = "POST" ]
    [ "$(appsec_seen body_len)" = 14 ]
    # the inspected verb is the client's, carried in the header
    [ "$(appsec_seen verb)" = "POST" ]
}

@test "an unusual method is forwarded, not rejected" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    curl -s -o /dev/null --max-time 10 -X PROPFIND \
        "http://127.0.0.1:$APACHE_PORT/"
    [ "$(appsec_seen verb)" = "PROPFIND" ]
}

@test "captcha becomes a ban by default, since none can be served" {
    appsec_set '{"action":"captcha","http_status":403,"status":403}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 429 ]
}

@test "captcha can be configured to allow instead" {
    appsec_set '{"action":"captcha","http_status":403,"status":403}'
    apache_start "$(appsec_conf 'CrowdsecRemediationFallback allow')"
    [ "$(http_status)" = 200 ]
}

@test "a 200 carrying captcha is still acted on" {
    # default_pass_action makes this real: the status says pass, the body does
    # not, so the body has to be parsed even on a 200.
    appsec_set '{"action":"captcha","http_status":200,"status":200}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 429 ]
}

@test "an action we do not recognise is not treated as allow" {
    appsec_set '{"action":"shenanigans","http_status":403,"status":403}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 429 ]
}

@test "appsec unreachable passes through by default" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    kill "$APPSEC_PID" 2>/dev/null; unset APPSEC_PID
    sleep 0.3
    [ "$(http_status)" = 200 ]
}

@test "appsec unreachable can be configured to deny" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf 'CrowdsecAppsecFailureAction deny')"
    kill "$APPSEC_PID" 2>/dev/null; unset APPSEC_PID
    sleep 0.3
    [ "$(http_status)" = 429 ]
}

@test "a rejected api key is a failure, not a verdict" {
    appsec_set '{"require_key":"the-real-key"}'
    apache_start "$(appsec_conf 'CrowdsecAppsecFailureAction deny')"
    [ "$(http_status)" = 429 ]
    grep -q "appsec returned 401" "$HARNESS_DIR/logs/error.log"
}

@test "a wrong path reports 404 with a hint" {
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf 'CrowdsecAppsecFailureAction deny')"
    # the stub answers everything, so force a 404 instead
    appsec_set '{"status":404}'
    [ "$(http_status)" = 429 ]
    grep -q "CrowdsecAppsecPath" "$HARNESS_DIR/logs/error.log"
}

@test "a slow appsec hits its own timeout, not Apache's" {
    appsec_set '{"action":"allow","http_status":200,"delay":4}'
    apache_start "$(appsec_conf 'CrowdsecAppsecTimeout 400ms')"
    start=$(date +%s)
    code="$(http_status)"
    elapsed=$(( $(date +%s) - start ))
    [ "$code" = 200 ]
    [ "$elapsed" -lt 3 ]
}

@test "an unparseable 403 blocks rather than failing open" {
    # The engine decided something; a body we cannot read must not become a
    # bypass.
    appsec_set '{"status":403,"raw":"this is not json"}'
    apache_start "$(appsec_conf)"
    [ "$(http_status)" = 429 ]
}

@test "an unparseable 200 is a failure, not a block" {
    appsec_set '{"status":200,"raw":"this is not json"}'
    apache_start "$(appsec_conf 'CrowdsecAppsecFailureAction passthrough')"
    [ "$(http_status)" = 200 ]
}

@test "appsec is skipped for an address the local api already bans" {
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecCacheTimeout 1s
CrowdsecMode live
CrowdsecFallback allow
Crowdsec On
CrowdsecAppsec On"
    [ "$(http_status)" = 429 ]
    # nothing is gained by inspecting a request that is refused anyway
    [ "$(appsec_calls)" = 0 ]
}

@test "AlwaysSend inspects even an already-banned address" {
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecCacheTimeout 1s
CrowdsecMode live
CrowdsecFallback allow
Crowdsec On
CrowdsecAppsec On
CrowdsecAppsecAlwaysSend On"
    [ "$(http_status)" = 429 ]
    [ "$(appsec_calls)" -ge 1 ]
}

@test "appsec off means no inspection" {
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec Off
CrowdsecAppsec Off"
    [ "$(http_status)" = 200 ]
    [ "$(appsec_calls)" = 0 ]
}
