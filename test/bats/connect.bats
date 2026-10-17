#!/usr/bin/env bats
# A decision must not be shed by changing the method.
#
# CONNECT used to be declined on the method alone, on the assumption that a
# CONNECT is always a forward-proxy request. With ProxyRequests off it is not:
# Apache leaves proxyreq as PROXYREQ_NONE, resolves the target against the
# document root, and hands it to whatever handler matches - so a banned client
# that swapped GET for CONNECT was served local content with no lookup and no
# inspection.
#
# What Apache does after the module declines depends on the handler, which is
# why the bug was invisible here before: the static core handler answers 405,
# while proxy_fcgi - any PHP deployment - runs the script and answers 200. The
# tests below pin the module's own behaviour instead.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
    appsec_start
}

teardown() {
    harness_cleanup
}

CONNECT_REQ=$'CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'

stream_conf() {
    cat <<CONF
CrowdsecMode stream
CrowdsecUpdateFrequency 1s
CrowdsecCache shmcb:crowdsec-connect$1(4194304)
CrowdsecCacheTimeout 1s
CrowdsecFallback allow
Crowdsec On
CONF
}

@test "a banned client is not released by CONNECT" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf a)
CrowdsecBlockedHTTPCode 403"
    wait_primed
    [ "$(http_status)" = 403 ]
    run raw_request "$CONNECT_REQ"
    [[ "$output" == *" 403 "* ]]
    [[ "$output" != *origin-ok* ]]
}

@test "an unbanned CONNECT is refused, not handed to the origin handler" {
    # The module now reaches a verdict and refuses: an authority-form target is
    # not something it can express for inspection, so crowdsec_target_ok
    # rejects it and the request ends in 400. Before the fix the module
    # declined and Apache's handler table decided - 405 here, 200 under PHP.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecCacheTimeout 1s
Crowdsec Off
CrowdsecAppsec On"
    run raw_request "$CONNECT_REQ"
    [[ "$output" == *" 400 "* ]]
    [[ "$output" != *origin-ok* ]]
}

@test "an invented method is still gated" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf b)
CrowdsecBlockedHTTPCode 403"
    wait_primed
    run raw_request $'FOOBAR / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
    [[ "$output" == *" 403 "* ]]
}

@test "a clean client is unaffected" {
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf c)"
    wait_primed
    [ "$(http_status)" = 200 ]
}
