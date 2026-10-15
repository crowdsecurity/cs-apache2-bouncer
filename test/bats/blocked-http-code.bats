#!/usr/bin/env bats
# CrowdsecBlockedHTTPCode has no default in the config creator, and Apache's
# OK is 0 - so an unset directive used to let banned IPs straight through.

load "../lib/harness.sh"

BANNED='[{"duration":"1h","id":1,"origin":"cscli","scenario":"manual","scope":"Ip","type":"ban","value":"127.0.0.1"}]'

setup() {
    harness_init
}

teardown() {
    harness_cleanup
}

@test "banned ip is blocked when CrowdsecBlockedHTTPCode is unset" {
    lapi_start "$BANNED"
    apache_start "Crowdsec On"
    # 429 is the documented default. The bug returned 200.
    [ "$(http_status)" = 429 ]
}

@test "banned ip is blocked with an explicit CrowdsecBlockedHTTPCode" {
    lapi_start "$BANNED"
    apache_start "Crowdsec On
CrowdsecBlockedHTTPCode 403"
    [ "$(http_status)" = 403 ]
}

@test "clean ip reaches the origin when CrowdsecBlockedHTTPCode is unset" {
    lapi_start "null"
    apache_start "Crowdsec On"
    [ "$(http_status)" = 200 ]
}

@test "module declines when Crowdsec is off" {
    lapi_start "$BANNED"
    apache_start "Crowdsec Off"
    [ "$(http_status)" = 200 ]
}
