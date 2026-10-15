#!/usr/bin/env bats
# Stream mode end to end: a real Apache, a stub local API, and the shared
# decision cache.

load "../lib/harness.sh"

BIG_CACHE="shmcb:crowdsec-test(8388608)"

setup() {
    harness_init
    lapi_api_start
}

teardown() {
    harness_cleanup
}

stream_conf() {
    cat <<CONF
CrowdsecMode stream
CrowdsecUpdateFrequency 1s
CrowdsecCache $BIG_CACHE
CrowdsecCacheTimeout 1s
CrowdsecFallback allow
Crowdsec On
$1
CONF
}

@test "a single-ip decision blocks that address" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]
}

@test "a clean address is not blocked" {
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 200 ]
}

@test "a range decision blocks an address inside it and not outside" {
    # 127.0.0.0/24 contains the client; 10.0.0.0/24 does not
    lapi_set "{\"decisions\":[$(decision 127.0.0.0/24 Range)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]

    lapi_set "{\"decisions\":[$(decision 10.0.0.0/24 Range)],\"sticky\":true}"
    harness_cleanup_apache
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 200 ]
}

@test "a non-byte-aligned range is matched correctly" {
    # /25 covers 127.0.0.0-127.0.0.127, which includes .1
    lapi_set "{\"decisions\":[$(decision 127.0.0.0/25 Range)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]
}

@test "a range that excludes the client by one bit does not block" {
    # /25 of the upper half covers .128-.255, so .1 must pass
    lapi_set "{\"decisions\":[$(decision 127.0.0.128/25 Range)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 200 ]
}

@test "deleting a decision unblocks the address" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]

    # stop repeating the ban, and report it as deleted
    lapi_set "{\"decisions\":[],\"deleted\":[$(decision 127.0.0.1 Ip)]}"
    sleep 3
    # the in-process memo has a 1s ttl, so this is the cache being updated
    [ "$(http_status)" = 200 ]
}

@test "an expired decision is never stored" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip -5s)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 200 ]
}

@test "a short decision stops blocking once it lapses" {
    # Deliberately not sticky: a repeated decision would be re-stored with a
    # fresh expiry on every poll and could never lapse, which is also what the
    # real API does while a ban is still live.
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip 2s)]}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]
    # the entry carries the decision's own duration as its cache expiry, so it
    # disappears without anyone deleting it
    sleep 6
    [ "$(http_status)" = 200 ]
}

@test "country scope is reported once and not enforced" {
    lapi_set "{\"decisions\":[$(decision FR Country)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 200 ]
}

@test "the first pull asks for the full set" {
    lapi_set "{\"decisions\":[],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(lapi_get startup_seen)" -ge 1 ]
}

@test "before the first pull completes, CrowdsecFallback decides" {
    # the api stalls, so the module serves requests unprimed
    lapi_set '{"decisions":[],"delay":6,"sticky":true}'
    apache_start "$(stream_conf 'CrowdsecFallback block')"
    # no wait_primed: that is the point
    [ "$(http_status)" = 429 ]
}

@test "unprimed with fallback allow lets requests through" {
    lapi_set '{"decisions":[],"delay":6,"sticky":true}'
    apache_start "$(stream_conf 'CrowdsecFallback allow')"
    [ "$(http_status)" = 200 ]
}

@test "unprimed with fallback fail returns 500" {
    lapi_set '{"decisions":[],"delay":6,"sticky":true}'
    apache_start "$(stream_conf 'CrowdsecFallback fail')"
    [ "$(http_status)" = 500 ]
}

@test "stream mode refuses to start without a cache" {
    lapi_set '{}'
    run apache_start "CrowdsecMode stream
Crowdsec On"
    [ "$status" -ne 0 ]
    grep -q "requires CrowdsecCache" "$HARNESS_DIR/logs/error.log"
}

@test "polling continues across several intervals" {
    lapi_set "{\"decisions\":[],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    first="$(lapi_get pulls)"
    sleep 3
    second="$(lapi_get pulls)"
    [ "$second" -gt "$first" ]
}
