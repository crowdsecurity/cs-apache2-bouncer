#!/usr/bin/env bats
# Live mode: one API query per request, no cache required. This is the default,
# so it is also the upgrade-compatibility path.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
}

teardown() {
    harness_cleanup
}

live_conf() {
    cat <<CONF
CrowdsecCacheTimeout 1s
CrowdsecFallback allow
Crowdsec On
$1
CONF
}

@test "live mode is the default, so no CrowdsecMode is needed" {
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    apache_start "$(live_conf)"
    [ "$(http_status)" = 429 ]
    [ "$(status_field mode)" = live ]
}

@test "a decision for the client blocks it" {
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    apache_start "$(live_conf 'CrowdsecMode live')"
    [ "$(http_status)" = 429 ]
}

@test "no decisions lets the request through" {
    lapi_set '{"live":[]}'
    apache_start "$(live_conf 'CrowdsecMode live')"
    [ "$(http_status)" = 200 ]
}

@test "an empty array is not a ban" {
    # The old code compared the body against the string "null", so an empty
    # array, or whitespace around null, read as a decision and blocked.
    lapi_set '{"live":[]}'
    apache_start "$(live_conf 'CrowdsecMode live')"
    [ "$(http_status)" = 200 ]
}

@test "live mode needs no cache" {
    lapi_set '{"live":[]}'
    apache_start "$(live_conf 'CrowdsecMode live')"
    [ "$(status_field cache)" = no ]
    [ "$(http_status)" = 200 ]
}

@test "an api error applies CrowdsecFallback" {
    lapi_set '{"status":500}'
    apache_start "$(live_conf 'CrowdsecMode live
CrowdsecFallback block')"
    [ "$(http_status)" = 429 ]
}

@test "an api error with fallback allow lets requests through" {
    lapi_set '{"status":500}'
    apache_start "$(live_conf 'CrowdsecMode live
CrowdsecFallback allow')"
    [ "$(http_status)" = 200 ]
}

@test "an unreachable api applies CrowdsecFallback" {
    apache_start "CrowdsecCacheTimeout 1s
CrowdsecMode live
CrowdsecFallback fail
Crowdsec On"
    # kill the api after apache has started
    kill "$LAPI_PID" 2>/dev/null
    unset LAPI_PID
    [ "$(http_status)" = 500 ]
}

@test "the per-child memo cannot outlive the shared entry it came from" {
    # Live mode chains two caches: the shared one, then a per-child memo seeded
    # from it. An uncapped memo keeps serving a verdict after the shared entry
    # it was copied from has expired, making the worst case twice
    # CrowdsecCacheTimeout. The memo is capped at the shared lifetime, so
    # asking for 60s here yields 1s.
    lapi_set '{"live":null}'
    apache_start "$(live_conf '
CrowdsecCacheTimeout 1s
CrowdsecLocalCacheTimeout 60s')"

    run python3 "$BATS_TEST_DIRNAME/../lib/memo_probe.py" \
        "$APACHE_PORT" "$LAPI_STATE" \
        "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    [[ "$output" == *"first=200"* ]]
    [[ "$output" == *"blocked=True"* ]]
}

@test "a verdict is cached across child processes, not just in one" {
    # Without a shared cache each child would query the API for the same
    # client, multiplying API traffic by the number of children. Requests go
    # to whichever child accepts them, so the only way the second request can
    # still see the ban is if the verdict is shared.
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    apache_start "CrowdsecCache shmcb:live(1048576)
CrowdsecCacheTimeout 30s
CrowdsecMode live
CrowdsecFallback allow
$(mpm_many_children)
Crowdsec On"
    [ "$(http_status)" = 429 ]

    # the api now reports the client as clean; the cached ban must still stand
    lapi_set '{"live":[]}'
    for _ in 1 2 3 4 5 6 7 8; do
        [ "$(http_status)" = 429 ]
    done
}

@test "one api query serves many requests" {
    lapi_set '{"live":[]}'
    apache_start "CrowdsecCache shmcb:live(1048576)
CrowdsecCacheTimeout 30s
CrowdsecMode live
CrowdsecFallback allow
$(mpm_many_children)
Crowdsec On"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ "$(http_status)" = 200 ]
    done
    # ten requests, spread over several children, must not be ten queries
    [ "$(status_field cache)" = yes ]
}

@test "a slow api hits CrowdsecTimeout and falls back" {
    lapi_set '{"live":[],"delay":5}'
    apache_start "CrowdsecCacheTimeout 1s
CrowdsecMode live
CrowdsecTimeout 1s
CrowdsecFallback block
Crowdsec On"
    start=$(date +%s)
    code="$(http_status)"
    elapsed=$(( $(date +%s) - start ))
    [ "$code" = 429 ]
    # our budget, not Apache's 60s Timeout
    [ "$elapsed" -lt 4 ]
}
