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

@test "a cached allow does not outlive the poll interval by much" {
    # The per-child memo caches the ALLOW for an address probed before the
    # decision lands. It must expire on CrowdsecLocalCacheTimeout, not on
    # CrowdsecCacheTimeout - a 60s shared lifetime here, which is the realistic
    # shape, would otherwise keep serving the stale allow for a full minute.
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "CrowdsecMode stream
CrowdsecUpdateFrequency 1s
CrowdsecCache $BIG_CACHE
CrowdsecCacheTimeout 60s
CrowdsecLocalCacheTimeout 1s
CrowdsecFallback allow
Crowdsec On"
    wait_primed
    [ "$(http_status)" = 200 ]          # warms an allow into this child's memo

    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    # bound is CrowdsecUpdateFrequency + CrowdsecLocalCacheTimeout = 2s
    for _ in $(seq 16); do
        [ "$(http_status)" = 429 ] && break
        sleep 0.5
    done
    # The 429 above proves one child enforced, but a sibling child's memo can
    # hold the pre-ban allow for up to CrowdsecLocalCacheTimeout after that.
    # Let it lapse, then any child must agree.
    sleep 1.1
    [ "$(http_status)" = 429 ]
}

@test "deleting a decision unblocks the address" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]

    # stop repeating the ban, and report it as deleted
    lapi_set "{\"decisions\":[],\"deleted\":[$(decision 127.0.0.1 Ip)]}"
    sleep 3
    # CrowdsecLocalCacheTimeout caps the per-child memo at 1s here, so what
    # is being observed is the shared cache being updated
    [ "$(http_status)" = 200 ]
}

# Several decisions for one address share its single cache entry, which must
# hold whichever lasts longest. Each test is arranged so that keeping the last
# one to arrive - the old behaviour - fails it.

@test "a shorter decision arriving last does not cut a longer one short" {
    lapi_set "{\"decisions\":[$(decision_typed 127.0.0.1 Ip ban 1h0m0s 1),$(decision_typed 127.0.0.1 Ip captcha 2s 2)]}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]
    sleep 4
    [ "$(http_status)" = 429 ]
}

@test "a longer decision arriving last replaces a shorter one" {
    # The other order, so keeping the first one to arrive fails too.
    lapi_set "{\"decisions\":[$(decision_typed 127.0.0.1 Ip ban 2s 1),$(decision_typed 127.0.0.1 Ip captcha 1h0m0s 2)]}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]
    sleep 4
    [ "$(http_status)" = 429 ]
}

@test "a shorter decision in an incremental pull does not cut a longer one short" {
    lapi_set "{\"decisions\":[$(decision_typed 127.0.0.1 Ip ban 1h0m0s 1)]}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]

    lapi_set "{\"decisions\":[$(decision_typed 127.0.0.1 Ip ban 2s 2)]}"
    sleep 4
    [ "$(http_status)" = 429 ]
}

@test "removing a shorter decision leaves the longer one blocking" {
    # What a real engine does when a short ban runs out on an address a
    # blocklist also carries: the short one is reported deleted. Removing the
    # entry on that would unblock an address that is still banned.
    lapi_set "{\"decisions\":[$(decision_typed 127.0.0.1 Ip ban 1h0m0s 1),$(decision_typed 127.0.0.1 Ip ban 1h0m0s 2)]}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(http_status)" = 429 ]

    # Same expiry, so the entry holds id 2, the later one; withdraw id 1.
    lapi_set "{\"decisions\":[],\"deleted\":[$(decision_typed 127.0.0.1 Ip ban -1s 1)]}"
    sleep 3
    [ "$(http_status)" = 429 ]

    # And withdrawing the one it holds does unblock.
    lapi_set "{\"decisions\":[],\"deleted\":[$(decision_typed 127.0.0.1 Ip ban -1s 2)]}"
    sleep 3
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

@test "a failed pull forces a full resync, so its batch is not lost" {
    # The engine advances its own stream cursor once it has finished writing a
    # response, so a batch we fail to read is never resent to an incremental
    # pull. Unless a failure forces startup=true, everything in that batch is
    # missed for good - here, the ban that arrives during the outage.
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed

    # Break the API and let at least one pull fail.
    lapi_set '{"status":500}'
    sleep 3

    # Heal, publishing a ban. lapi_set replaces the whole state, so the stub's
    # counters restart from zero here: any startup=true pull counted from now
    # on can only be the resync the failure forced.
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"

    for _ in $(seq 60); do
        [ "$(lapi_get startup_seen)" != "" ] \
            && [ "$(lapi_get startup_seen)" -ge 1 ] && break
        sleep 0.2
    done
    [ "$(lapi_get startup_seen)" -ge 1 ]
    [ "$(http_status)" = 429 ]
}

@test "a full pull retires a ban the snapshot no longer carries" {
    # The other half of the resync above. A full snapshot only ever stored
    # entries, so a deletion the previous leader consumed before dying was
    # never applied and never resent: the ban stayed in the cache for the
    # decision's whole duration, and the exact-address probe found it even
    # though the snapshot had stopped carrying it.
    #
    # Sticky and the default 1h duration, so nothing here can expire on its
    # own - only a full pull that retires what it no longer sees can clear it.
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf 'CrowdsecLocalCacheTimeout 1s')"
    wait_primed
    [ "$(http_status)" = 429 ]

    # Force a full pull the same way: break the API so a pull fails, which sets
    # need_full, then heal with a snapshot that no longer carries the ban.
    lapi_set '{"status":500}'
    sleep 3
    lapi_set '{"decisions":[],"sticky":true}'

    for _ in $(seq 60); do
        [ "$(lapi_get startup_seen)" != "" ] \
            && [ "$(lapi_get startup_seen)" -ge 1 ] && break
        sleep 0.2
    done
    [ "$(lapi_get startup_seen)" -ge 1 ]

    # Past the 1s per-child memo, so the allow below comes from the store
    # rather than from a slot still holding the earlier ban.
    sleep 2
    [ "$(http_status)" = 200 ]
}

@test "a full pull that fails to parse leaves the previous snapshot enforced" {
    # The other side of the generation swap. A full pull publishes the
    # generation it is about to write before applying, because lookups have to
    # keep working while it does. The risk is that a pull which then fails
    # leaves the store answering from a snapshot that was never finished, so
    # this pins the only outcome that is safe: the last good snapshot still
    # decides, and nobody it had already blocked gets let through.
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf 'CrowdsecLocalCacheTimeout 1s')"
    wait_primed
    [ "$(http_status)" = 429 ]

    # Fail in the parser rather than the transport, so the apply is entered
    # and abandoned instead of never starting.
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true,\"stream_body\":\"{\\\"new\\\": [\"}"
    sleep 4

    [ "$(http_status)" = 429 ]
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
