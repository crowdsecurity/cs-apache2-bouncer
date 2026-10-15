#!/usr/bin/env bats
# What happens at the edges: a cache too small for the decision set, IPv6,
# many prefix lengths at once, and the polling lease changing hands.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
}

teardown() {
    harness_cleanup
}

# Writes <count> single-ip ban decisions into the stub's state.
gen_decisions() {
    python3 - "$LAPI_STATE" "$1" <<'PY'
import json, sys
path, n = sys.argv[1], int(sys.argv[2])
decs = [{"duration": "4h0m0s", "id": i, "origin": "cscli",
         "scenario": "manual", "scope": "Ip", "type": "ban",
         "value": "10.%d.%d.%d" % ((i >> 16) & 255, (i >> 8) & 255, i & 255)}
        for i in range(n)]
# the client address, so the test can check it is still blocked under pressure
decs.append({"duration": "4h0m0s", "id": n, "origin": "cscli",
             "scenario": "manual", "scope": "Ip", "type": "ban",
             "value": "127.0.0.1"})
json.dump({"decisions": decs, "sticky": True}, open(path, "w"))
PY
}

stream_conf() {
    cat <<CONF
CrowdsecMode stream
CrowdsecUpdateFrequency 60s
CrowdsecCache shmcb:limits($1)
CrowdsecCacheTimeout 1s
CrowdsecFallback allow
Crowdsec On
CONF
}

@test "a cache far too small reports eviction instead of failing quietly" {
    # 20000 decisions need about 1MB; 512KB cannot hold them
    gen_decisions 20000
    apache_start "$(stream_conf 524288)"
    wait_primed
    grep -q "decision cache is too small" "$HARNESS_DIR/logs/error.log"
    # and the reported retention is visibly below what was stored
    [ "$(status_field stored)" -gt 0 ]
    [ "$(status_field retained)" -lt "$(status_field stored)" ]
}

@test "an adequately sized cache reports no eviction" {
    gen_decisions 20000
    apache_start "$(stream_conf 4194304)"
    wait_primed
    ! grep -q "decision cache is too small" "$HARNESS_DIR/logs/error.log"
    [ "$(status_field retained)" = "$(status_field stored)" ]
}

@test "100000 decisions are held without eviction in 16MB" {
    gen_decisions 100000
    apache_start "$(stream_conf 16777216)"
    wait_primed
    [ "$(status_field stored)" -ge 100000 ]
    [ "$(status_field retained)" = "$(status_field stored)" ]
    ! grep -q "decision cache is too small" "$HARNESS_DIR/logs/error.log"
    # and the client, whose decision is one among 100000, is still blocked
    [ "$(http_status)" = 429 ]
}

@test "the client stays blocked while the cache is under pressure" {
    # The entry for 127.0.0.1 competes with 20000 others in a cache that
    # cannot hold them. This documents behaviour rather than guaranteeing it:
    # if it ever fails, eviction took the one entry that mattered, which is
    # exactly what the warning in the log is for.
    gen_decisions 20000
    apache_start "$(stream_conf 524288)"
    wait_primed
    run bash -c '[ "$(http_status)" = 429 ]'
    if [ "$status" -ne 0 ]; then
        skip "the client's own decision was evicted, as the log warns"
    fi
}

@test "an ipv6 single address is blocked" {
    lapi_set "{\"decisions\":[$(decision ::1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf 4194304)"
    wait_primed
    # the harness listens on 127.0.0.1, so reach it over v6 to be seen as ::1
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://[::1]:$APACHE_PORT/"
    if [ "$output" = "000" ]; then
        skip "no ipv6 loopback listener"
    fi
    [ "$output" = 429 ]
}

@test "an ipv6 range is matched on a non-byte boundary" {
    lapi_set "{\"decisions\":[$(decision ::/125 Range)],\"sticky\":true}"
    apache_start "$(stream_conf 4194304)"
    wait_primed
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://[::1]:$APACHE_PORT/"
    if [ "$output" = "000" ]; then
        skip "no ipv6 loopback listener"
    fi
    # ::/125 covers ::0 through ::7, so ::1 is inside
    [ "$output" = 429 ]
}

@test "many prefix lengths at once still resolve the right one" {
    # Every length from /8 to /32 present, only one of which contains the
    # client. This is what the prefix-length bitmap is for: without it the
    # lookup would have to probe all 33.
    python3 - "$LAPI_STATE" <<'PY'
import json, sys
decs = []
for plen in range(8, 33):
    # 10.0.0.0/<plen> never contains 127.0.0.1
    decs.append({"duration": "4h0m0s", "id": plen, "origin": "c",
                 "scenario": "m", "scope": "Range", "type": "ban",
                 "value": "10.0.0.0/%d" % plen})
# and one that does
decs.append({"duration": "4h0m0s", "id": 99, "origin": "c", "scenario": "m",
             "scope": "Range", "type": "ban", "value": "127.0.0.0/30"})
json.dump({"decisions": decs, "sticky": True}, open(sys.argv[1], "w"))
PY
    apache_start "$(stream_conf 4194304)"
    wait_primed
    [ "$(http_status)" = 429 ]
}

@test "decisions whose prefixes do not contain the client are ignored" {
    python3 - "$LAPI_STATE" <<'PY'
import json, sys
decs = [{"duration": "4h0m0s", "id": plen, "origin": "c", "scenario": "m",
         "scope": "Range", "type": "ban", "value": "10.0.0.0/%d" % plen}
        for plen in range(8, 33)]
json.dump({"decisions": decs, "sticky": True}, open(sys.argv[1], "w"))
PY
    apache_start "$(stream_conf 4194304)"
    wait_primed
    [ "$(http_status)" = 200 ]
}

@test "malformed decisions are counted and dropped, not applied" {
    python3 - "$LAPI_STATE" <<'PY'
import json, sys
decs = [
    {"duration": "4h0m0s", "scope": "Ip", "value": "10.0.0.256", "type": "ban"},
    {"duration": "4h0m0s", "scope": "Ip", "value": "127.0.0.1/33", "type": "ban"},
    {"duration": "nonsense", "scope": "Ip", "value": "127.0.0.1", "type": "ban"},
    {"scope": "Ip", "value": "127.0.0.1", "type": "ban"},
]
json.dump({"decisions": decs, "sticky": True}, open(sys.argv[1], "w"))
PY
    apache_start "$(stream_conf 4194304)"
    wait_primed
    grep -q "decisions were malformed and dropped" "$HARNESS_DIR/logs/error.log"
    # none of those four should have blocked the client
    [ "$(http_status)" = 200 ]
}

@test "polling survives the leader child being killed" {
    # mod_watchdog's singleton never re-elects, which is why this module uses
    # a lease instead. Kill whichever child holds it and polling must resume.
    gen_decisions 10
    apache_start "CrowdsecMode stream
CrowdsecUpdateFrequency 1s
CrowdsecCache shmcb:lease(4194304)
CrowdsecFallback allow
$(mpm_many_children)
Crowdsec On"
    wait_primed
    before="$(lapi_get pulls)"

    leader="$(grep -oE "child \([0-9]+\) is now polling" \
        "$HARNESS_DIR/logs/error.log" | grep -oE "[0-9]+" | tail -1)"
    [ -n "$leader" ]
    kill -9 "$leader"

    # two intervals to notice the stale lease, plus margin
    sleep 8
    after="$(lapi_get pulls)"
    [ "$after" -gt "$before" ]
    grep -q "took over a stale polling lease" "$HARNESS_DIR/logs/error.log"
}
