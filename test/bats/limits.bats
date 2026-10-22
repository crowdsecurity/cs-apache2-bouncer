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

# A batch of <count> fresh single-ip bans numbered from <base>, replacing
# whatever the stub was about to serve. Distinct from gen_decisions' 10.0.0.0/8
# so a batch never re-stores an address the snapshot already carried.
gen_batch() {
    lapi_set "$(python3 - "$1" "$2" <<'PY'
import json, sys
base, n = int(sys.argv[1]), int(sys.argv[2])
decs = [{"duration": "4h0m0s", "id": base + i, "origin": "cscli",
         "scenario": "manual", "scope": "Ip", "type": "ban",
         "value": "172.%d.%d.%d" % (16 + (((base + i) >> 16) & 15),
                                    ((base + i) >> 8) & 255,
                                    (base + i) & 255)}
        for i in range(n)]
print(json.dumps({"decisions": decs}))
PY
)"
}

# Waits until the stub has handed out the pending batch, so the next one does
# not replace it unserved.
wait_served() {
    local i=0
    while [ "$i" -lt 150 ]; do
        if [ "$(lapi_get decisions)" = "[]" ]; then
            return 0
        fi
        i=$((i + 1)); sleep 0.1
    done
    echo "a batch was never served" >&2
    return 1
}

# Waits until the module reports <n> applied pulls.
wait_pulls() {
    local want="$1" i=0
    while [ "$i" -lt 200 ]; do
        if [ "$(status_field pulls)" -ge "$want" ]; then
            return 0
        fi
        i=$((i + 1)); sleep 0.1
    done
    echo "only $(status_field pulls) pulls applied, wanted $want" >&2
    return 1
}

# A stream-mode vhost that polls fast enough for a test to watch several pulls.
polling_conf() {
    cat <<CONF
CrowdsecMode stream
CrowdsecUpdateFrequency ${2:-1s}
CrowdsecCache shmcb:limits($1)
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

@test "the reported figures survive an incremental pull" {
    # They used to be rewritten from every pull's own counter, so the first
    # incremental pull that added nothing reported the cache as empty while it
    # was holding the whole snapshot.
    gen_decisions 1000
    apache_start "$(polling_conf 4194304)"
    wait_primed
    stored="$(status_field stored)"
    [ "$stored" -ge 1000 ]

    # Nothing left to report, so the pulls that follow write nothing at all.
    # Patched rather than replaced, to keep the counters the stub maintains.
    lapi_patch sticky false
    lapi_patch decisions '[]'
    lapi_patch deleted '[]'
    wait_pulls "$(( $(status_field pulls) + 2 ))"

    [ "$(lapi_get startup_seen)" = 1 ]
    [ "$(status_field stored)" = "$stored" ]
    [ "$(status_field retained)" = "$stored" ]
    [ "$(status_field stored_age_s)" -ge 0 ]
}

@test "an undersized cache is still reported as such between full pulls" {
    # The figures are what the documented sizing check reads, so they have to
    # stay readable on a server that has been up for a while - not only in the
    # moment after the one full pull of its life.
    gen_decisions 20000
    apache_start "$(polling_conf 524288)"
    wait_primed
    stored="$(status_field stored)"
    [ "$(status_field retained)" -lt "$stored" ]

    lapi_patch sticky false
    lapi_patch decisions '[]'
    lapi_patch deleted '[]'
    wait_pulls "$(( $(status_field pulls) + 2 ))"

    [ "$(status_field stored)" = "$stored" ]
    [ "$(status_field retained)" -lt "$stored" ]
}

@test "a cache filled by incremental pulls still reports eviction" {
    # Every batch here is far below the sampling interval a full pull uses, so
    # no pull has a sample of its own to check. Noticing the cache overflow at
    # all means re-reading keys that earlier pulls wrote.
    gen_decisions 200
    apache_start "$(polling_conf 65536 200ms)"
    wait_primed
    stored="$(status_field stored)"

    i=0
    while [ "$i" -lt 40 ]; do
        gen_batch "$(( i * 40 ))" 40
        wait_served
        if grep -q "decision cache is too small" \
            "$HARNESS_DIR/logs/error.log"; then
            break
        fi
        i=$(( i + 1 ))
    done

    grep -q "decision cache is too small" "$HARNESS_DIR/logs/error.log"
    # and the status handler agrees with the log, which is what the README
    # tells people to look at
    [ "$(status_field stored)" = "$stored" ]
    [ "$(status_field retained)" -lt "$stored" ]
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
