#!/usr/bin/env bats
# Usage metrics end to end: a real Apache, a stub local API recording what was
# pushed to /v1/usage-metrics, and the counters read back off CrowdsecStatus.

load "../lib/harness.sh"

BIG_CACHE="shmcb:crowdsec-test(8388608)"

setup() {
    harness_init
    lapi_api_start
}

teardown() {
    harness_cleanup
}

# The shortest window the directive allows, so a test sees a push in seconds
# rather than a quarter of an hour.
metrics_conf() {
    cat <<CONF
CrowdsecMetricsInterval 10s
CrowdsecFallback allow
Crowdsec On
$1
CONF
}

stream_conf() {
    metrics_conf "$(cat <<CONF
CrowdsecMode stream
CrowdsecUpdateFrequency 1s
CrowdsecCache $BIG_CACHE
CrowdsecCacheTimeout 1s
CrowdsecLocalCacheTimeout 1s
$1
CONF
)"
}

live_conf() {
    metrics_conf "$(cat <<CONF
CrowdsecMode live
CrowdsecCache $BIG_CACHE
CrowdsecCacheTimeout 1s
CrowdsecLocalCacheTimeout 1s
$1
CONF
)"
}

# The caller runs appsec_start itself, in the test body: backgrounding the stub
# inside a command substitution would leave it holding that pipe open, and the
# substitution would never return.
appsec_conf() {
    stream_conf "$(cat <<CONF
CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
CrowdsecAppsec On
# The status endpoint is how these tests read the counters back, and AppSec
# enabled at server scope covers it too - so a stub that bans everything would
# ban the very endpoint being polled. The harness turns Crowdsec off there;
# this turns inspection off as well.
<Location /crowdsec-status>
    CrowdsecAppsec Off
</Location>
$1
CONF
)"
}

# --------------------------------------------------------------- the payload

@test "the payload carries everything the local API requires" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    wait_metrics 1

    [ "$(metric_component 0 type)" = "crowdsec-apache2-bouncer" ]
    [ -n "$(metric_component 0 version)" ]
    # Required and must be a real timestamp, not a zero.
    [ "$(metric_component 0 utc_startup_timestamp)" -gt 1000000000 ]
    [ -n "$(metric_meta 0 utc_now_timestamp)" ]
    [ -n "$(metric_meta 0 window_size_seconds)" ]

    # os.name and os.version are required and must be non-empty, or the
    # payload is rejected outright.
    run metric_component 0 os
    [ "$status" -eq 0 ]
    python3 -c 'import json,sys
os_ = json.loads(sys.argv[1])
assert os_.get("name"), os_
assert os_.get("version"), os_' "$output"
}

@test "the component name is left for the local API to resolve" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    wait_metrics 1

    # Sending one would only let our opinion disagree with the name the key
    # was registered under.
    [ -z "$(metric_component 0 name)" ]
}

@test "empty arrays are arrays, and log_processors is null" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    wait_metrics 1

    # Asserted on the raw body: json.loads collapses [] and {} to the same
    # thing, and {} is what the local API answers 400 for.
    raw="$(metric_raw 0)"
    [[ "$raw" == *'"feature_flags":[]'* ]]
    [[ "$raw" != *'"feature_flags":{}'* ]]
    [[ "$raw" == *'"log_processors":null'* ]]
}

@test "the push authenticates and declares its content type" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    wait_metrics 1

    [ "$(metric_header x-api-key)" = "testkey" ]
    [ "$(metric_header content-type)" = "application/json" ]
    [[ "$(metric_header user-agent)" == crowdsec-apache2-bouncer/* ]]
}

# -------------------------------------------------------------- processed

@test "processed counts every request that was decided" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed

    for _ in 1 2 3 4 5; do
        curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    done
    # The status handler is itself a request, and it is not in a Crowdsec
    # scope, so it must not be counted. Read the counter before the window
    # closes and takes it away.
    [ "$(status_metric 'processed{ip_type=ipv4}')" = 5 ]

    wait_metrics 1
    [ "$(metric_item 0 processed ip_type=ipv4)" = 5 ]
    # Reported for both families even at zero: an absent item cannot say
    # "alive, no traffic".
    [ "$(metric_item 0 processed ip_type=ipv6)" = 0 ]
}

@test "processed carries no origin label" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    wait_metrics 1

    raw="$(metric_raw 0)"
    # At the point processed is counted there is no decision to attribute it
    # to, which is also what both reference bouncers do.
    [[ "$raw" != *'"processed","value":1,"unit":"request","labels":{"ip_type":"ipv4","origin"'* ]]
}

@test "a request that no scope decided is not counted" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf "
<Location /open/>
    Crowdsec Off
</Location>")"
    wait_primed

    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/open/" >/dev/null
    [ "$(status_metric 'processed{ip_type=ipv4}')" = 0 ]
}

# ---------------------------------------------------------------- dropped

@test "a dropped request is attributed to the deciding origin" {
    lapi_set "{\"decisions\":[$(decision_from 127.0.0.1 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed

    [ "$(http_status)" = 429 ]
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=CAPI}')" = 1 ]

    wait_metrics 1
    [ "$(metric_item 0 dropped ip_type=ipv4 origin=CAPI)" = 1 ]
}

@test "a blocklist decision is attributed to its list, not to lists" {
    lapi_set "{\"decisions\":[$(decision_from 127.0.0.1 Ip lists firehol_level1)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed

    [ "$(http_status)" = 429 ]
    # Reporting every blocklist as "lists" would collapse them into one line.
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=lists:firehol_level1}')" = 1 ]

    wait_metrics 1
    [ "$(metric_item 0 dropped ip_type=ipv4 origin=lists:firehol_level1)" = 1 ]
}

@test "a range decision attributes the block too" {
    lapi_set "{\"decisions\":[$(decision_from 127.0.0.0/24 Range CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed

    [ "$(http_status)" = 429 ]
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=CAPI}')" = 1 ]
}

@test "a memo hit is still attributed" {
    lapi_set "{\"decisions\":[$(decision_from 127.0.0.1 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf "CrowdsecLocalCacheTimeout 60")"
    wait_primed

    # The first request fills the memo; the rest are answered from it, before
    # the store is ever consulted. Without the origin in the memo slot these
    # would all land under "unknown".
    for _ in 1 2 3; do
        [ "$(http_status)" = 429 ]
    done
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=CAPI}')" = 3 ]
    [ -z "$(status_metric 'dropped{ip_type=ipv4,origin=unknown}')" ]
}

@test "live mode attributes a block to the origin the query returned" {
    lapi_set "{\"live\":[$(decision_from 127.0.0.1 Ip lists mylist)]}"
    apache_start "$(live_conf)"

    [ "$(http_status)" = 429 ]
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=lists:mylist}')" = 1 ]

    wait_metrics 1
    [ "$(metric_item 0 dropped ip_type=ipv4 origin=lists:mylist)" = 1 ]
}

@test "an allowed request is not counted as dropped" {
    lapi_set "{\"decisions\":[$(decision_from 10.9.9.9 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed

    [ "$(http_status)" = 200 ]
    wait_metrics 1
    [ -z "$(metric_item 0 dropped ip_type=ipv4 origin=CAPI)" ]
    [ "$(metric_item 0 processed ip_type=ipv4)" -ge 1 ]
}

@test "a request blocked by the fallback has no origin to attribute" {
    # No decisions loaded yet, so stream mode is unprimed and the fallback
    # decides. There is no decision behind that, so it is processed but not
    # dropped - the alternative would be inventing an origin.
    lapi_set '{"status":500}'
    apache_start "$(stream_conf "CrowdsecFallback block")"

    [ "$(http_status)" = 429 ]
    [ "$(status_metric 'processed{ip_type=ipv4}')" = 1 ]
    [ -z "$(status_metric 'dropped{ip_type=ipv4,origin=unknown}')" ]
}

# -------------------------------------------------------- active_decisions

@test "active_decisions counts what the store holds, per origin" {
    lapi_set "{\"decisions\":[$(decision_from 10.0.0.1 Ip CAPI),$(decision_from 10.0.0.2 Ip CAPI),$(decision_from 10.0.0.3 Ip lists mylist)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed

    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 2 ]
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=lists:mylist}')" = 1 ]

    wait_metrics 1
    [ "$(metric_item 0 active_decisions ip_type=ipv4 origin=CAPI)" = 2 ]
    [ "$(metric_item 0 active_decisions ip_type=ipv4 origin=lists:mylist)" = 1 ]
}

@test "an ipv6 decision is counted under ipv6" {
    lapi_set "{\"decisions\":[$(decision_from 2001:db8::1 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed

    [ "$(status_metric 'active_decisions{ip_type=ipv6,origin=CAPI}')" = 1 ]
    [ -z "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" ]
}

@test "a deletion decrements the gauge for the right origin" {
    lapi_set "{\"decisions\":[$(decision_from 10.0.0.1 Ip CAPI),$(decision_from 10.0.0.2 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 2 ]

    # The stream says what to remove, not what it was attributed to, so the
    # origin has to come back out of the store.
    lapi_set "{\"decisions\":[],\"deleted\":[$(decision_from 10.0.0.1 Ip CAPI)]}"
    local i=0
    while [ "$i" -lt 100 ]; do
        [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 1 ] \
            && break
        i=$((i + 1)); sleep 0.1
    done
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 1 ]
}

@test "the gauge re-converges after entries expire on their own" {
    # The socache drops an entry when its decision runs out and tells nobody,
    # so the decrement never happens and the gauge drifts up. A full pull is
    # the only moment the store knows the truth, which is why the reporting
    # thread asks for one each window. This is that recovery.
    lapi_set "{\"decisions\":[$(decision_from 10.0.0.1 Ip CAPI 'manual' '2s'),$(decision_from 10.0.0.2 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 2 ]

    # Let the short one lapse, then drop it from what the API serves so the
    # next full pull recounts without it.
    sleep 3
    lapi_set "{\"decisions\":[$(decision_from 10.0.0.2 Ip CAPI)],\"sticky\":true}"

    local i=0
    while [ "$i" -lt 300 ]; do
        [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 1 ] \
            && break
        i=$((i + 1)); sleep 0.1
    done
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=CAPI}')" = 1 ]
}

@test "an emptied origin reports zero rather than its last reading" {
    lapi_set "{\"decisions\":[$(decision_from 10.0.0.1 Ip lists gone)],\"sticky\":true}"
    apache_start "$(stream_conf)"
    wait_primed
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=lists:gone}')" = 1 ]

    # Unsubscribed. Reporting nothing would leave the Console showing 1 for
    # good, which is what lua-cs-bouncer does.
    lapi_set '{"decisions":[],"sticky":true}'
    local i=0
    while [ "$i" -lt 300 ]; do
        [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=lists:gone}')" = 0 ] \
            && break
        i=$((i + 1)); sleep 0.1
    done
    [ "$(status_metric 'active_decisions{ip_type=ipv4,origin=lists:gone}')" = 0 ]
}

@test "live mode reports no active_decisions at all" {
    lapi_set '{"live":[]}'
    apache_start "$(live_conf)"
    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    wait_metrics 1

    # There is no local decision store to count, so a zero would be a claim we
    # cannot make.
    raw="$(metric_raw 0)"
    [[ "$raw" != *active_decisions* ]]
}

# ---------------------------------------------------------------- appsec

@test "a WAF block is attributed to appsec, not to a decision" {
    appsec_start
    lapi_set '{"decisions":[],"sticky":true}'
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    apache_start "$(appsec_conf "CrowdsecBlockedHTTPCode 403")"
    wait_primed

    [ "$(http_status)" = 403 ]
    # The lua bouncer counts no WAF block at all, so its WAF looks idle in the
    # Console however much it is blocking. This is the haproxy behaviour.
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=appsec}')" = 1 ]

    wait_metrics 1
    [ "$(metric_item 0 dropped ip_type=ipv4 origin=appsec)" = 1 ]
}

@test "a decision block is not stolen by appsec" {
    appsec_start
    lapi_set "{\"decisions\":[$(decision_from 127.0.0.1 Ip CAPI)],\"sticky\":true}"
    # The WAF allows; the decision is what blocks, so the decision's origin is
    # what the drop belongs to.
    appsec_set '{"action":"allow","http_status":200}'
    apache_start "$(appsec_conf)"
    wait_primed

    [ "$(http_status)" = 429 ]
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=CAPI}')" = 1 ]
    [ -z "$(status_metric 'dropped{ip_type=ipv4,origin=appsec}')" ]
}

@test "a WAF block on top of an allow still counts once" {
    appsec_start
    lapi_set '{"decisions":[],"sticky":true}'
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    apache_start "$(appsec_conf "CrowdsecBlockedHTTPCode 403")"
    wait_primed

    [ "$(http_status)" = 403 ]
    [ "$(status_metric 'processed{ip_type=ipv4}')" = 1 ]
    [ "$(status_metric 'dropped{ip_type=ipv4,origin=appsec}')" = 1 ]
}

# ------------------------------------------------------------- the window

@test "window_size_seconds is measured, not assumed" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    wait_metrics 1

    w="$(metric_meta 0 window_size_seconds)"
    # The interval is 10s; a measured window is that or a little more, never
    # the configured number regardless of what actually elapsed.
    [ "$w" -ge 9 ]
    [ "$w" -le 60 ]
}

@test "counters are not lost when a push is rejected" {
    lapi_set '{"decisions":[],"sticky":true,"metrics_status":500}'
    apache_start "$(stream_conf)"
    wait_primed

    for _ in 1 2 3; do
        curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    done
    wait_metrics 1

    # Nothing is taken back on a failure, so the count survives and the next
    # window covers both periods with an honest window_size_seconds.
    [ "$(status_metric 'processed{ip_type=ipv4}')" = 3 ]
    [ "$(status_field metrics_last_status)" = 500 ]

    # Patched, not replaced: lapi_set would discard the pushes recorded so far.
    lapi_patch metrics_status 201
    local i=0
    while [ "$i" -lt 300 ]; do
        [ "$(status_metric 'processed{ip_type=ipv4}')" = 0 ] && break
        i=$((i + 1)); sleep 0.1
    done
    # Accepted this time, so the window closed and took back what it reported.
    [ "$(status_metric 'processed{ip_type=ipv4}')" = 0 ]
    # The three requests were reported, by whichever push finally landed - and
    # the window it claimed spans both periods, not just the last one.
    [ "$(metric_item_max processed ip_type=ipv4)" -ge 3 ]
    [ "$(metric_meta -1 window_size_seconds)" -ge 10 ]
}

@test "a window takes back only what it reported" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf)"
    wait_primed
    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    wait_metrics 1

    # Counted after the first window closed, so it belongs to the second one
    # and must not be wiped by it either.
    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    wait_metrics 2
    [ "$(metric_item 0 processed ip_type=ipv4)" = 1 ]
    [ "$(metric_item 1 processed ip_type=ipv4)" = 1 ]
}

# ------------------------------------------------------------- the lease

@test "only one child reports, and reporting survives losing it" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf "$(mpm_many_children)")"
    wait_primed
    wait_metrics 1

    # Every child runs a reporting thread; the lease is what stops them all
    # pushing the same window under the same name.
    sleep 2
    [ "$(metrics_posts)" -le 2 ]

    before="$(metrics_posts)"
    # Take out whichever child holds the lease along with all the others; the
    # parent replaces them and one picks the lease up.
    pkill -f "$HARNESS_DIR/httpd.conf" -P "$(cat "$HARNESS_DIR/run/httpd.pid")" \
        2>/dev/null || true
    wait_metrics $((before + 1))
}

# ----------------------------------------------------------------- the off

@test "CrowdsecMetrics off reports nothing" {
    lapi_set '{"decisions":[],"sticky":true}'
    apache_start "$(stream_conf "CrowdsecMetrics Off")"
    wait_primed

    curl -fsS --max-time 5 "http://127.0.0.1:$APACHE_PORT/" >/dev/null
    [ "$(status_field metrics)" = "off" ]
    sleep 12
    [ "$(metrics_posts)" = 0 ]
}

@test "the counters are off too, so nothing is accumulated" {
    lapi_set "{\"decisions\":[$(decision_from 127.0.0.1 Ip CAPI)],\"sticky\":true}"
    apache_start "$(stream_conf "CrowdsecMetrics Off")"
    wait_primed

    # Blocking still works; it just is not reported.
    [ "$(http_status)" = 429 ]
    [ -z "$(status_metric 'processed{ip_type=ipv4}')" ]
}
