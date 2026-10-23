#!/usr/bin/env bats
# Directive syntax, checked with `apache2 -t` rather than a running server.
#
# Durations are the reason this file exists. The module reads them with
# Apache's own ap_timeout_parameter_parse, which knows "2min" and not "15m" -
# but "15m" is the Go spelling the rest of CrowdSec uses, it is what the
# shipped configuration and the documentation both quote, and uncommenting it
# used to take httpd down. Both spellings are accepted now, so both need a
# test: a parser that silently drops one of them is the bug coming back.

load "../lib/harness.sh"

setup() {
    harness_init
}

teardown() {
    harness_cleanup
}

# Minimal config: just enough to load the module and parse one directive.
configtest() {
    cat > "$HARNESS_DIR/syntax.conf" <<CONF
ServerRoot "$HARNESS_DIR"
DefaultRuntimeDir "$HARNESS_DIR/run"
ServerName localhost
PidFile "$HARNESS_DIR/run/httpd.pid"
ErrorLog "$HARNESS_DIR/logs/error.log"
DocumentRoot "$HARNESS_DIR/htdocs"
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so
LoadModule crowdsec_module $MODULE
CrowdsecURL http://127.0.0.1:8080
CrowdsecAPIKey testkey
$1
CONF
    apache2 -t -f "$HARNESS_DIR/syntax.conf" 2>&1
}

@test "duration: apache spelling is accepted" {
    for v in 200ms 5s 2min 3h; do
        run configtest "CrowdsecMetricsInterval $v"
        [ "$status" -eq 0 ] || { echo "rejected $v: $output" >&2; return 1; }
    done
}

@test "duration: go spelling is accepted" {
    for v in 15m 1h30m 90s; do
        run configtest "CrowdsecMetricsInterval $v"
        [ "$status" -eq 0 ] || { echo "rejected $v: $output" >&2; return 1; }
    done
}

@test "duration: a bare number is seconds" {
    run configtest "CrowdsecMetricsInterval 900"
    [ "$status" -eq 0 ]
}

@test "duration: nonsense is still refused" {
    run configtest "CrowdsecMetricsInterval banana"
    [ "$status" -ne 0 ]
    [[ "$output" == *"is not a valid duration"* ]]
}

# The value the shipped configuration and the reference table both quote. It
# parsed as invalid once, which made the documented default unusable.
@test "duration: the documented CrowdsecMetricsInterval default parses" {
    run configtest "CrowdsecMetricsInterval 15m"
    [ "$status" -eq 0 ]
}

@test "duration: every interval directive takes both spellings" {
    for d in CrowdsecUpdateFrequency CrowdsecCacheTimeout \
             CrowdsecLocalCacheTimeout CrowdsecConnectTimeout CrowdsecTimeout; do
        run configtest "$d 1min"
        [ "$status" -eq 0 ] || { echo "$d rejected 1min: $output" >&2; return 1; }
        run configtest "$d 1m"
        [ "$status" -eq 0 ] || { echo "$d rejected 1m: $output" >&2; return 1; }
    done
}

# The sized form the package now ships, as opposed to the bare "shmcb" it used
# to: stream mode silently evicts almost everything with an unsized cache.
@test "cache: the shipped sized shmcb form parses" {
    run configtest "CrowdsecCache shmcb:crowdsec(16777216)"
    [ "$status" -eq 0 ]
}
