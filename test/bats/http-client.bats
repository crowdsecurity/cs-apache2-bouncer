#!/usr/bin/env bats
# crowdsec_http against real sockets: the response ceiling, timeouts, a closed
# port, and handle reuse. Driven through test/unit/t_http so the scenarios come
# from a real server rather than a mock.

load "../lib/harness.sh"

setup() {
    harness_init
    # Default to where make check builds it, not /tmp: a clean in-tree build
    # would otherwise skip this whole suite, or run a stale leftover binary.
    T_HTTP="${T_HTTP:-$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/test/unit/t_http}"
    [ -x "$T_HTTP" ] || skip "t_http not built (run make check)"
}

teardown() {
    harness_cleanup
}

@test "successful GET returns the body and status" {
    lapi_start "null"
    run "$T_HTTP" "http://127.0.0.1:$LAPI_PORT/v1/decisions" 1048576 2000
    [ "$status" -eq 0 ]
    [[ "$output" == *"err=ok status=200 len=4"* ]]
}

@test "a released handle is reused for a second exchange" {
    lapi_start "null"
    run "$T_HTTP" "http://127.0.0.1:$LAPI_PORT/v1/decisions" 1048576 2000
    [[ "$output" == *"again=ok status=200"* ]]
}

@test "response over the ceiling fails as oversize, not truncated" {
    # chunked, so nothing announces a length: MAXFILESIZE could not catch this
    lapi_start_sized 200000
    run "$T_HTTP" "http://127.0.0.1:$LAPI_PORT/v1/decisions" 65536 5000
    [[ "$output" == *"err=oversize"* ]]
}

@test "response just under the ceiling succeeds" {
    lapi_start_sized 60000
    run "$T_HTTP" "http://127.0.0.1:$LAPI_PORT/v1/decisions" 65536 5000
    [[ "$output" == *"err=ok status=200 len=60000"* ]]
}

@test "a slow endpoint hits our timeout, not Apache's" {
    lapi_start_slow "null" 3
    start=$(date +%s)
    run "$T_HTTP" "http://127.0.0.1:$LAPI_PORT/v1/decisions" 1048576 300
    elapsed=$(( $(date +%s) - start ))
    [[ "$output" == *"err=timeout"* ]]
    # both exchanges run, so allow for two 300ms budgets plus startup
    [ "$elapsed" -lt 3 ]
}

@test "closed port reports connect-fail and the pool still works after" {
    # nothing listening: an invalidated handle must not wedge the reslist
    local dead
    dead="$(harness_free_port)"
    run "$T_HTTP" "http://127.0.0.1:$dead/v1/decisions" 1048576 2000
    [[ "$output" == *"err=connect-fail"* ]]
    [[ "$output" == *"again=connect-fail"* ]]
}

@test "http_proxy in the environment is ignored" {
    lapi_start "null"
    # a bogus proxy would break the request if CURLOPT_PROXY were not cleared
    run env http_proxy="http://127.0.0.1:1" https_proxy="http://127.0.0.1:1" \
        all_proxy="http://127.0.0.1:1" \
        "$T_HTTP" "http://127.0.0.1:$LAPI_PORT/v1/decisions" 1048576 2000
    [[ "$output" == *"err=ok status=200"* ]]
}
