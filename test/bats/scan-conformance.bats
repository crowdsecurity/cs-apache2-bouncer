#!/usr/bin/env bats
# The header sanitisers are reimplemented locally because Apache's
# ap_scan_* are not linkable from a standalone test. This proves they
# agree with the real thing, so "parity with Apache's parser" is a measured
# claim rather than an intention.

load "../lib/harness.sh"

setup() {
    harness_init
    CONF_MOD="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/test/unit/.libs/mod_scan_conformance.so"
}

teardown() {
    harness_cleanup
}

@test "sanitisers match Apache's ap_scan_* for every byte" {
    [ -f "$CONF_MOD" ] || skip "conformance module not built"
    lapi_start "null"
    apache_start "LoadModule scan_conformance_module $CONF_MOD"
    grep -q "SCANCONF PASS" "$HARNESS_DIR/logs/error.log"
    ! grep -q "SCANCONF MISMATCH" "$HARNESS_DIR/logs/error.log"
}
