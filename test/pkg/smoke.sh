#!/bin/sh
# Smoke-tests an already-installed crowdsec-apache2-bouncer package.
#
# Deliberately not part of the bats suite: that one loads the module from the
# build tree under an httpd.conf it writes itself, so it cannot tell you
# whether the *package* put files in the right place, whether the maintainer
# scripts ran, or whether the config came out 0600. This drives the distro's
# own httpd against the installed files instead, which is also why it is plain
# sh - EL8 has no bats in its base repositories.
#
# Needs: the package installed, python3, curl. Run as root.
set -eu

PKG=crowdsec-apache2-bouncer
CONF="/etc/crowdsec/bouncers/$PKG.conf"
HELPER="/usr/lib/$PKG/_bouncer.sh"
DOCROOT=/var/www/html
WORK=$(mktemp -d)
LAPI_PORT=8080
failures=0

ok()   { echo "ok - $1"; }
bad()  { echo "not ok - $1" >&2; failures=$((failures + 1)); }
die()  { echo "Bail out! $1" >&2; exit 1; }

# EL's apachectl is a wrapper that defers to systemctl, so it cannot start
# httpd where there is no systemd - which is every container, and so every CI
# run. The binary's own -k start works there. On Debian it is the other way
# round: apachectl is the real thing and the bare binary needs the APACHE_*
# variables it sources from /etc/apache2/envvars, so the fallback never fires.
httpd_start() {
    apachectl start >"$WORK/start.log" 2>&1 && return 0
    "$HTTPD_BIN" -k start >>"$WORK/start.log" 2>&1
}

httpd_stop() {
    apachectl stop >/dev/null 2>&1 && return 0
    "$HTTPD_BIN" -k stop >/dev/null 2>&1 || true
}

cleanup() {
    httpd_stop
    if [ -n "${LAPI_PID:-}" ]; then
        kill "$LAPI_PID" 2>/dev/null || true
        wait "$LAPI_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- which layout are we on -------------------------------------------------
# From the filesystem rather than apxs: apxs comes from the -dev package, which
# an installed-package test has no business requiring.
if [ -d /etc/apache2/mods-enabled ]; then
    LAYOUT=debian
    HTTPD_BIN=apache2
    PKG_FILES="dpkg -L $PKG"
elif [ -d /etc/httpd/conf.modules.d ]; then
    LAYOUT=el
    HTTPD_BIN=httpd
    PKG_FILES="rpm -ql $PKG"
else
    die "no recognised apache layout under /etc"
fi
ok "layout detected: $LAYOUT"

# apachectl -M is unsupported on EL, where apachectl is a start/stop wrapper;
# the bare binary is the one that works there. On Debian it is the other way
# round - apache2 -M needs the APACHE_* variables that apachectl sources from
# /etc/apache2/envvars.
module_list() {
    apachectl -M 2>/dev/null || "$HTTPD_BIN" -M 2>/dev/null || true
}

# --- what the package installed ---------------------------------------------
$PKG_FILES >"$WORK/files" 2>/dev/null || die "$PKG is not installed"

MODULE=$(grep -E 'mod_crowdsec\.so$' "$WORK/files" | head -1)
[ -n "$MODULE" ] || die "the package ships no mod_crowdsec.so"
[ -f "$MODULE" ] && ok "module installed at $MODULE" || bad "$MODULE is missing"

# This is the one the packaging goes out of its way to get right: the file
# holds the API key, and _bouncer.sh rewrites it with a redirect that
# preserves the existing mode, so a 0644 config would stay 0644 with the key
# in it and nothing would fail loudly.
for f in "$CONF" "$HELPER"; do
    [ -f "$f" ] || { bad "$f is missing"; continue; }
    mode=$(stat -c %a "$f")
    [ "$mode" = 600 ] && ok "$f is 0600" || bad "$f is $mode, expected 600"
done

# --- the maintainer scripts actually ran ------------------------------------
# envsubst is what writes the key, and it comes from a package apache does not
# depend on, so a missing declaration shows up here rather than in the field.
command -v envsubst >/dev/null && ok "envsubst is available" \
    || bad "envsubst is missing - gettext-base/gettext is not declared"

if grep -q '\$API_KEY' "$CONF"; then
    bad "the \$API_KEY placeholder is still in $CONF - postinst did not run"
else
    ok "the API key placeholder was substituted"
fi

# --- the module is enabled the way the layout expects -----------------------
if [ "$LAYOUT" = debian ]; then
    for f in /etc/apache2/mods-enabled/crowdsec.load /etc/apache2/mods-enabled/crowdsec.conf; do
        [ -L "$f" ] && ok "$(basename "$f") is linked into mods-enabled" \
            || bad "$f is not a symlink"
    done
    # a2query strips a leading "mod" from the name it is given, so this also
    # pins the file naming: mod_crowdsec.load would resolve to _crowdsec and
    # match nothing, and apache2_invoke could then never disable the module.
    a2query -m crowdsec >/dev/null 2>&1 && ok "a2query resolves the module" \
        || bad "a2query -m crowdsec fails - check the snippet filenames"
else
    for f in /etc/httpd/conf.modules.d/10-crowdsec.conf /etc/httpd/conf.d/crowdsec.conf; do
        [ -f "$f" ] && ok "$(basename "$f") installed" || bad "$f is missing"
    done
fi

# --- point it at a stub API and gate a real request -------------------------
cat > "$WORK/state.json" <<JSON
{"live":[{"duration":"1h0m0s","id":1,"origin":"cscli","scenario":"manual","scope":"Ip","type":"ban","value":"127.0.0.1"}]}
JSON
python3 "$(dirname "$0")/../lib/stub_lapi.py" "$LAPI_PORT" "$WORK/state.json" \
    >"$WORK/lapi.log" 2>&1 &
LAPI_PID=$!
i=0
while [ "$i" -lt 50 ]; do
    curl -fsS --max-time 1 "http://127.0.0.1:$LAPI_PORT/v1/decisions" >/dev/null 2>&1 && break
    i=$((i + 1))
    sleep 0.1
done
[ "$i" -lt 50 ] && ok "stub local API is up on $LAPI_PORT" \
    || die "stub local API never came up: $(cat "$WORK/lapi.log")"

# Appended rather than edited: a later directive wins for these, and it keeps
# the shipped defaults visible in the diff. The two cache timeouts are the
# shipped 60s and 2s, which would hold the first verdict well past the point
# where this test withdraws the decision.
cat >> "$CONF" <<CONF

# appended by test/pkg/smoke.sh
CrowdsecURL http://127.0.0.1:$LAPI_PORT
CrowdsecMode live
CrowdsecCacheTimeout 1s
CrowdsecLocalCacheTimeout 1s
CrowdsecFallback allow
CrowdsecBlockedHTTPCode 403
Crowdsec On
CONF

mkdir -p "$DOCROOT"
echo smoke > "$DOCROOT/smoke.txt"

apachectl configtest >"$WORK/configtest.log" 2>&1 \
    && ok "apachectl configtest passes" \
    || { cat "$WORK/configtest.log" >&2; die "configtest failed"; }

httpd_start || { cat "$WORK/start.log" >&2; die "httpd would not start"; }
i=0
while [ "$i" -lt 50 ]; do
    curl -fsS --max-time 1 -o /dev/null "http://127.0.0.1/smoke.txt" 2>/dev/null && break
    curl -sS --max-time 1 -o /dev/null "http://127.0.0.1/smoke.txt" 2>/dev/null && break
    i=$((i + 1))
    sleep 0.1
done
[ "$i" -lt 50 ] || die "httpd never answered on port 80"

module_list | grep -q crowdsec_module && ok "crowdsec_module is loaded" \
    || bad "crowdsec_module is not in the module list"

status() { curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1/smoke.txt"; }

# CrowdsecFallback is allow, so a 403 here can only come from the module
# having asked the API and been told to ban - it is not a side effect of the
# API being unreachable.
code=$(status)
[ "$code" = 403 ] && ok "a banned client gets 403" || bad "banned client got $code, expected 403"

echo '{"live":[]}' > "$WORK/state.json"
i=0
code=
while [ "$i" -lt 60 ]; do
    code=$(status)
    [ "$code" = 200 ] && break
    i=$((i + 1))
    sleep 0.5
done
[ "$code" = 200 ] && ok "withdrawing the decision unblocks the client" \
    || bad "client still gets $code after the decision was withdrawn"

if [ "$failures" -gt 0 ]; then
    echo "FAILED: $failures check(s)" >&2
    exit 1
fi
echo "all package smoke checks passed on the $LAYOUT layout"
