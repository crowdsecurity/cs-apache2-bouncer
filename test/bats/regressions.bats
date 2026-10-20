#!/usr/bin/env bats
# The issues 0.1 left open, one test per reported symptom.
#
# They shared a cause. 0.1 fetched the decision by building an Apache
# subrequest for the request's own URI and repointing it at mod_proxy:
#
#     rr = ap_sub_req_method_uri("GET", r->uri, r, NULL);
#     if (rr->status != HTTP_OK) { ...; return rr->status; }
#
# Creating that subrequest ran the per-directory access and auth chain for the
# real URI, so Apache's own verdict on the request came back as if CrowdSec had
# answered: a basic-auth directory produced 401, a redirect produced 301, and
# the module returned those from the access hook - ahead of the authentication
# phase, so nothing ever added WWW-Authenticate, and in place of the real
# response, so nothing ever set Location.
#
# 1.0 queries the API with libcurl and builds no subrequest, so all of this
# passes by construction. That is why it needs tests: nothing else would notice
# the mechanism coming back.
#
# Every case runs against a cold cache. Not incidental - a cached verdict skips
# the lookup entirely, which is why #17 was reported as intermittent and why a
# warm second request proves nothing.

load "../lib/harness.sh"

setup() {
    harness_init
    lapi_api_start
}

teardown() {
    harness_cleanup
}

# Live mode with no CrowdsecCache, so nothing outlives the 1s per-child memo
# and the request under test is always the one doing the lookup.
#
# CrowdsecFallback fail rather than allow: these tests assert the module gets
# out of the way after an allow, and a fallback that also lets requests through
# would hide a lookup that never worked at all.
regr_conf() {
    cat <<CONF
CrowdsecMode live
CrowdsecFallback fail
CrowdsecLocalCacheTimeout 1s
Crowdsec On
$1
CONF
}

# 0.1 logged "crowdsec: service '<url>' returned <code>" when it read Apache's
# status as the API's. Both the auth and the redirect reports quoted that line,
# which is what made them look like local API failures.
refute_blamed_the_api() {
    ! grep -q "crowdsec: service" "$HARNESS_DIR/logs/error.log"
}

# --- #14 / #17: basic auth --------------------------------------------------
#
# issues/14, issues/17
#
# Reported: an unauthenticated visitor to an auth-protected path got a bare 401
# with no WWW-Authenticate, so the browser never prompted, and the error log
# blamed the local API for a 401 it had never sent.
#
# Creating the decision subrequest ran ap_location_walk and then the access and
# auth chain over the same URI, so mod_auth_basic answered 401 on the
# subrequest. The module returned that from its access hook, ahead of the main
# request's own authentication phase, so ap_note_basic_auth_failure never ran
# and nothing added the challenge.
#
# <Location> is the shape that reproduces: the subrequest inherited Location
# config but not <Directory> or .htaccess config, so only this one put the auth
# chain in front of the lookup. The <Directory> shape the issues name is
# covered too, since it is the one an operator is more likely to write.

auth_body() {
    cat <<CONF
    AuthType Basic
    AuthName "harness"
    AuthUserFile "$HARNESS_DIR/passwd"
    Require valid-user
CONF
}

auth_fixture() {
    mkdir -p "$HARNESS_DIR/htdocs/protected"
    echo protected-ok > "$HARNESS_DIR/htdocs/protected/index.html"
    harness_passwd tester s3cret
}

auth_conf() {
    auth_fixture
    regr_conf "<Location /protected/>
$(auth_body)
</Location>"
}

auth_conf_directory() {
    auth_fixture
    regr_conf "<Directory \"$HARNESS_DIR/htdocs/protected\">
$(auth_body)
</Directory>"
}

@test "#17 a cold-cache 401 still carries a WWW-Authenticate challenge" {
    lapi_set '{"live":[]}'
    apache_start "$(auth_conf)"
    [ "$(harness_request protected/)" = 401 ]
    [[ "$(resp_header WWW-Authenticate)" == Basic* ]]
    refute_blamed_the_api
}

@test "#14 correct credentials reach the content on a cold cache" {
    lapi_set '{"live":[]}'
    apache_start "$(auth_conf)"
    [ "$(harness_request protected/ -u tester:s3cret)" = 200 ]
    grep -q protected-ok "$HARNESS_DIR/resp.body"
}

@test "#14 wrong credentials get Apache's 401, with a challenge" {
    lapi_set '{"live":[]}'
    apache_start "$(auth_conf)"
    [ "$(harness_request protected/ -u tester:wrong)" = 401 ]
    [[ "$(resp_header WWW-Authenticate)" == Basic* ]]
}

@test "#14 the challenge survives with the auth in <Directory> too" {
    lapi_set '{"live":[]}'
    apache_start "$(auth_conf_directory)"
    [ "$(harness_request protected/)" = 401 ]
    [[ "$(resp_header WWW-Authenticate)" == Basic* ]]
    refute_blamed_the_api
}

@test "#17 a banned client is still blocked on a protected path" {
    # The counterpart: handing the auth phase back must not hand over
    # enforcement with it. A ban outranks the missing credentials.
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    apache_start "$(auth_conf)"
    [ "$(harness_request protected/)" = 429 ]
}

@test "#17 a denied path answers 403 without the module claiming it" {
    # Require all denied was the other source of the same log noise: any URI
    # whose subrequest evaluated non-OK was logged as a rejected request.
    lapi_set '{"live":[]}'
    apache_start "$(regr_conf '<Location /xmlrpc.php>
    Require all denied
</Location>')"
    [ "$(harness_request xmlrpc.php)" = 403 ]
    refute_blamed_the_api
}

# --- #8 / #13: redirects ----------------------------------------------------
#
# issues/8, issues/13
#
# Reported: with Crowdsec On a 3xx came back with no Location and a blank href
# in the body, and the error log claimed the API had returned 301. Covered here
# in each shape that reaches the access hook: mod_dir's trailing slash,
# mod_alias in a directory, and a mod_rewrite [R].

@test "#13 DirectorySlash keeps its Location on a cold cache" {
    # /guarded is a directory; mod_dir redirects to /guarded/ from the handler,
    # long after the access hook. This is the reported /links -> /links/ case.
    lapi_set '{"live":[]}'
    apache_start "$(regr_conf)"
    [ "$(harness_request guarded)" = 301 ]
    [[ "$(resp_header Location)" == */guarded/ ]]
    # the href in the body went blank too, so assert the document as well
    grep -q '/guarded/' "$HARNESS_DIR/resp.body"
    refute_blamed_the_api
}

@test "#8 a per-directory Redirect keeps its Location on a cold cache" {
    # In <Directory> mod_alias applies the redirect from fixups instead of
    # returning it from translate_name, so the access hook runs first.
    lapi_set '{"live":[]}'
    apache_start "$(regr_conf "<Directory \"$HARNESS_DIR/htdocs/open\">
    Redirect 301 /open/moved /target
</Directory>")"
    [ "$(harness_request open/moved)" = 301 ]
    [[ "$(resp_header Location)" == */target ]]
    refute_blamed_the_api
}

@test "#13 a rewrite redirect keeps its Location on a cold cache" {
    lapi_set '{"live":[]}'
    apache_start "$(regr_conf "<Directory \"$HARNESS_DIR/htdocs/open\">
    RewriteEngine On
    RewriteRule ^bounce\$ /target [R=301,L]
</Directory>")"
    [ "$(harness_request open/bounce)" = 301 ]
    [[ "$(resp_header Location)" == */target ]]
}

@test "#8 a server-scope Redirect keeps its Location on a cold cache" {
    # The literal config from the report. mod_alias returns this one from
    # translate_name, ahead of the access hook, so it was never the broken
    # shape - kept so a hook moved earlier cannot quietly take it over.
    lapi_set '{"live":[]}'
    apache_start "$(regr_conf 'Redirect 301 /moved /target')"
    [ "$(harness_request moved)" = 301 ]
    [[ "$(resp_header Location)" == */target ]]
}

@test "#13 a banned client is blocked rather than redirected" {
    # The counterpart again: a redirecting path must still enforce. Uses the
    # DirectorySlash shape, the one that does reach the hook.
    lapi_set "{\"live\":[$(decision 127.0.0.1 Ip)]}"
    apache_start "$(regr_conf)"
    [ "$(harness_request guarded)" = 429 ]
    [ -z "$(resp_header Location)" ]
}

# --- #10: ProxyPreserveHost -------------------------------------------------
#
# issues/10
#
# Reported: AH01092 in the error log for every request, behind Varnish. The
# decision subrequest carried no Host and went out through mod_proxy, which
# warns and substitutes the hostname when ProxyPreserveHost is on. 1.0 puts no
# synthetic request through mod_proxy at all.

@test "#10 ProxyPreserveHost logs no AH01092" {
    lapi_set '{"live":[]}'
    apache_start "$(regr_conf "ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto expr=%{REQUEST_SCHEME}
ProxyPass /proxied http://127.0.0.1:$LAPI_PORT/v1/decisions
ProxyPassReverse /proxied http://127.0.0.1:$LAPI_PORT/v1/decisions")"
    [ "$(harness_request proxied)" = 200 ]
    ! grep -q AH01092 "$HARNESS_DIR/logs/error.log"
}

# --- #12: user agent --------------------------------------------------------
#
# issues/12
#
# Reported: the local API logged "bad user agent" for every call. 0.1 sent
# ap_get_server_description(), e.g.
#   Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13 mod_perl/2.0.13 Perl/v5.38.2
# The API wants the bouncer's own name/version and warns on anything else,
# which is also what makes cscli bouncers list show a type and a version.

@test "#12 the live query identifies itself as the bouncer" {
    lapi_set '{"live":[],"record_headers":true}'
    apache_start "$(regr_conf)"
    [ "$(harness_request)" = 200 ]
    ua="$(lapi_header decisions user-agent)"
    [[ "$ua" =~ ^crowdsec-apache2-bouncer/[0-9]+\.[0-9]+ ]]
    # the shape the API warns about: a product list, with spaces in it
    [[ "$ua" != *" "* ]]
}

@test "#12 the stream pull identifies itself the same way" {
    lapi_set '{"decisions":[],"sticky":true,"record_headers":true}'
    apache_start "CrowdsecMode stream
CrowdsecUpdateFrequency 1s
CrowdsecCache shmcb:crowdsec-regr(1048576)
CrowdsecFallback allow
Crowdsec On"
    wait_primed
    ua="$(lapi_header stream user-agent)"
    [[ "$ua" =~ ^crowdsec-apache2-bouncer/[0-9]+\.[0-9]+ ]]
    [[ "$ua" != *" "* ]]
}
