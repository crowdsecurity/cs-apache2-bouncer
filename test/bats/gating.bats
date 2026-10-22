#!/usr/bin/env bats
# Which requests reach the decision lookup at all. Each test here covers a
# request shape the module used to skip entirely: a reverse-proxied request, an
# internal redirect out of an unprotected scope, and a vhost that inherited the
# cache.

load "../lib/harness.sh"

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
CrowdsecCache shmcb:crowdsec-gating(4194304)
CrowdsecCacheTimeout 1s
CrowdsecFallback allow
CONF
}

# --- reverse proxy ---------------------------------------------------------
#
# ProxyPass sets r->proxyreq = PROXYREQ_REVERSE from translate_name, which runs
# before access_checker. Excluding every proxyreq left reverse-proxy
# deployments with no lookup at all.

@test "a banned client is blocked on a reverse-proxied location" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)
Crowdsec On
ProxyPass /proxied http://127.0.0.1:$LAPI_PORT/v1/decisions
ProxyPassReverse /proxied http://127.0.0.1:$LAPI_PORT/v1/decisions"
    wait_primed
    [ "$(http_status proxied)" = 429 ]
}

@test "a clean client still reaches the proxied backend" {
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)
Crowdsec On
ProxyPass /proxied http://127.0.0.1:$LAPI_PORT/v1/decisions
ProxyPassReverse /proxied http://127.0.0.1:$LAPI_PORT/v1/decisions"
    wait_primed
    [ "$(http_status proxied)" = 200 ]
}

# --- internal redirects ----------------------------------------------------
#
# A per-directory RewriteRule reaches its target through ap_internal_redirect,
# which sets r->prev. The module used to decline on r->prev alone, so a rewrite
# out of a "Crowdsec off" scope into a protected one skipped the check
# entirely: /open/jump served the protected content to a banned client while
# /guarded/index.html returned 429 to the same client.
#
# A server-context rule with [PT] will not do: it rewrites in place on the same
# request_rec, never sets r->prev, and so cannot catch this.

redirect_conf() {
    cat <<CONF
$(stream_conf)
Crowdsec Off
<Directory "$HARNESS_DIR/htdocs/open">
    RewriteEngine On
    RewriteRule ^jump\$ /guarded/index.html
</Directory>
<Location /guarded>
    Crowdsec On
</Location>
CONF
}

@test "an internal redirect into a protected scope is still checked" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(redirect_conf)"
    wait_primed
    [ "$(http_status guarded/index.html)" = 429 ]
    # The bypass: same client, same target, reached by redirect.
    [ "$(http_status open/jump)" = 429 ]
    run curl -s --max-time 10 "http://127.0.0.1:$APACHE_PORT/open/jump"
    [ "$output" != "guarded-ok" ]
}

@test "that same redirect serves the target when the client is clean" {
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(redirect_conf)"
    wait_primed
    run curl -s --max-time 10 "http://127.0.0.1:$APACHE_PORT/open/jump"
    [ "$output" = "guarded-ok" ]
}

# The same shape one level down: the source scope is checked against the local
# API, the target also has AppSec. The note used to say only "decided", so the
# redirect inherited a verdict that never involved the WAF.
waf_redirect_conf() {
    cat <<CONF
$(stream_conf)
CrowdsecAppsecURL http://127.0.0.1:$APPSEC_PORT
Crowdsec On
<Directory "$HARNESS_DIR/htdocs/open">
    RewriteEngine On
    RewriteRule ^jump\$ /guarded/index.html
</Directory>
<Location /guarded>
    CrowdsecAppsec On
</Location>
CONF
}

@test "a redirect into an AppSec scope is inspected" {
    appsec_start
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(waf_redirect_conf)"
    wait_primed
    [ "$(http_status guarded/index.html)" = 429 ]
    # The bypass: same request, reached through a rewrite. Reset first, so
    # what the stub saw can only come from the redirect.
    appsec_set '{"action":"ban","http_status":403,"status":403}'
    [ "$(http_status open/jump)" = 429 ]
    # What the client sent, not what the rewrite mapped it to.
    [ "$(appsec_seen uri)" = /open/jump ]
}

@test "a redirect into an AppSec scope still serves a clean request" {
    appsec_start
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(waf_redirect_conf)"
    wait_primed
    run curl -s --max-time 10 "http://127.0.0.1:$APACHE_PORT/open/jump"
    [ "$output" = "guarded-ok" ]
    [ "$(appsec_calls)" = 1 ]
}

@test "ErrorDocument still inherits the decision instead of looping" {
    # The block response is served through an internal redirect. The redirect
    # must reuse the verdict already reached, not re-enter the lookup, or a
    # blocked request could recurse.
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)
Crowdsec On
ErrorDocument 429 /denied.html"
    wait_primed
    [ "$(http_status)" = 429 ]
    run curl -s --max-time 10 "http://127.0.0.1:$APACHE_PORT/"
    [ "$output" = "denied-doc" ]
}

# --- vhosts inheriting the cache -------------------------------------------
#
# merge_crowdsec_server_config copies the cache instance into a fresh struct
# per vhost. Initialising per struct meant re-running socache init on the same
# segment, a second mutex that excluded nothing, and a poller per vhost - all
# in one child, so all with the same pid, so all electing themselves leader.

vhost_conf() {
    cat <<CONF
$(stream_conf)
Crowdsec On
$(mpm_many_children)
NameVirtualHost *
<VirtualHost *:$APACHE_PORT>
    ServerName first.example
    DocumentRoot "$HARNESS_DIR/htdocs"
    Crowdsec On
</VirtualHost>
<VirtualHost *:$APACHE_PORT>
    ServerName second.example
    DocumentRoot "$HARNESS_DIR/htdocs"
    Crowdsec On
</VirtualHost>
CONF
}

@test "vhosts inheriting the cache start exactly one poller" {
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(vhost_conf)"
    wait_primed
    sleep 2

    # One "is now polling" line per child, not one per vhost per child.
    pollers="$(grep -c "is now polling" "$HARNESS_DIR/logs/error.log" || true)"
    children="$(grep -oE "child \([0-9]+\) is now polling" \
        "$HARNESS_DIR/logs/error.log" | grep -oE "[0-9]+" | sort -u | wc -l)"
    [ "$pollers" -eq "$children" ]
}

@test "an inherited cache is initialised once per process, not once per vhost" {
    lapi_set "{\"decisions\":[$(decision 10.9.9.9 Ip)],\"sticky\":true}"
    apache_start "$(vhost_conf)"
    wait_primed
    harness_cleanup_apache

    # Apache runs post_config twice at startup, in different processes, so
    # count per pid rather than in total: the bug was the main server plus
    # both vhosts each initialising the same segment inside one process.
    # Threaded MPMs log "[pid N:tid M]", so do not anchor on the bracket.
    worst="$(grep "AH00830" "$HARNESS_DIR/logs/error.log" \
        | grep -oE "\[pid [0-9]+" | sort | uniq -c \
        | awk '{print $1}' | sort -rn | head -1)"
    [ -n "$worst" ]
    [ "$worst" -eq 1 ] || {
        grep "AH00830" "$HARNESS_DIR/logs/error.log" >&2; false
    }
}

@test "a banned client is blocked on a vhost that inherited the cache" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(vhost_conf)"
    wait_primed
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -H "Host: second.example" "http://127.0.0.1:$APACHE_PORT/"
    [ "$output" = 429 ]
}

# A vhost can set CrowdsecMode but cannot set CrowdsecCache, so it can end up
# in the other mode on the main server's cache. Both modes use the same keys,
# and live mode stores allow at the full-width key where store_probe looks
# first, so a cached allow would answer ahead of a stream range ban.
#
# Only servers that actually query the API are compared, so a main server
# declaring the cache for its vhosts without a CrowdsecURL of its own does not
# impose its default mode on them.

@test "a vhost cannot pick a different mode on the main server's cache" {
    lapi_set '{}'
    run apache_start "$(stream_conf)
Crowdsec On
NameVirtualHost *
<VirtualHost *:$APACHE_PORT>
    ServerName live.example
    DocumentRoot \"$HARNESS_DIR/htdocs\"
    Crowdsec On
    CrowdsecMode live
</VirtualHost>"
    [ "$status" -ne 0 ]
    grep -q "shares a CrowdsecCache with one in CrowdsecMode" \
        "$HARNESS_DIR/logs/error.log"
}

@test "a vhost agreeing with the cache's mode still starts" {
    lapi_set "{\"decisions\":[$(decision 127.0.0.1 Ip)],\"sticky\":true}"
    apache_start "$(stream_conf)
Crowdsec On
NameVirtualHost *
<VirtualHost *:$APACHE_PORT>
    ServerName same.example
    DocumentRoot \"$HARNESS_DIR/htdocs\"
    Crowdsec On
    CrowdsecMode stream
</VirtualHost>"
    wait_primed
    run curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -H "Host: same.example" "http://127.0.0.1:$APACHE_PORT/"
    [ "$output" = 429 ]
}
