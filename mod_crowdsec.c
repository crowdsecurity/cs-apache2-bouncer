/*
 * MIT License
 *
 * Copyright (c) 2024 Graham Leggett
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


/*
 * The Apache mod_crowdsec module checks each request against the decisions
 * published by CrowdSec at https://www.crowdsec.net.
 *
 * When blocked, this module returns 429 Too Many Requests, as described in
 * https://datatracker.ietf.org/doc/html/rfc6585#section-4, or redirects to
 * the URL given by CrowdsecLocation.
 *
 *  Author: Graham Leggett
 *
 * Decisions are obtained either per request (CrowdsecMode live) or from the
 * decision stream, polled in the background and held in a shared cache
 * (CrowdsecMode stream). Stream mode needs CrowdsecCache and keeps every
 * decision locally, so it costs no round trip on the request path.
 *
 * Basic configuration:
 *
 * <IfModule !crowdsec_module>
 *   LoadModule crowdsec_module modules/mod_crowdsec.so
 * </IfModule>
 * <IfModule !socache_shmcb_module>
 *   LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
 * </IfModule>
 *
 * CrowdsecURL http://localhost:8080
 * CrowdsecAPIKey [...]
 *
 * # stream mode wants room for every decision; see the directive docs for
 * # how to size this
 * CrowdsecCache shmcb:crowdsec(16777216)
 * CrowdsecMode stream
 * CrowdsecUpdateFrequency 10s
 *
 * <Location />
 *   Crowdsec on
 * </Location>
 *
 * <Location /one/>
 *   Crowdsec on
 *   ErrorDocument 429 "IP Address Blocked"
 * </Location>
 *
 * <Location /four/>
 *   Crowdsec on
 *   CrowdsecLocation https://somewhere.example.com/blocked.html?ip=%{REMOTE_ADDR}
 * </Location>
 */

#include "crowdsec_config.h"

#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_mpm.h"

#include "apr_strings.h"

#include "crowdsec_appsec.h"
#include "crowdsec_http.h"
#include "crowdsec_lapi.h"
#include "crowdsec_util.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"

static const char *const crowdsec_id = "crowdsec";

/* Only used to report our own identity to LAPI; cscli bouncers list shows
 * this, and the old code sent Apache's server description instead, so every
 * Apache bouncer appeared as an unknown type.
 */
#ifndef CROWDSEC_BOUNCER_VERSION
#define CROWDSEC_BOUNCER_VERSION "1.0.0"
#endif

static apr_status_t cleanup_lock(void *data)
{
    server_rec *s = data;
    crowdsec_server_rec *sconf = ap_get_module_config(s->module_config,
                                                      &crowdsec_module);

    if (sconf->cache_mutex) {
        apr_global_mutex_destroy(sconf->cache_mutex);
        sconf->cache_mutex = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t cleanup_cache(void *data)
{
    server_rec *s = data;
    crowdsec_server_rec *sconf = ap_get_module_config(s->module_config,
                                                      &crowdsec_module);

    if (sconf->cache_instance) {
        sconf->cache_provider->destroy(sconf->cache_instance, s);
        sconf->cache_instance = NULL;
    }
    return APR_SUCCESS;
}

int crowdsec_blocked_code(crowdsec_config_rec *conf)
{
    /* Resolved here rather than seeded in the config creator, so that an unset
     * parent scope is not mistaken for one that chose a value explicitly. The
     * default cannot be left as the struct's zero: OK == 0 in Apache, which
     * check_access reads as DECLINED and lets a banned request through.
     */
    return conf->blockedhttpcode_set ? conf->blockedhttpcode
        : HTTP_TOO_MANY_REQUESTS;
}

const char *crowdsec_client_ip(request_rec *r, crowdsec_config_rec *conf)
{
    /* useragent_ip is what mod_remoteip rewrites from RemoteIPHeader. That is
     * correct behind a trusted proxy and a liability without one, so an
     * operator who cannot fix the proxy configuration can pin us to the real
     * peer instead.
     */
    if (conf->trust_useragent_ip_set && !conf->trust_useragent_ip) {
        return r->connection->client_ip;
    }
    return r->useragent_ip;
}

/* ------------------------------------------------------------ the decision */

static int crowdsec_apply(request_rec *r, crowdsec_config_rec *conf,
                          crowdsec_rem_t rem, const char *ip)
{
    int code;

    if (rem == CROWDSEC_REM_UNKNOWN || rem == CROWDSEC_REM_CAPTCHA) {
        /* This module serves no captcha, and an action invented by an
         * administrator means nothing to us. Either is resolved by
         * CrowdsecRemediationFallback, which defaults to ban so that an
         * unservable remediation is never silently downgraded to allow.
         */
        rem = conf->remediation_fallback_set ? conf->remediation_fallback
            : CROWDSEC_REM_BAN;
    }
    if (rem < CROWDSEC_REM_BAN) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "crowdsec: ip address '%s' not blocked, request "
                      "accepted: %s", ip, r->uri);
        apr_table_setn(r->subprocess_env, "CROWDSEC_STATUS", "allow");
        return DECLINED;
    }

    code = crowdsec_blocked_code(conf);
    apr_table_setn(r->subprocess_env, "CROWDSEC_STATUS", "ban");

    if (conf->location) {
        const char *location, *err = NULL;

        location = ap_expr_str_exec(r, conf->location, &err);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "crowdsec: CrowdsecLocation: can't evaluate "
                          "location expression: %s", err);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "crowdsec: ip address '%s' blocked, request redirected "
                      "to '%s': %s", ip, location, r->uri);
        ap_custom_response(r, code, location);
        return code;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                  "crowdsec: ip address '%s' blocked, request rejected: %s",
                  ip, r->uri);
    return code;
}

static int crowdsec_fallback(request_rec *r, crowdsec_config_rec *conf,
                             const char *why)
{
    crowdsec_fallback_t fb = conf->fallback;

    apr_table_setn(r->subprocess_env, "CROWDSEC_STATUS", why);

    switch (fb) {
    case CROWDSEC_ALLOW:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: %s; allowing the request (CrowdsecFallback "
                      "allow)", why);
        return DECLINED;
    case CROWDSEC_BLOCK:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: %s; blocking the request (CrowdsecFallback "
                      "block)", why);
        return crowdsec_apply(r, conf, CROWDSEC_REM_BAN,
                              crowdsec_client_ip(r, conf));
    case CROWDSEC_FAIL:
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: %s; failing the request (CrowdsecFallback "
                      "fail)", why);
        apr_table_setn(r->notes, "error-notes",
                       "Could not verify the request against the threat "
                       "intelligence service, the request has been rejected.");
        apr_table_setn(r->notes, "verbose-error-to", "*");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}

/* Set on every request_rec where this module actually reached a verdict.
 * r->notes is per-request_rec - an internal redirect gets a fresh table - so
 * walking r->prev distinguishes "already checked" from "never checked".
 */
#define CROWDSEC_NOTE_DECIDED "crowdsec-decided"

static int decided_earlier(request_rec *r)
{
    request_rec *prev;

    for (prev = r->prev; prev; prev = prev->prev) {
        if (apr_table_get(prev->notes, CROWDSEC_NOTE_DECIDED)) {
            return 1;
        }
    }
    return 0;
}

/* Resolved at the point of use, so an unset parent scope is not mistaken for
 * one that chose the default explicitly.
 */
static crowdsec_rem_t remediation_fallback(crowdsec_config_rec *conf)
{
    return conf->remediation_fallback_set ? conf->remediation_fallback
        : CROWDSEC_REM_BAN;
}

static int appsec_failure(request_rec *r, crowdsec_config_rec *conf,
                          crowdsec_rem_t *rem)
{
    if (conf->appsec_failure_action_set
        && conf->appsec_failure_action == CROWDSEC_APPSEC_DENY) {
        *rem = crowdsec_rem_merge(*rem, CROWDSEC_REM_BAN);
        return 1;
    }
    /* Fail open. This is an availability choice, not a security one: an
     * attacker who can degrade the engine buys themselves a window with no
     * inspection, which is what CrowdsecAppsecFailureAction deny is for.
     */
    return 0;
}

static int crowdsec_check_access(request_rec *r)
{
    crowdsec_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                     &crowdsec_module);
    crowdsec_server_rec *sconf = ap_get_module_config(r->server->module_config,
                                                      &crowdsec_module);
    crowdsec_req_rec *st;
    crowdsec_rem_t rem = CROWDSEC_REM_ALLOW;
    crowdsec_lookup_t lr;
    const char *ip;
    int appsec_on, challenge_path = 0;

    /* A subrequest is covered by the main request. */
    if (r->main) {
        return DECLINED;
    }
    /* An internal redirect inherits a verdict only if one was actually
     * reached. A RewriteRule out of an unprotected scope into a protected one
     * arrives here with r->prev set and nothing checked, so declining on
     * r->prev alone would hand the target over unchecked. An ErrorDocument
     * follows a request we did decide, so it still short-circuits here.
     *
     * The body is gone by this point, though: the original request consumed
     * it. A redirect that does reach the checks below therefore inspects
     * headers only - see the body handling in crowdsec_appsec_check.
     */
    if (r->prev && decided_earlier(r)) {
        /* The verdict carries over, but the body does not: the redirect lost
         * our input filter and HTTP_IN is already drained, so hand the
         * captured copy to this request's handler.
         */
        crowdsec_appsec_inherit_body(r);
        return DECLINED;
    }
    if (!sconf) {
        return DECLINED;
    }
    /* A forward-proxy request is a different threat model and r->unparsed_uri
     * means something else there. Reverse-proxied requests are deliberately
     * NOT excluded: ProxyPass sets PROXYREQ_REVERSE from translate_name, which
     * runs before this hook, so skipping them would leave every Apache acting
     * as a reverse proxy - a primary deployment for this module - with no
     * decision lookup at all.
     *
     * Keyed on proxyreq alone, not on M_CONNECT: with ProxyRequests off a
     * CONNECT is not a proxy request - Apache leaves proxyreq as
     * PROXYREQ_NONE and resolves the target against the document root - so
     * declining on the method let a banned client swap GET for CONNECT and be
     * served local content with no lookup and no inspection.
     */
    if (r->proxyreq == PROXYREQ_PROXY) {
        return DECLINED;
    }

    appsec_on = conf->appsec_enable_set && conf->appsec_enable;

    /* The challenge's own assets and its submit endpoint live outside whatever
     * <Location> enabled appsec, so without this the engine would never be
     * consulted for them, the origin would 404, and a challenged visitor would
     * be stuck for good - not blocked, not allowed. This is the one place the
     * module deliberately overrides a per-directory off.
     *
     * Matched on r->uri, which Apache has already decoded and collapsed, so a
     * traversal cannot slip past; the engine is still sent r->unparsed_uri,
     * because it routes on that and its rules need the raw form.
     */
    if (sconf->appsec_url
        && crowdsec_is_challenge_path(r->uri,
                                      sconf->appsec_internal_path
                                      ? sconf->appsec_internal_path
                                      : CROWDSEC_APPSEC_INTERNAL_DEFAULT)) {
        appsec_on = 1;
        challenge_path = 1;
    }

    if (!conf->enable && !appsec_on) {
        return DECLINED;
    }
    if (appsec_on && !sconf->appsec_url) {
        appsec_on = 0;
    }

    /* Past the enable gate, so this request really is being decided - by the
     * local API, by AppSec, or by the fallback below. Marking any earlier
     * would let a "Crowdsec off" scope claim a verdict it never reached, and
     * an internal redirect out of it would inherit that and skip its own
     * check.
     */
    apr_table_setn(r->notes, CROWDSEC_NOTE_DECIDED, "1");

    ip = crowdsec_client_ip(r, conf);
    if (!ip) {
        return crowdsec_fallback(r, conf, "no client address");
    }

    st = apr_pcalloc(r->pool, sizeof(*st));
    st->r = r;
    ap_set_module_config(r->request_config, &crowdsec_module, st);

    /* 1. The local API's view, from the stream cache or a live query. */
    if (conf->enable && sconf->url) {
        lr = crowdsec_lapi_lookup(r, sconf, ip, &rem);
        if (lr != CROWDSEC_LOOKUP_OK) {
            int fb = crowdsec_fallback(r, conf,
                                       lr == CROWDSEC_LOOKUP_UNPRIMED
                                       ? "the decision stream has not been "
                                         "loaded yet"
                                       : "could not query crowdsec");

            /* Only an allow fallback carries on. Returning here whenever the
             * local API was unreachable would also switch off a perfectly
             * healthy AppSec - and CROWDSEC_LOOKUP_UNPRIMED happens on every
             * start in stream mode, so inspection would be off for the first
             * seconds after each restart. It would also let the challenge
             * endpoints fall through to the origin, which is the
             * permanently-stuck case the carve-out exists to prevent.
             */
            if (fb != DECLINED) {
                return fb;
            }
            /* rem stays ALLOW; whatever AppSec says below decides. */
        }
    }

    /* 2. Inspection, unless the verdict is already as restrictive as it can
     * get. Nothing is gained by inspecting a request that is already banned.
     */
    if (appsec_on
        && (rem < CROWDSEC_REM_BAN
            || (conf->appsec_always_send_set && conf->appsec_always_send))) {
        switch (crowdsec_appsec_check(r, sconf, conf, st, ip)) {
        case CROWDSEC_APPSEC_OK:
            rem = crowdsec_rem_merge(rem,
                                     crowdsec_action_to_rem(st->verdict.action
                                                            ? st->verdict.action
                                                            : ""));
            /* A parse failure on a 403 sets the remediation directly. */
            if (st->verdict.rem > rem) {
                rem = st->verdict.rem;
            }
            break;
        case CROWDSEC_APPSEC_DROP:
            rem = crowdsec_rem_merge(rem, CROWDSEC_REM_BAN);
            break;
        case CROWDSEC_APPSEC_BADREQ:
            /* A body read that failed already knows why: 413 for
             * LimitRequestBody, 408 on a read timeout, 501 for an
             * unimplemented transfer encoding. AP_FILTER_ERROR means a filter
             * has already produced the response, so pass it straight through.
             * Flattening all of these to 400 is what the comment on
             * capture_body claimed was not happening.
             */
            if (st->read_rv != APR_SUCCESS) {
                if (st->read_rv == AP_FILTER_ERROR) {
                    return AP_FILTER_ERROR;
                }
                return ap_map_http_request_error(st->read_rv,
                                                 HTTP_BAD_REQUEST);
            }
            return HTTP_BAD_REQUEST;
        case CROWDSEC_APPSEC_FAIL:
        default:
            appsec_failure(r, conf, &rem);
            break;
        }
    }

    if (rem == CROWDSEC_REM_UNKNOWN || rem == CROWDSEC_REM_CAPTCHA) {
        if (rem == CROWDSEC_REM_CAPTCHA) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "crowdsec: a captcha was requested for '%s' but "
                          "this component cannot serve one; applying "
                          "CrowdsecRemediationFallback", ip);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "crowdsec: unrecognised remediation '%s' for '%s'; "
                          "applying CrowdsecRemediationFallback",
                          st->verdict.action ? st->verdict.action : "?", ip);
        }
        rem = remediation_fallback(conf);
    }

    if (rem == CROWDSEC_REM_CHALLENGE) {
        int rv;

        /* Only the engine can produce a challenge, because only it has the
         * page and the sealed cookie. A challenge arriving any other way - a
         * blocklist, or a local decision - has no body to serve, so it has to
         * fail closed.
         */
        rv = crowdsec_appsec_serve(r, &st->verdict);
        if (rv == DONE) {
            apr_table_setn(r->subprocess_env, "CROWDSEC_STATUS", "challenge");
            return DONE;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: a challenge was required for '%s' but could "
                      "not be served; blocking instead", ip);
        rem = CROWDSEC_REM_BAN;
    }

    if (rem >= CROWDSEC_REM_BAN) {
        return crowdsec_apply(r, conf, rem, ip);
    }

    /* Allowed. A challenge asset must never reach the origin even so: the
     * engine answers those itself and the origin has nothing to serve.
     */
    if (challenge_path) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: '%s' is a challenge endpoint but the engine "
                      "did not answer it; refusing rather than passing it to "
                      "the origin", r->uri);
        return HTTP_NOT_FOUND;
    }

    /* The body was consumed to inspect it, so put it back for the real
     * handler. Only here: on any other path the request does not proceed.
     */
    crowdsec_appsec_replay(r, st);

    return crowdsec_apply(r, conf, rem, ip);
}

/* ------------------------------------------------------- status handler */

static int crowdsec_status_handler(request_rec *r)
{
    crowdsec_server_rec *sconf;
    crowdsec_store_stats_t st;

    if (!r->handler || strcmp(r->handler, "crowdsec-status")) {
        return DECLINED;
    }
    if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }
    sconf = ap_get_module_config(r->server->module_config, &crowdsec_module);

    ap_set_content_type(r, "text/plain; charset=utf-8");
    ap_rprintf(r, "mode: %s\n",
               sconf->mode == CROWDSEC_MODE_STREAM ? "stream" : "live");
    ap_rprintf(r, "url: %s\n", sconf->url ? sconf->url : "(unset)");
    ap_rprintf(r, "cache: %s\n", sconf->cache_instance ? "yes" : "no");

    if (sconf->mode == CROWDSEC_MODE_STREAM
        && crowdsec_store_stats(r->server, sconf, &st)) {
        ap_rprintf(r, "primed: %s\n", st.primed_at ? "yes" : "no");
        ap_rprintf(r, "pulls: %u\n", (unsigned int) st.pulls);
        ap_rprintf(r, "stored: %u\n", (unsigned int) st.stored);
        ap_rprintf(r, "retained: %u\n", (unsigned int) st.retained);
        ap_rprintf(r, "last_pull_age_ms: %" APR_TIME_T_FMT "\n",
                   st.last_pull ? apr_time_as_msec(apr_time_now()
                                                   - st.last_pull) : -1);
    }
    else if (sconf->mode == CROWDSEC_MODE_STREAM) {
        ap_rputs("primed: no\n", r);
    }
    return OK;
}

/* ------------------------------------------------------------ lifecycle */

static int crowdsec_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptmp)
{
    apr_status_t rv = ap_mutex_register(pconf, crowdsec_id, NULL,
                                        APR_LOCK_DEFAULT, 0);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog,
                      "failed to register %s mutex", crowdsec_id);
        return 500;             /* An HTTP status would be a misnomer! */
    }
    return OK;
}

static int crowdsec_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                apr_pool_t *ptmp, server_rec *s)
{
    server_rec *s_vhost;
    int remoteip_loaded = ap_find_linked_module("mod_remoteip.c") != NULL;

    /* avg_id_len is 18: our longest key is family + prefix + 16 address bytes.
     * avg_obj_size is 32, comfortably over the 4-byte decision value, so the
     * provider sizes its subcaches for many small entries.
     */
    static struct ap_socache_hints cache_hints = { 18, 32, 60000000 };

    for (s_vhost = s; s_vhost; s_vhost = s_vhost->next) {
        crowdsec_server_rec *sconf =
            ap_get_module_config(s_vhost->module_config, &crowdsec_module);
        apr_status_t status;

        /* Only the server_rec that created the instance sets it up. A vhost
         * that inherited the pointer through the config merge would otherwise
         * re-init the same shmcb segment, guard it with a second mutex that
         * excludes nothing, and destroy it again at shutdown.
         */
        if (sconf->cache_owned) {
            status = ap_global_mutex_create(&sconf->cache_mutex, NULL,
                                            crowdsec_id, NULL, s_vhost, pconf,
                                            0);
            if (status != APR_SUCCESS) {
                ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog,
                              "failed to create %s mutex", crowdsec_id);
                return 500;
            }
            apr_pool_cleanup_register(pconf, s_vhost, cleanup_lock,
                                      apr_pool_cleanup_null);

            status = sconf->cache_provider->init(sconf->cache_instance,
                                                 crowdsec_id, &cache_hints,
                                                 s_vhost, pconf);
            if (status != APR_SUCCESS) {
                ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog,
                              "failed to initialise %s cache", crowdsec_id);
                return 500;
            }
            apr_pool_cleanup_register(pconf, s_vhost, cleanup_cache,
                                      apr_pool_cleanup_null);

            status = crowdsec_meta_create(pconf, sconf);
            if (status != APR_SUCCESS) {
                ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog,
                              "failed to create the %s shared control region",
                              crowdsec_id);
                return 500;
            }
        }

        /* AppSec authenticates with the same bouncer key as the local API,
         * so there is one directive for both.
         */
        if (!sconf->appsec_key) {
            sconf->appsec_key = sconf->key;
        }
        if (sconf->appsec_url && !sconf->appsec_key) {
            /* The engine answers 401 without a key, which would make every
             * request take the failure action. Say so now instead.
             */
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s_vhost,
                         "crowdsec: CrowdsecAppsecURL is set but "
                         "CrowdsecAPIKey is not; AppSec cannot authenticate");
            return 500;
        }

        if (!sconf->url && !sconf->appsec_url) {
            continue;
        }

        /* Stream mode keeps every decision in the shared cache, so without one
         * there is nowhere to put them and nothing would ever be blocked.
         * Refuse at startup rather than fail open at runtime.
         */
        if (sconf->mode == CROWDSEC_MODE_STREAM && !sconf->cache_instance) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s_vhost,
                         "crowdsec: CrowdsecMode stream requires CrowdsecCache "
                         "to be configured");
            return 500;
        }

        if (remoteip_loaded) {
            /* mod_remoteip's trusted-proxy list is private to it, so a notice
             * is all we can offer: with RemoteIPHeader set and no trusted
             * list, any client can choose the address we police.
             */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s_vhost,
                         "crowdsec: mod_remoteip is loaded and this module "
                         "trusts the address it reports; make sure "
                         "RemoteIPTrustedProxy or RemoteIPInternalProxy is "
                         "set, or use CrowdsecTrustUseragentIP off");
        }
    }

    /* A vhost that inherited the cache pointer has no mutex of its own, and
     * store_lock treats a NULL mutex as "nothing to lock" - so without this it
     * would read and write the shared segment unsynchronised. Hand it the
     * owner's mutex, and refuse to start if there is somehow no owner rather
     * than run unlocked.
     */
    for (s_vhost = s; s_vhost; s_vhost = s_vhost->next) {
        crowdsec_server_rec *sconf =
            ap_get_module_config(s_vhost->module_config, &crowdsec_module);
        server_rec *owner;

        if (!sconf->cache_instance || sconf->cache_mutex) {
            continue;
        }
        for (owner = s; owner; owner = owner->next) {
            crowdsec_server_rec *oconf =
                ap_get_module_config(owner->module_config, &crowdsec_module);

            if (oconf->cache_owned
                && oconf->cache_instance == sconf->cache_instance) {
                sconf->cache_mutex = oconf->cache_mutex;
                sconf->meta_shm = oconf->meta_shm;
                sconf->meta = oconf->meta;
                break;
            }
        }
        if (!sconf->cache_mutex) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s_vhost,
                         "crowdsec: the decision cache has no owning server; "
                         "refusing to use it without a lock");
            return 500;
        }
    }
    return OK;
}

static void crowdsec_child_init(apr_pool_t *pchild, server_rec *s)
{
    server_rec *s_vhost;
    apr_reslist_t *handles = NULL;
    int threads = 1;

    /* curl_global_init is documented as not thread-safe and sets up TLS
     * library state that does not survive a fork cleanly, so it belongs here
     * rather than in post_config, which also runs twice and in the parent.
     */
    if (crowdsec_http_child_init(pchild) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "crowdsec: could not initialise libcurl; this child will "
                     "apply CrowdsecFallback to every request");
        return;
    }
    if (!crowdsec_http_proto_ok()) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "crowdsec: this libcurl accepts neither protocol "
                     "allowlist option, so requests are not confined to "
                     "http and https");
    }

    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads);
    if (threads < 1) {
        threads = 1;
    }

    /* One pool for the whole child, not one per vhost. The handles carry no
     * per-vhost state - every option is set per exchange - so a pool each
     * would multiply the handle count by the number of vhosts for no gain.
     * Sized at one handle per worker thread, so acquiring one can never block
     * and turn engine latency into a stalled request.
     */
    if (crowdsec_http_pool_create(pchild, threads, &handles) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "crowdsec: could not create the curl handle pool; this "
                     "child will apply CrowdsecFallback to every request");
        return;
    }

    for (s_vhost = s; s_vhost; s_vhost = s_vhost->next) {
        crowdsec_server_rec *sconf =
            ap_get_module_config(s_vhost->module_config, &crowdsec_module);

        /* Either endpoint needs handles. Guarding on url alone left an
         * AppSec-only configuration (CrowdsecAppsecURL without CrowdsecURL,
         * which post_config accepts) with no handles at all, so every
         * inspection failed instantly and the default passthrough let
         * everything by uninspected - silently.
         */
        if ((!sconf->url && !sconf->appsec_url) || sconf->curl_handles) {
            continue;           /* vhosts sharing a config share its handles */
        }
        sconf->curl_handles = handles;
        if (crowdsec_memo_init(pchild, sconf) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s_vhost,
                         "crowdsec: could not create the decision memo");
        }
    }

    crowdsec_poller_start(pchild, s);
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(crowdsec_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(crowdsec_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(crowdsec_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(crowdsec_status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(crowdsec_check_access, NULL, NULL, APR_HOOK_FIRST);
    crowdsec_appsec_register(p);
}

AP_DECLARE_MODULE(crowdsec) = {
    STANDARD20_MODULE_STUFF,
    create_crowdsec_dir_config,
    merge_crowdsec_dir_config,
    create_crowdsec_server_config,
    merge_crowdsec_server_config,
    crowdsec_cmds,
    register_hooks
};
