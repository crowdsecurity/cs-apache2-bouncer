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
    /* CrowdsecBlockedHTTPCode gets no default in create_crowdsec_dir_config,
     * and Apache spells success as OK == 0 - so an unset directive used to
     * return 0, which check_access reads as DECLINED, and the banned request
     * went through. Resolved here rather than in the config creator so that
     * an unset parent scope is not mistaken for one that set it explicitly.
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

/* What to do when we could not get an answer at all. */
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

static int crowdsec_check_access(request_rec *r)
{
    crowdsec_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                     &crowdsec_module);
    crowdsec_server_rec *sconf = ap_get_module_config(r->server->module_config,
                                                      &crowdsec_module);
    crowdsec_rem_t rem = CROWDSEC_REM_ALLOW;
    crowdsec_lookup_t lr;
    const char *ip;

    /* A subrequest is covered by the main request. */
    if (r->main) {
        return DECLINED;
    }
    /* An internal redirect inherits a verdict only if one was actually
     * reached. A RewriteRule out of an unprotected scope into a protected one
     * arrives here with r->prev set and nothing checked, so declining on
     * r->prev alone would hand the target over unchecked. An ErrorDocument
     * follows a request we did decide, so it still short-circuits here.
     */
    if (r->prev && decided_earlier(r)) {
        return DECLINED;
    }
    if (!conf->enable || !sconf || !sconf->url) {
        return DECLINED;
    }
    /* A forward-proxy request is a different threat model and r->unparsed_uri
     * means something else there. Reverse-proxied requests are deliberately
     * NOT excluded: ProxyPass sets PROXYREQ_REVERSE from translate_name, which
     * runs before this hook, so skipping them would leave every Apache acting
     * as a reverse proxy - a primary deployment for this module - with no
     * decision lookup at all.
     */
    if (r->proxyreq == PROXYREQ_PROXY || r->method_number == M_CONNECT) {
        return DECLINED;
    }
    apr_table_setn(r->notes, CROWDSEC_NOTE_DECIDED, "1");

    ip = crowdsec_client_ip(r, conf);
    if (!ip) {
        return crowdsec_fallback(r, conf, "no client address");
    }

    lr = crowdsec_lapi_lookup(r, sconf, ip, &rem);

    switch (lr) {
    case CROWDSEC_LOOKUP_OK:
        return crowdsec_apply(r, conf, rem, ip);
    case CROWDSEC_LOOKUP_UNPRIMED:
        /* Stream mode, before the first pull has finished. Every address
         * looks clean here, which is a real if brief window, so it is the
         * admin's CrowdsecFallback choice rather than an implicit allow.
         */
        return crowdsec_fallback(r, conf,
                                 "the decision stream has not been loaded yet");
    case CROWDSEC_LOOKUP_FAIL:
    default:
        return crowdsec_fallback(r, conf, "could not query crowdsec");
    }
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

        if (!sconf->url) {
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

        if (!sconf->url || sconf->curl_handles) {
            continue;           /* vhosts sharing a config share its handles */
        }
        sconf->curl_handles = handles;
        if (crowdsec_memo_init(pchild, sconf) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s_vhost,
                         "crowdsec: could not create the decision memo");
            continue;
        }
        sconf->curl_ok = 1;
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
}

/* ------------------------------------------------------------ config */

static void *create_crowdsec_dir_config(apr_pool_t *p, char *d)
{
    /* Defaults are deliberately not seeded here: a value set in the creator is
     * indistinguishable from one an administrator wrote, which breaks the
     * *_set merge for child scopes. Each is resolved at the point of use.
     */
    return apr_pcalloc(p, sizeof(crowdsec_config_rec));
}

#define MERGE(field)                                                    \
    new->field = (add->field##_set == 0) ? base->field : add->field;    \
    new->field##_set = add->field##_set || base->field##_set

static void *merge_crowdsec_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    crowdsec_config_rec *new = apr_pcalloc(p, sizeof(crowdsec_config_rec));
    crowdsec_config_rec *add = addv;
    crowdsec_config_rec *base = basev;

    MERGE(enable);
    MERGE(fallback);
    MERGE(location);
    MERGE(blockedhttpcode);
    MERGE(remediation_fallback);
    MERGE(trust_useragent_ip);

    return new;
}

static void *create_crowdsec_server_config(apr_pool_t *p, server_rec *s)
{
    crowdsec_server_rec *conf = apr_pcalloc(p, sizeof(crowdsec_server_rec));

    conf->cache_timeout = CROWDSEC_CACHE_TIMEOUT_DEFAULT;
    conf->update_frequency = CROWDSEC_UPDATE_FREQ_DEFAULT;
    conf->connect_timeout = CROWDSEC_CONNECT_TIMEOUT_DEFAULT;
    conf->timeout = CROWDSEC_TIMEOUT_DEFAULT;
    conf->mode = CROWDSEC_MODE_LIVE;

    return conf;
}

static void *merge_crowdsec_server_config(apr_pool_t *p, void *basev,
                                          void *addv)
{
    crowdsec_server_rec *new = apr_pcalloc(p, sizeof(crowdsec_server_rec));
    crowdsec_server_rec *add = addv;
    crowdsec_server_rec *base = basev;

    MERGE(url);
    MERGE(key);
    MERGE(mode);
    MERGE(update_frequency);
    MERGE(connect_timeout);
    MERGE(timeout);
    MERGE(cache_timeout);

    /* provider and instance travel together. */
    new->cache_provider = (add->cache_provider_set == 0)
        ? base->cache_provider : add->cache_provider;
    new->cache_instance = (add->cache_provider_set == 0)
        ? base->cache_instance : add->cache_instance;
    new->cache_provider_set = add->cache_provider_set
        || base->cache_provider_set;

    return new;
}

/* ------------------------------------------------------- directives */

static const char *set_crowdsec(cmd_parms *cmd, void *dconf, int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->enable = flag;
    conf->enable_set = 1;

    return NULL;
}

static const char *set_crowdsec_trust_useragent_ip(cmd_parms *cmd, void *dconf,
                                                   int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->trust_useragent_ip = flag;
    conf->trust_useragent_ip_set = 1;

    return NULL;
}

static const char *set_crowdsec_fallback(cmd_parms *cmd, void *dconf,
                                         const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(arg, "fail")) {
        conf->fallback = CROWDSEC_FAIL;
    }
    else if (!strcmp(arg, "block")) {
        conf->fallback = CROWDSEC_BLOCK;
    }
    else if (!strcmp(arg, "allow")) {
        conf->fallback = CROWDSEC_ALLOW;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecFallback '%s'. Valid "
                            "values are fail, block and allow.", arg);
    }
    conf->fallback_set = 1;

    return NULL;
}

static const char *set_crowdsec_remediation_fallback(cmd_parms *cmd,
                                                     void *dconf,
                                                     const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(arg, "ban")) {
        conf->remediation_fallback = CROWDSEC_REM_BAN;
    }
    else if (!strcmp(arg, "allow")) {
        conf->remediation_fallback = CROWDSEC_REM_ALLOW;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecRemediationFallback "
                            "'%s'. Valid values are ban and allow.", arg);
    }
    conf->remediation_fallback_set = 1;

    return NULL;
}

static const char *set_crowdsec_blockedhttpcode(cmd_parms *cmd, void *dconf,
                                                const char *arg)
{
    crowdsec_config_rec *conf = dconf;
    apr_off_t code;

    /* Not atoi: it cannot tell "0" from "banana", and silently reading a
     * typo as zero here used to mean OK, which means "allow".
     */
    if (!crowdsec_parse_size(arg, &code)) {
        return apr_psprintf(cmd->pool, "CrowdsecBlockedHTTPCode '%s' is not a "
                            "number.", arg);
    }
    switch (code) {
    case HTTP_TOO_MANY_REQUESTS:
    case HTTP_FORBIDDEN:
    case HTTP_INTERNAL_SERVER_ERROR:
        conf->blockedhttpcode = (http_code) code;
        break;
    default:
        return apr_psprintf(cmd->pool, "Unknown CrowdsecBlockedHTTPCode '%s'. "
                            "Valid values are 403, 500 and 429.", arg);
    }
    conf->blockedhttpcode_set = 1;

    return NULL;
}

static const char *set_crowdsec_location(cmd_parms *cmd, void *dconf,
                                         const char *arg)
{
    crowdsec_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->location = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
                                       &expr_err, NULL);
    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in CrowdsecLocation: ",
                           expr_err, NULL);
    }
    conf->location_set = 1;

    return NULL;
}

static const char *set_crowdsec_url(cmd_parms *cmd, void *dconf,
                                    const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    apr_size_t len;

    if (!*arg) {
        return "CrowdsecURL must not be empty.";
    }
    /* The URL is concatenated with the endpoint path, so a trailing slash
     * would produce a double slash and a 404 that looks like a bad key.
     */
    len = strlen(arg);
    while (len > 1 && arg[len - 1] == '/') {
        len--;
    }
    sconf->url = apr_pstrmemdup(cmd->pool, arg, len);
    sconf->url_set = 1;

    return NULL;
}

static const char *set_crowdsec_api_key(cmd_parms *cmd, void *dconf,
                                        const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);

    /* Caught here rather than per request: the key goes into a header, and a
     * stray newline in a config file would otherwise inject one.
     */
    if (!crowdsec_hdr_value_ok(arg) || !*arg) {
        return "CrowdsecAPIKey is empty or contains characters that cannot "
            "appear in an HTTP header.";
    }
    sconf->key = arg;
    sconf->key_set = 1;

    return NULL;
}

static const char *set_crowdsec_mode(cmd_parms *cmd, void *dconf,
                                     const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);

    if (!strcmp(arg, "live")) {
        sconf->mode = CROWDSEC_MODE_LIVE;
    }
    else if (!strcmp(arg, "stream")) {
        sconf->mode = CROWDSEC_MODE_STREAM;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecMode '%s'. Valid "
                            "values are live and stream.", arg);
    }
    sconf->mode_set = 1;

    return NULL;
}

static const char *parse_interval(cmd_parms *cmd, const char *arg,
                                 const char *name, apr_interval_time_t max,
                                 apr_interval_time_t *out)
{
    apr_interval_time_t t;

    if (ap_timeout_parameter_parse(arg, &t, "s") != APR_SUCCESS) {
        return apr_psprintf(cmd->pool, "%s '%s' is not a valid duration. Use "
                            "e.g. 200ms, 5s or 2min.", name, arg);
    }
    if (t <= 0) {
        return apr_psprintf(cmd->pool, "%s must be greater than zero.", name);
    }
    if (t > max) {
        return apr_psprintf(cmd->pool, "%s is too large.", name);
    }
    *out = t;

    return NULL;
}

static const char *set_crowdsec_update_frequency(cmd_parms *cmd, void *dconf,
                                                 const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecUpdateFrequency",
                                     apr_time_from_sec(3600),
                                     &sconf->update_frequency);

    if (err) {
        return err;
    }
    sconf->update_frequency_set = 1;

    return NULL;
}

static const char *set_crowdsec_connect_timeout(cmd_parms *cmd, void *dconf,
                                                const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecConnectTimeout",
                                     apr_time_from_sec(60),
                                     &sconf->connect_timeout);

    if (err) {
        return err;
    }
    sconf->connect_timeout_set = 1;

    return NULL;
}

static const char *set_crowdsec_timeout(cmd_parms *cmd, void *dconf,
                                        const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecTimeout",
                                     apr_time_from_sec(300),
                                     &sconf->timeout);

    if (err) {
        return err;
    }
    sconf->timeout_set = 1;

    return NULL;
}

static const char *set_crowdsec_cache(cmd_parms *cmd, void *dconf,
                                      const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *errmsg, *name, *args = ap_strchr_c(arg, ':');

    if (args) {
        name = apr_pstrmemdup(cmd->temp_pool, arg, args - arg);
        args++;
    }
    else {
        name = arg;
    }

    sconf->cache_provider =
        ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, name,
                           AP_SOCACHE_PROVIDER_VERSION);
    if (!sconf->cache_provider) {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecCache provider '%s'. "
                            "Maybe you need to load mod_socache_%s?", name,
                            name);
    }
    errmsg = sconf->cache_provider->create(&sconf->cache_instance, args,
                                           cmd->temp_pool, cmd->pool);
    if (errmsg) {
        return apr_psprintf(cmd->pool, "CrowdsecCache: %s", errmsg);
    }
    sconf->cache_provider_set = 1;
    /* This server_rec created the instance, so it is the one that initialises
     * and destroys it. merge_crowdsec_server_config deliberately does not
     * propagate this bit.
     */
    sconf->cache_owned = 1;

    return NULL;
}

static const char *set_crowdsec_cache_timeout(cmd_parms *cmd, void *dconf,
                                              const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecCacheTimeout",
                                     apr_time_from_sec(86400),
                                     &sconf->cache_timeout);

    if (err) {
        return err;
    }
    sconf->cache_timeout_set = 1;

    return NULL;
}

static const command_rec crowdsec_cmds[] = {
    AP_INIT_FLAG("Crowdsec", set_crowdsec, NULL, RSRC_CONF | ACCESS_CONF,
                 "Check requests in this scope against crowdsec. Default off."),
    AP_INIT_TAKE1("CrowdsecFallback", set_crowdsec_fallback, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "What to do when crowdsec cannot be consulted, including "
                  "before the decision stream has loaded: fail (500), block, "
                  "or allow. Default fail."),
    AP_INIT_TAKE1("CrowdsecBlockedHTTPCode", set_crowdsec_blockedhttpcode,
                  NULL, RSRC_CONF | ACCESS_CONF,
                  "Status returned to a blocked client: 429, 403 or 500. "
                  "Default 429."),
    AP_INIT_TAKE1("CrowdsecRemediationFallback",
                  set_crowdsec_remediation_fallback, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "What an AppSec remediation this component cannot serve "
                  "(captcha, or one defined by the administrator) becomes: ban "
                  "or allow. Default ban. Does not apply to local API "
                  "decisions, which are always enforced as a ban."),
    AP_INIT_TAKE1("CrowdsecLocation", set_crowdsec_location, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "URL or path to redirect a blocked client to. Supports "
                  "expressions, e.g. /blocked?ip=%{REMOTE_ADDR}."),
    AP_INIT_FLAG("CrowdsecTrustUseragentIP",
                 set_crowdsec_trust_useragent_ip, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Trust the client address reported by modules such as "
                 "mod_remoteip. Default on. Turn off to use the connection's "
                 "real peer instead, when no trusted-proxy list is in place."),
    AP_INIT_TAKE1("CrowdsecURL", set_crowdsec_url, NULL, RSRC_CONF,
                  "Base URL of the crowdsec local API, e.g. "
                  "http://localhost:8080."),
    AP_INIT_TAKE1("CrowdsecAPIKey", set_crowdsec_api_key, NULL, RSRC_CONF,
                  "API key for this bouncer, from cscli bouncers add."),
    AP_INIT_TAKE1("CrowdsecMode", set_crowdsec_mode, NULL, RSRC_CONF,
                  "live queries the API per request; stream polls the decision "
                  "stream in the background and needs CrowdsecCache. "
                  "Default live."),
    AP_INIT_TAKE1("CrowdsecUpdateFrequency", set_crowdsec_update_frequency,
                  NULL, RSRC_CONF,
                  "How often to poll the decision stream. Default 10s."),
    AP_INIT_TAKE1("CrowdsecConnectTimeout", set_crowdsec_connect_timeout, NULL,
                  RSRC_CONF,
                  "How long to wait for a connection to the API. Default 1s."),
    AP_INIT_TAKE1("CrowdsecTimeout", set_crowdsec_timeout, NULL, RSRC_CONF,
                  "Total budget for one API request. Default 5s. A stream pull "
                  "is allowed a multiple of this."),
    AP_INIT_TAKE1("CrowdsecCache", set_crowdsec_cache, NULL, RSRC_CONF,
                  "Shared cache for decisions, e.g. shmcb or "
                  "shmcb:crowdsec(16777216). Required by stream mode, where it "
                  "must hold every decision. Measured: 100000 decisions need "
                  "at least 6MB and 1000000 fit in 128MB, so budget about 128 "
                  "bytes per decision for headroom. Too small and decisions "
                  "are silently evicted, leaving those clients unblocked; the "
                  "error log reports it after each pull."),
    AP_INIT_TAKE1("CrowdsecCacheTimeout", set_crowdsec_cache_timeout, NULL,
                  RSRC_CONF,
                  "How long one address's verdict is remembered in-process. "
                  "Default 60s."),
    {NULL}
};

AP_DECLARE_MODULE(crowdsec) = {
    STANDARD20_MODULE_STUFF,
    create_crowdsec_dir_config,
    merge_crowdsec_dir_config,
    create_crowdsec_server_config,
    merge_crowdsec_server_config,
    crowdsec_cmds,
    register_hooks
};
