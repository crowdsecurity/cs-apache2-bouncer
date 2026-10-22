/* The stream poller: one thread per child, agreeing on a single puller through
 * a lease in the shared control region that crowdsec_lapi.c owns.
 */
#include <string.h>
#include <unistd.h>

/* crowdsec_lapi.h pulls in httpd.h, which the rest of the Apache headers
 * require to have been included first.
 */
#include "crowdsec_lapi.h"

#include "http_log.h"
#include "http_protocol.h"
#include "ap_mpm.h"

#include "apr_strings.h"
#include "apr_thread_proc.h"

#include "crowdsec_http.h"
#include "crowdsec_metrics.h"
#include "crowdsec_util.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"
#include "crowdsec_store.h"

/* ------------------------------------------------------------- the poller */

/* Every child runs a poller thread and they agree on one leader through this
 * lease, so that a child killed by the OOM killer or a crash cannot stop
 * polling permanently: its lease goes stale and another child claims it.
 */

static int lease_claim(crowdsec_server_rec *sconf, int *took_over)
{
    lease_t lease;
    apr_time_t now = apr_time_now();
    apr_int64_t me = (apr_int64_t) getpid();
    apr_interval_time_t stale;
    int leader = 0;

    *took_over = 0;

    /* Two intervals of silence is enough to call it: one missed tick could
     * just be a slow pull, and a pull that runs longer than that keeps the
     * lease warm itself through lease_heartbeat, so reaching this point really
     * does mean the holder stopped running. Keeping the window short is what
     * bounds failover after a child is killed.
     */
    stale = sconf->update_frequency * 2;

    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
        return 0;
    }
    lease = sconf->meta->lease;

    if (lease.holder == me) {
        leader = 1;
    }
    else if (!lease.holder || now - lease.last_run > stale) {
        *took_over = lease.holder ? 1 : 0;
        leader = 1;
    }

    if (leader) {
        lease.holder = me;
        lease.last_run = now;
        sconf->meta->lease = lease;
    }
    crowdsec_store_unlock(sconf);

    return leader;
}

static void lease_release(crowdsec_server_rec *sconf)
{
    lease_t lease;

    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
        return;
    }
    /* Only drop it if it is still ours, so a child exiting late cannot evict
     * whoever took over from it.
     */
    lease = sconf->meta->lease;
    if (lease.holder == (apr_int64_t) getpid()) {
        lease.holder = 0;
        lease.last_run = 0;
        sconf->meta->lease = lease;
    }
    crowdsec_store_unlock(sconf);
}

/* Keeps the lease warm while a pull is running. Without this a startup pull
 * of a large blocklist can outlast the staleness window and get itself
 * declared dead mid-transfer; the alternative - widening the window to the
 * worst-case pull budget - would stretch failover after a child is killed from
 * two intervals to over a minute.
 */
typedef struct
{
    crowdsec_server_rec *sconf;
    apr_int64_t me;
    apr_time_t last_beat;
} heartbeat_ctx_t;

static int lease_heartbeat(void *data)
{
    heartbeat_ctx_t *hb = data;
    apr_time_t now = apr_time_now();
    int still_ours = 1;

    /* curl calls this far more often than the lease needs touching, and each
     * touch takes the global lock.
     */
    if (now - hb->last_beat < hb->sconf->update_frequency / 2) {
        return 0;
    }
    hb->last_beat = now;

    if (crowdsec_store_lock(hb->sconf) != APR_SUCCESS) {
        return 0;
    }
    /* Only refresh what is still ours: if another child has taken over, say
     * so by aborting rather than stealing the lease back mid-transfer.
     */
    if (hb->sconf->meta->lease.holder == hb->me) {
        hb->sconf->meta->lease.last_run = now;
    }
    else {
        still_ours = 0;
    }
    crowdsec_store_unlock(hb->sconf);

    return still_ours ? 0 : 1;
}

static apr_status_t do_pull(server_rec *s, crowdsec_server_rec *sconf,
                            int full, apr_pool_t *ptemp)
{
    heartbeat_ctx_t hb;
    crowdsec_http_req_t req;
    crowdsec_buf_t buf;
    crowdsec_http_err_t herr;
    crowdsec_decision_stats_t dstats;
    struct curl_slist **hdrs;
    long status = 0;
    char errbuf[256];
    apr_status_t rv;

    if (!sconf->curl_handles) {
        return APR_EINVAL;
    }
    hdrs = apr_pcalloc(ptemp, sizeof(*hdrs));   /* see live_query */
    apr_pool_cleanup_register(ptemp, hdrs, crowdsec_http_headers_cleanup,
                              apr_pool_cleanup_null);
    if (sconf->key
        && !crowdsec_http_header_add(ptemp, hdrs, "X-Api-Key", sconf->key)) {
        return APR_EINVAL;
    }
    crowdsec_http_header_add_raw(hdrs, "Accept:");

    memset(&req, 0, sizeof(req));
    /* scopes is filtered server-side so Country and AS decisions never reach
     * us: less memory, less traffic, and no config surface for it.
     */
    req.url = apr_pstrcat(ptemp, sconf->url, "/v1/decisions/stream?scopes=ip,range",
                          full ? "&startup=true" : "", NULL);
    req.connect_timeout = sconf->connect_timeout;
    /* A startup pull is much bigger than a live query, so it gets its own,
     * more generous budget.
     */
    req.timeout = full ? sconf->timeout * 12 : sconf->timeout * 4;
    /* A startup pull of a large blocklist can be quiet for a while before the
     * server starts writing. Measured: an 18MB body made a one-second window
     * abort every attempt, so the store never primed.
     */
    req.low_speed_time = full ? apr_time_from_sec(30) : apr_time_from_sec(10);
    req.ceiling = CROWDSEC_CEILING_STREAM;
    req.ssl_verify = 1;
    req.user_agent = CROWDSEC_BOUNCER_UA;
    req.headers = *hdrs;

    hb.sconf = sconf;
    hb.me = (apr_int64_t) getpid();
    hb.last_beat = apr_time_now();
    req.progress = lease_heartbeat;
    req.progress_data = &hb;

    errbuf[0] = '\0';
    herr = crowdsec_http_exchange(sconf->curl_handles, &req, ptemp, &status,
                                  &buf, errbuf, sizeof(errbuf));
    if (herr != CROWDSEC_HTTP_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: stream pull from '%s' failed (%s): %s",
                     sconf->url, crowdsec_http_err_str(herr), errbuf);
        return APR_EGENERAL;
    }
    if (status != 200) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: stream pull from '%s' returned %ld%s",
                     sconf->url, status,
                     status == 403 ? " (is the API key valid?)" : "");
        return APR_EGENERAL;
    }

    rv = crowdsec_store_apply_stream(s, sconf, buf.data, buf.len, full,
                                     &dstats, ptemp);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "crowdsec: %s pull applied: %" APR_SIZE_T_FMT " added, %"
                 APR_SIZE_T_FMT " removed, %" APR_SIZE_T_FMT
                 " expired, %" APR_SIZE_T_FMT " out-of-scope, %"
                 APR_SIZE_T_FMT " malformed",
                 full ? "startup" : "incremental",
                 dstats.added, dstats.removed, dstats.skipped_expired,
                 dstats.skipped_scope, dstats.malformed);

    /* Out-of-scope decisions should be impossible now that scopes is sent on
     * the wire, so say so once rather than every poll.
     */
    if (dstats.skipped_scope) {
        static int warned_scope;

        if (!warned_scope) {
            warned_scope = 1;
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "crowdsec: %" APR_SIZE_T_FMT " decisions use a scope "
                         "this component cannot evaluate (Country or AS need "
                         "geo data) and are not enforced here",
                         dstats.skipped_scope);
        }
    }
    if (dstats.malformed) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "crowdsec: %" APR_SIZE_T_FMT
                     " decisions were malformed and dropped", dstats.malformed);
    }
    return APR_SUCCESS;
}

/* How much freed memory the poller's allocator may keep between pulls. Enough
 * to recycle the small per-pull buffers, far below a parse arena.
 */
#define POLLER_POOL_MAX_FREE (4 * 1024 * 1024)

static void *APR_THREAD_FUNC poller_main(apr_thread_t *thd, void *data)
{
    crowdsec_server_rec *sconf = data;
    server_rec *s = sconf->poller_server;
    apr_allocator_t *alc = NULL;
    apr_pool_t *tpool = NULL;
    int was_leader = 0;
    int need_full = 1;
    apr_time_t last_pull = 0;   /* 0 so the first wake pulls immediately */

    /* Our own bounded allocator, not the thread pool's: that one is shared up
     * the pool tree and never returns freed memory to the OS, so the parse
     * arena of one large startup pull - sized at roughly 9x the body - would
     * inflate this child's footprint for the rest of its life. No mutex is
     * set because only this thread allocates from it.
     */
    if (apr_allocator_create(&alc) == APR_SUCCESS) {
        apr_allocator_max_free_set(alc, POLLER_POOL_MAX_FREE);
        if (apr_pool_create_ex(&tpool, apr_thread_pool_get(thd), NULL, alc)
            == APR_SUCCESS) {
            /* The pool owns the allocator, so destroying it below frees both. */
            apr_allocator_owner_set(alc, tpool);
        }
        else {
            apr_allocator_destroy(alc);
            tpool = NULL;
        }
    }
    if (!tpool) {
        apr_pool_create(&tpool, apr_thread_pool_get(thd));
    }

    while (!sconf->poller_stop) {
        apr_pool_t *ptemp;
        int leader, took_over;

        leader = lease_claim(sconf, &took_over);

        if (leader && !was_leader) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "crowdsec: this child (%d) is now polling the "
                         "decision stream%s", (int) getpid(),
                         took_over ? " (the previous one stopped)" : "");
            if (took_over) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                             "crowdsec: took over a stale polling lease; the "
                             "child that held it died without releasing it");
            }
            /* A new leader has no idea how much of the store the last one had
             * applied, so start from a full pull. Stores overwrite, so this is
             * idempotent - just more expensive, and only on takeover.
             */
            need_full = 1;
            last_pull = 0;      /* and do it now, not an interval from now */
        }
        was_leader = leader;

        /* The lease is checked twice per interval so a stale one is noticed
         * quickly, but pulling on every wake would double the configured
         * rate, so the pull itself is gated on elapsed time.
         */
        if (leader && apr_time_now() - last_pull >= sconf->update_frequency) {
            /* The reporting thread asks for a full pull once per window,
             * because that is the only kind that can rebuild the
             * active_decisions gauge - see crowdsec_store_apply_stream. Taken
             * here rather than when it is set, so the request is only consumed
             * by a pull that is actually about to happen.
             */
            if (crowdsec_metrics_resync_take(sconf)) {
                need_full = 1;
            }
            apr_pool_create(&ptemp, tpool);
            if (do_pull(s, sconf, need_full, ptemp) == APR_SUCCESS) {
                need_full = 0;
            }
            else {
                /* The engine advances its own stream cursor when it finishes
                 * writing a response, so a batch we failed to read or parse is
                 * gone for good: its additions and deletions would never be
                 * resent to an incremental pull. Resync from a full snapshot
                 * instead, which is idempotent and carries the deletions too.
                 */
                need_full = 1;
            }
            last_pull = apr_time_now();
            apr_pool_destroy(ptemp);
        }

        /* Sleep in slices so a shutdown is noticed promptly rather than after
         * a whole interval, and wake at twice the poll rate so a stale lease
         * is picked up within roughly two intervals.
         */
        {
            apr_interval_time_t slept = 0;
            apr_interval_time_t want = sconf->update_frequency / 2;

            if (want < apr_time_from_msec(200)) {
                want = apr_time_from_msec(200);
            }
            while (slept < want && !sconf->poller_stop) {
                apr_sleep(apr_time_from_msec(200));
                slept += apr_time_from_msec(200);
            }
        }
    }

    if (was_leader) {
        lease_release(sconf);
    }
    apr_pool_destroy(tpool);
    apr_thread_exit(thd, APR_SUCCESS);

    return NULL;
}

static apr_status_t poller_cleanup(void *data)
{
    crowdsec_server_rec *sconf = data;
    apr_status_t rv;

    sconf->poller_stop = 1;
    if (sconf->poller) {
        apr_thread_join(&rv, sconf->poller);
        sconf->poller = NULL;
    }
    return APR_SUCCESS;
}

static int poller_exists_for_cache(server_rec *base,
                                   const crowdsec_server_rec *want)
{
    server_rec *s;

    for (s = base; s; s = s->next) {
        const crowdsec_server_rec *other =
            ap_get_module_config(s->module_config, &crowdsec_module);

        if (other && other != want && other->poller
            && other->cache_instance == want->cache_instance) {
            return 1;
        }
    }
    return 0;
}

apr_status_t crowdsec_poller_start(apr_pool_t *pchild, server_rec *base)
{
    server_rec *s;

    for (s = base; s; s = s->next) {
        crowdsec_server_rec *sconf =
            ap_get_module_config(s->module_config, &crowdsec_module);

        if (!sconf || sconf->mode != CROWDSEC_MODE_STREAM || !sconf->url) {
            continue;
        }
        if (!sconf->cache_instance) {
            /* post_config refuses this combination, so reaching here means
             * something changed underneath us.
             */
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         "crowdsec: stream mode needs CrowdsecCache; not "
                         "polling");
            continue;
        }
        if (sconf->poller) {
            continue;
        }
        /* One poller per decision cache, not per vhost. Vhosts that inherited
         * the cache through the config merge each get their own server_rec, so
         * a per-struct check alone would start a thread for every one of them
         * - all in the same child, hence all with the same pid, so the lease
         * would identify every one of them as the leader and they would pull
         * and apply over each other.
         */
        if (poller_exists_for_cache(base, sconf)) {
            continue;
        }
        sconf->poller_server = s;
        sconf->poller_stop = 0;
        if (apr_thread_create(&sconf->poller, NULL, poller_main, sconf,
                              pchild) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         "crowdsec: could not start the stream poller thread");
            continue;
        }
        /* A pre-cleanup, not an ordinary one: apr_pool_cleanup_register runs
         * AFTER a pool's subpools are destroyed, and the thread's own pool is
         * a subpool of pchild. Registering normally would free the pools the
         * thread is still running on, then join it.
         */
        apr_pool_pre_cleanup_register(pchild, sconf, poller_cleanup);
    }
    return APR_SUCCESS;
}
