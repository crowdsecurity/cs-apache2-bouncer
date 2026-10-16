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
#include "crowdsec_util.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"

/* Which prefix lengths currently exist in the store, so a lookup probes two
 * or three candidates instead of all 33 or 129.
 */
typedef struct
{
    unsigned char bits[17];     /* 129 bits, enough for v6; v4 uses 5 */
} plen_set_t;

typedef struct
{
    apr_int64_t holder;         /* pid of the child doing the polling */
    apr_time_t last_run;
} lease_t;

/* The module's shared control state: about 90 bytes, fixed for the life of
 * the server. It used to live in the socache next to the decisions, which was
 * a category error - that is a cache, and force-expiring the oldest entry in
 * a subcache is normal operation for it, so this could be dropped at any
 * moment. Its own region cannot be evicted and needs no reserved keyspace.
 * Every field is read and written under sconf->cache_mutex.
 */
struct crowdsec_meta
{
    lease_t lease;
    apr_time_t primed_at;
    crowdsec_store_stats_t stats;
    plen_set_t plens4;
    plen_set_t plens6;
};

apr_status_t crowdsec_meta_create(apr_pool_t *pconf,
                                  crowdsec_server_rec *sconf)
{
    apr_status_t rv;

    rv = apr_shm_create(&sconf->meta_shm, sizeof(struct crowdsec_meta), NULL,
                        pconf);
    if (rv != APR_SUCCESS) {
        /* Anonymous shared memory is unavailable on some platforms, so fall
         * back to a named segment in the runtime directory.
         */
        const char *path = ap_runtime_dir_relative(pconf, "crowdsec_meta.shm");

        apr_file_remove(path, pconf);
        rv = apr_shm_create(&sconf->meta_shm,
                            sizeof(struct crowdsec_meta), path, pconf);
    }
    if (rv != APR_SUCCESS) {
        return rv;
    }
    sconf->meta = apr_shm_baseaddr_get(sconf->meta_shm);
    memset(sconf->meta, 0, sizeof(*sconf->meta));

    return APR_SUCCESS;
}

#define DECISION_VALUE_VERSION 1

typedef struct
{
    unsigned char version;
    unsigned char rem;
    unsigned char reserved[2];
} decision_value_t;

/* ------------------------------------------------------------------ store */

static int plen_test(const plen_set_t *s, int plen)
{
    return (s->bits[plen >> 3] >> (plen & 7)) & 1;
}

static void plen_set(plen_set_t *s, int plen)
{
    s->bits[plen >> 3] |= (unsigned char) (1u << (plen & 7));
}

/* Every socache call needs the mutex: shmcb's retrieve mutates shared state
 * when it discards an expired entry, so even reads are writes.
 */
static apr_status_t store_lock(crowdsec_server_rec *sconf)
{
    if (!sconf->cache_mutex) {
        return APR_SUCCESS;
    }
    return apr_global_mutex_lock(sconf->cache_mutex);
}

static void store_unlock(crowdsec_server_rec *sconf)
{
    if (sconf->cache_mutex) {
        apr_global_mutex_unlock(sconf->cache_mutex);
    }
}

int crowdsec_store_stats(server_rec *s, crowdsec_server_rec *sconf,
                         crowdsec_store_stats_t *out)
{
    if (!sconf->meta || !out) {
        return 0;
    }
    if (store_lock(sconf) != APR_SUCCESS) {
        return 0;
    }
    *out = sconf->meta->stats;
    store_unlock(sconf);

    return 1;
}

/* ------------------------------------------------------------- apply batch */

typedef struct
{
    server_rec *s;
    crowdsec_server_rec *sconf;
    apr_pool_t *p;
    /* One set per family: a v4 lookup must not be made to probe prefix
     * lengths that only v6 decisions use, and each probe costs a socache read
     * under the global lock.
     */
    plen_set_t plens4;
    plen_set_t plens6;
    apr_size_t stored;
    apr_size_t store_failures;
    /* A sample of keys just written, re-read after the batch to notice the
     * cache quietly evicting what we stored.
     */
    unsigned char sample[32][CROWDSEC_KEY_MAX];
    apr_size_t sample_len[32];
    apr_size_t samples;
    apr_size_t sample_every;
} apply_ctx_t;

static apr_status_t apply_one(void *ctx, int added,
                              const crowdsec_decision_t *d)
{
    apply_ctx_t *a = ctx;
    unsigned char key[CROWDSEC_KEY_MAX];
    apr_size_t keylen;
    decision_value_t val;

    keylen = crowdsec_key_encode(&d->net, key, sizeof(key));
    if (!keylen) {
        return APR_SUCCESS;     /* cannot happen; counted as a no-op if it does */
    }

    if (!added) {
        /* A removal for something we never had is not an error. */
        a->sconf->cache_provider->remove(a->sconf->cache_instance, a->s,
                                         key, (unsigned int) keylen, a->p);
        return APR_SUCCESS;
    }

    /* Every stream decision is a ban: a challenge from LAPI carries no
     * interstitial to serve and must fail closed, and captcha maps to ban
     * because this module does not implement captcha.
     */
    val.version = DECISION_VALUE_VERSION;
    val.rem = (unsigned char) CROWDSEC_REM_BAN;
    val.reserved[0] = 0;
    val.reserved[1] = 0;

    if (a->sconf->cache_provider->store(a->sconf->cache_instance, a->s,
                                        key, (unsigned int) keylen,
                                        apr_time_now() + d->duration,
                                        (unsigned char *) &val, sizeof(val),
                                        a->p) != APR_SUCCESS) {
        a->store_failures++;
        return APR_SUCCESS;     /* keep going; the count is reported after */
    }
    plen_set(d->net.family == 6 ? &a->plens6 : &a->plens4, d->net.plen);
    a->stored++;

    if (a->sample_every && (a->stored % a->sample_every) == 0
        && a->samples < 32) {
        memcpy(a->sample[a->samples], key, keylen);
        a->sample_len[a->samples] = keylen;
        a->samples++;
    }
    return APR_SUCCESS;
}

/* Counts how many entries the cache can still hand back, and how many of our
 * sampled keys survived. shmcb force-expires the oldest entry in a subcache to
 * admit a new one and only logs it at debug level, so without this a cache
 * that is too small silently stops blocking people.
 */
static void check_retention(server_rec *s, apply_ctx_t *a,
                            crowdsec_store_stats_t *st)
{
    apr_size_t i, lost = 0;

    for (i = 0; i < a->samples; i++) {
        decision_value_t val;
        unsigned int len = sizeof(val);

        if (a->sconf->cache_provider->retrieve(a->sconf->cache_instance, s,
                                               a->sample[i],
                                               (unsigned int) a->sample_len[i],
                                               (unsigned char *) &val, &len,
                                               a->p) != APR_SUCCESS) {
            lost++;
        }
    }

    st->stored = (apr_uint32_t) a->stored;
    st->retained = (apr_uint32_t) (a->stored
                                   - (a->samples
                                      ? (lost * a->stored) / a->samples
                                      : 0));

    if (lost) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: decision cache is too small: %"
                     APR_SIZE_T_FMT " of %" APR_SIZE_T_FMT
                     " sampled entries were already evicted after storing %"
                     APR_SIZE_T_FMT ". Increase the CrowdsecCache size; "
                     "decisions are being dropped and those clients are "
                     "no longer blocked.", lost, a->samples, a->stored);
    }
    if (a->store_failures) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: %" APR_SIZE_T_FMT " decisions could not be "
                     "stored at all; the cache is far too small",
                     a->store_failures);
    }
}

/* An incremental batch adds to what is already known; a full pull replaces it,
 * so prefix lengths that no longer exist stop being probed. Caller holds the
 * lock.
 */
static void plen_merge(plen_set_t *dst, const plen_set_t *fresh, int full)
{
    apr_size_t i;

    if (full) {
        *dst = *fresh;
        return;
    }
    for (i = 0; i < sizeof(dst->bits); i++) {
        dst->bits[i] |= fresh->bits[i];
    }
}

apr_status_t crowdsec_store_apply_stream(server_rec *s,
                                         crowdsec_server_rec *sconf,
                                         const char *body, apr_size_t len,
                                         int full,
                                         crowdsec_decision_stats_t *stats,
                                         apr_pool_t *ptemp)
{
    apply_ctx_t a;
    crowdsec_store_stats_t st;
    const char *err = NULL;
    apr_status_t rv;
    int parsed;

    if (!sconf->cache_instance || !sconf->meta) {
        return APR_EINVAL;
    }
    memset(&a, 0, sizeof(a));
    a.s = s;
    a.sconf = sconf;
    a.p = ptemp;
    /* Sample roughly 1% of what we write, capped at 32 probes. */
    a.sample_every = 100;

    rv = store_lock(sconf);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* Another child may have claimed the lease while this pull was in flight.
     * Applying now would write our older snapshot over the new leader's, so
     * drop the batch instead. A zero holder means nobody is polling (the test
     * entry point, or before any election), which is free to proceed.
     */
    {
        lease_t lease;

        lease = sconf->meta->lease;
        if (lease.holder && lease.holder != (apr_int64_t) getpid()) {
            store_unlock(sconf);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "crowdsec: discarding a decision batch pulled before "
                         "the polling lease moved to pid %" APR_INT64_T_FMT,
                         lease.holder);
            return APR_EAGAIN;
        }
    }

    /* One lock for the whole batch: a startup pull is six figures of entries
     * and must not take six figures of locks.
     */
    parsed = crowdsec_stream_parse(body, len, ptemp, apply_one, &a, stats,
                                   &err);

    if (parsed) {
        memset(&st, 0, sizeof(st));
        st = sconf->meta->stats;

        /* Incremental batches add to what is already known. A full pull
         * rebuilds instead, so prefix lengths that no longer exist stop being
         * probed.
         */
        plen_merge(&sconf->meta->plens4, &a.plens4, full);
        plen_merge(&sconf->meta->plens6, &a.plens6, full);

        check_retention(s, &a, &st);
        st.last_pull = apr_time_now();
        st.pulls++;
        if (!st.primed_at) {
            st.primed_at = st.last_pull;
        }
        sconf->meta->stats = st;
        sconf->meta->primed_at = st.primed_at;
    }

    store_unlock(sconf);

    if (!parsed) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: could not parse the decision stream: %s",
                     err ? err : "unknown");
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

/* ------------------------------------------------------------------ lookup */

/* Caller holds the lock. Probes the exact address, then only those prefix
 * lengths the store says exist, longest first so the most specific decision
 * wins.
 */
static int store_probe(server_rec *s, crowdsec_server_rec *sconf,
                       const crowdsec_net_t *host, apr_pool_t *p,
                       crowdsec_rem_t *rem)
{
    plen_set_t plens;
    unsigned char key[CROWDSEC_KEY_MAX];
    decision_value_t val;
    apr_size_t keylen;
    unsigned int vlen;
    int width = (host->family == 6) ? 128 : 32;
    int plen;

    /* The exact address first: single-IP decisions are the overwhelming
     * majority, so the common case is one probe.
     */
    keylen = crowdsec_key_encode(host, key, sizeof(key));
    vlen = sizeof(val);
    if (keylen
        && sconf->cache_provider->retrieve(sconf->cache_instance, s, key,
                                           (unsigned int) keylen,
                                           (unsigned char *) &val, &vlen,
                                           p) == APR_SUCCESS
        && vlen == sizeof(val) && val.version == DECISION_VALUE_VERSION) {
        *rem = (crowdsec_rem_t) val.rem;
        return 1;
    }

    plens = (host->family == 6) ? sconf->meta->plens6 : sconf->meta->plens4;

    for (plen = width - 1; plen >= 0; plen--) {
        crowdsec_net_t net;

        if (!plen_test(&plens, plen)) {
            continue;
        }
        crowdsec_ip_mask(host, plen, &net);
        keylen = crowdsec_key_encode(&net, key, sizeof(key));
        if (!keylen) {
            continue;
        }
        vlen = sizeof(val);
        if (sconf->cache_provider->retrieve(sconf->cache_instance, s, key,
                                            (unsigned int) keylen,
                                            (unsigned char *) &val, &vlen,
                                            p) == APR_SUCCESS
            && vlen == sizeof(val) && val.version == DECISION_VALUE_VERSION) {
            *rem = (crowdsec_rem_t) val.rem;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------- memo */

apr_status_t crowdsec_memo_init(apr_pool_t *pchild, crowdsec_server_rec *sconf)
{
    int threaded = 0;

    sconf->memo.slots = apr_pcalloc(pchild, CROWDSEC_MEMO_SLOTS
                                    * sizeof(crowdsec_memo_slot_t));
    if (!sconf->memo.slots) {
        return APR_ENOMEM;
    }
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded);
    if (threaded) {
        return apr_thread_mutex_create(&sconf->memo.mutex,
                                       APR_THREAD_MUTEX_DEFAULT, pchild);
    }
    sconf->memo.mutex = NULL;

    return APR_SUCCESS;
}

static unsigned int memo_hash(const char *ip)
{
    unsigned int h = 2166136261u;

    while (*ip) {
        h = (h ^ (unsigned char) *ip++) * 16777619u;
    }
    return h % CROWDSEC_MEMO_SLOTS;
}

static int memo_get(crowdsec_server_rec *sconf, const char *ip,
                    crowdsec_rem_t *rem)
{
    crowdsec_memo_slot_t *slot;
    int hit = 0;

    if (!sconf->memo.slots) {
        return 0;
    }
    if (sconf->memo.mutex) {
        apr_thread_mutex_lock(sconf->memo.mutex);
    }
    slot = &sconf->memo.slots[memo_hash(ip)];
    if (slot->used && slot->expiry > apr_time_now() && !strcmp(slot->ip, ip)) {
        *rem = slot->rem;
        hit = 1;
    }
    if (sconf->memo.mutex) {
        apr_thread_mutex_unlock(sconf->memo.mutex);
    }
    return hit;
}

static void memo_put(crowdsec_server_rec *sconf, const char *ip,
                     crowdsec_rem_t rem)
{
    crowdsec_memo_slot_t *slot;

    if (!sconf->memo.slots || strlen(ip) > CROWDSEC_IP_MAX) {
        return;
    }
    if (sconf->memo.mutex) {
        apr_thread_mutex_lock(sconf->memo.mutex);
    }
    /* Direct-mapped: a collision overwrites, which costs a future miss and
     * nothing else. No eviction policy, no allocation, fixed memory.
     */
    slot = &sconf->memo.slots[memo_hash(ip)];
    apr_cpystrn(slot->ip, ip, sizeof(slot->ip));
    slot->rem = rem;
    slot->expiry = apr_time_now() + sconf->cache_timeout;
    slot->used = 1;
    if (sconf->memo.mutex) {
        apr_thread_mutex_unlock(sconf->memo.mutex);
    }
}

/* In live mode the shared cache holds the verdict for one address, the way it
 * did before this module had a stream mode: without it every child process
 * would query the API separately for the same client, so a server with 150
 * children would multiply the API traffic by 150.
 *
 * This reuses the decision key space, which is safe because live and stream
 * are mutually exclusive for a vhost. The difference is that live mode stores
 * allow as well as ban - absence means "not asked yet" rather than "allowed" -
 * and expires entries after CrowdsecCacheTimeout rather than the decision's
 * own duration.
 */
static int live_cache_get(request_rec *r, crowdsec_server_rec *sconf,
                          const crowdsec_net_t *host, crowdsec_rem_t *rem)
{
    unsigned char key[CROWDSEC_KEY_MAX];
    decision_value_t val;
    apr_size_t keylen;
    unsigned int vlen = sizeof(val);
    int hit = 0;

    if (!sconf->cache_instance) {
        return 0;
    }
    keylen = crowdsec_key_encode(host, key, sizeof(key));
    if (!keylen) {
        return 0;
    }
    if (store_lock(sconf) != APR_SUCCESS) {
        return 0;
    }
    if (sconf->cache_provider->retrieve(sconf->cache_instance, r->server, key,
                                        (unsigned int) keylen,
                                        (unsigned char *) &val, &vlen,
                                        r->pool) == APR_SUCCESS
        && vlen == sizeof(val) && val.version == DECISION_VALUE_VERSION) {
        *rem = (crowdsec_rem_t) val.rem;
        hit = 1;
    }
    store_unlock(sconf);

    return hit;
}

static void live_cache_put(request_rec *r, crowdsec_server_rec *sconf,
                           const crowdsec_net_t *host, crowdsec_rem_t rem)
{
    unsigned char key[CROWDSEC_KEY_MAX];
    decision_value_t val;
    apr_size_t keylen;

    if (!sconf->cache_instance) {
        return;
    }
    keylen = crowdsec_key_encode(host, key, sizeof(key));
    if (!keylen) {
        return;
    }
    val.version = DECISION_VALUE_VERSION;
    val.rem = (unsigned char) rem;
    val.reserved[0] = 0;
    val.reserved[1] = 0;

    if (store_lock(sconf) != APR_SUCCESS) {
        return;
    }
    sconf->cache_provider->store(sconf->cache_instance, r->server, key,
                                 (unsigned int) keylen,
                                 apr_time_now() + sconf->cache_timeout,
                                 (unsigned char *) &val, sizeof(val),
                                 r->pool);
    store_unlock(sconf);
}

/* ------------------------------------------------------------- live query */

static crowdsec_lookup_t live_query(request_rec *r,
                                    crowdsec_server_rec *sconf,
                                    const char *ip, crowdsec_rem_t *rem)
{
    crowdsec_http_req_t req;
    crowdsec_buf_t buf;
    crowdsec_http_err_t herr;
    struct curl_slist **hdrs;
    long status = 0;
    char errbuf[256];
    const char *perr = NULL;
    int any = 0;

    if (!sconf->curl_handles) {
        return CROWDSEC_LOOKUP_FAIL;
    }
    /* The holder lives in the pool, not on the stack: this cleanup runs when
     * the pool is destroyed, long after this function has returned, and a
     * registered stack address would by then be a dead frame - handing
     * curl_slist_free_all whatever happened to occupy it.
     */
    hdrs = apr_pcalloc(r->pool, sizeof(*hdrs));
    apr_pool_cleanup_register(r->pool, hdrs,
                              crowdsec_http_headers_cleanup,
                              apr_pool_cleanup_null);
    if (sconf->key
        && !crowdsec_http_header_add(r->pool, hdrs, "X-Api-Key", sconf->key)) {
        return CROWDSEC_LOOKUP_FAIL;
    }
    crowdsec_http_header_add_raw(hdrs, "Accept:");

    memset(&req, 0, sizeof(req));
    req.url = apr_pstrcat(r->pool, sconf->url, "/v1/decisions?ip=",
                          ap_escape_urlencoded(r->pool, ip), NULL);
    req.connect_timeout = sconf->connect_timeout;
    req.timeout = sconf->timeout;
    /* On the request path a stalled reply must not eat the budget. */
    req.low_speed_time = apr_time_from_sec(1);
    req.ceiling = CROWDSEC_CEILING_LIVE;
    req.ssl_verify = 1;
    req.user_agent = CROWDSEC_BOUNCER_UA;
    req.headers = *hdrs;

    errbuf[0] = '\0';
    herr = crowdsec_http_exchange(sconf->curl_handles, &req, r->pool, &status,
                                  &buf, errbuf, sizeof(errbuf));
    if (herr != CROWDSEC_HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: live query to '%s' failed (%s): %s",
                      sconf->url, crowdsec_http_err_str(herr), errbuf);
        return CROWDSEC_LOOKUP_FAIL;
    }
    if (status != 200) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: live query to '%s' returned %ld",
                      sconf->url, status);
        return CROWDSEC_LOOKUP_FAIL;
    }
    if (!crowdsec_decisions_any(buf.data, buf.len, r->pool, &any, &perr)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: could not parse the decisions reply: %s",
                      perr ? perr : "unknown");
        return CROWDSEC_LOOKUP_FAIL;
    }
    /* Every decision LAPI returns for this address is treated as a ban, for
     * the same reason the stream is.
     */
    *rem = any ? CROWDSEC_REM_BAN : CROWDSEC_REM_ALLOW;

    return CROWDSEC_LOOKUP_OK;
}

/* ---------------------------------------------------------------- lookup */

crowdsec_lookup_t crowdsec_lapi_lookup(request_rec *r,
                                       crowdsec_server_rec *sconf,
                                       const char *ip, crowdsec_rem_t *rem)
{
    crowdsec_net_t host;
    crowdsec_lookup_t lr;
    apr_time_t primed = 0;
    int found;

    *rem = CROWDSEC_REM_ALLOW;

    if (memo_get(sconf, ip, rem)) {
        apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "memo");
        return CROWDSEC_LOOKUP_OK;
    }

    if (!crowdsec_cidr_parse(ip, &host)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: cannot parse the client address '%s'", ip);
        return CROWDSEC_LOOKUP_FAIL;
    }

    if (sconf->mode == CROWDSEC_MODE_LIVE) {
        /* The shared cache sits between the per-child memo and the API, so
         * one query serves every child.
         */
        if (live_cache_get(r, sconf, &host, rem)) {
            memo_put(sconf, ip, *rem);
            apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "cache");
            return CROWDSEC_LOOKUP_OK;
        }
        lr = live_query(r, sconf, ip, rem);
        if (lr == CROWDSEC_LOOKUP_OK) {
            live_cache_put(r, sconf, &host, *rem);
            memo_put(sconf, ip, *rem);
            apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "live");
        }
        return lr;
    }

    /* Stream mode. */
    if (!sconf->cache_instance || !sconf->meta) {
        return CROWDSEC_LOOKUP_FAIL;
    }

    if (store_lock(sconf) != APR_SUCCESS) {
        return CROWDSEC_LOOKUP_FAIL;
    }
    /* One lock for the primed check and the whole prefix walk. */
    primed = sconf->meta->primed_at;
    if (!primed) {
        store_unlock(sconf);
        apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "unprimed");
        return CROWDSEC_LOOKUP_UNPRIMED;
    }
    found = store_probe(r->server, sconf, &host, r->pool, rem);
    store_unlock(sconf);

    if (!found) {
        *rem = CROWDSEC_REM_ALLOW;
    }
    memo_put(sconf, ip, *rem);
    apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "cache");

    return CROWDSEC_LOOKUP_OK;
}

/* ------------------------------------------------------------- the poller */

/* mod_watchdog's AP_WATCHDOG_SINGLETON was measured and rejected: it never
 * re-elects after the holding child dies, so an OOM-killed child would stop
 * polling permanently and silently. Instead every child runs a poller thread
 * and they agree on a leader through a lease in the shared cache. A dead
 * leader's lease goes stale and someone else claims it.
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

    if (store_lock(sconf) != APR_SUCCESS) {
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
    store_unlock(sconf);

    return leader;
}

static void lease_release(crowdsec_server_rec *sconf)
{
    lease_t lease;

    if (store_lock(sconf) != APR_SUCCESS) {
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
    store_unlock(sconf);
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

    if (store_lock(hb->sconf) != APR_SUCCESS) {
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
    store_unlock(hb->sconf);

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

static void *APR_THREAD_FUNC poller_main(apr_thread_t *thd, void *data)
{
    crowdsec_server_rec *sconf = data;
    server_rec *s = sconf->poller_server;
    apr_pool_t *tpool;
    int was_leader = 0;
    int need_full = 1;
    apr_time_t last_pull = 0;   /* 0 so the first wake pulls immediately */

    apr_pool_create(&tpool, apr_thread_pool_get(thd));

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

/* True when another server_rec in this child already polls the same cache. */
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
