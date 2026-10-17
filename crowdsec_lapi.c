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

#include "crowdsec_store.h"

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
apr_status_t crowdsec_store_lock(crowdsec_server_rec *sconf)
{
    if (!sconf->cache_mutex) {
        return APR_SUCCESS;
    }
    return apr_global_mutex_lock(sconf->cache_mutex);
}

void crowdsec_store_unlock(crowdsec_server_rec *sconf)
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
    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
        return 0;
    }
    *out = sconf->meta->stats;
    crowdsec_store_unlock(sconf);

    return 1;
}

/* ------------------------------------------------------------- apply batch */

/* How many stores to apply per hold of the global mutex. Request lookups need
 * the same mutex, so a full pull held for its whole six-figure batch would
 * stall every request in every child for the duration. At ~1us per store a
 * slice is a few milliseconds.
 */
#define APPLY_CHUNK_OPS 4096

typedef struct
{
    server_rec *s;
    crowdsec_server_rec *sconf;
    apr_pool_t *p;
    apr_int64_t me;             /* our pid, for the lease re-check */
    apr_size_t ops;             /* stores and removals since the last yield */
    unsigned int locked:1;      /* cleared if a re-take of the lock fails */
    unsigned int lease_lost:1;  /* another child took over mid-batch */
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

/* Releases and retakes the lock so request lookups can interleave with a
 * large batch. The lease is re-checked on the way back in - the pre-batch
 * check only covers the moment the batch began - and kept warm, so a long
 * apply cannot be declared stale by another child.
 */
static apr_status_t apply_yield(apply_ctx_t *a)
{
    lease_t lease;

    crowdsec_store_unlock(a->sconf);
    if (crowdsec_store_lock(a->sconf) != APR_SUCCESS) {
        a->locked = 0;
        return APR_EGENERAL;
    }
    lease = a->sconf->meta->lease;
    if (lease.holder && lease.holder != a->me) {
        a->lease_lost = 1;
        return APR_EAGAIN;
    }
    if (lease.holder == a->me) {
        a->sconf->meta->lease.last_run = apr_time_now();
    }
    return APR_SUCCESS;
}

static apr_status_t apply_one(void *ctx, int added,
                              const crowdsec_decision_t *d)
{
    apply_ctx_t *a = ctx;
    unsigned char key[CROWDSEC_KEY_MAX];
    apr_size_t keylen;
    decision_value_t val;

    if (++a->ops >= APPLY_CHUNK_OPS) {
        apr_status_t rv;

        a->ops = 0;
        rv = apply_yield(a);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

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
    a.me = (apr_int64_t) getpid();
    /* Sample roughly 1% of what we write, capped at 32 probes. */
    a.sample_every = 100;

    rv = crowdsec_store_lock(sconf);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    a.locked = 1;

    /* Another child may have claimed the lease while this pull was in flight.
     * Applying now would write our older snapshot over the new leader's, so
     * drop the batch instead. A zero holder means nobody is polling (the test
     * entry point, or before any election), which is free to proceed.
     */
    {
        lease_t lease;

        lease = sconf->meta->lease;
        if (lease.holder && lease.holder != (apr_int64_t) getpid()) {
            crowdsec_store_unlock(sconf);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "crowdsec: discarding a decision batch pulled before "
                         "the polling lease moved to pid %" APR_INT64_T_FMT,
                         lease.holder);
            return APR_EAGAIN;
        }
    }

    /* The lock is held in slices of APPLY_CHUNK_OPS stores - see apply_yield -
     * so a startup pull neither takes six figures of locks nor starves every
     * request lookup for the whole apply.
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

    if (a.locked) {
        crowdsec_store_unlock(sconf);
    }

    if (!parsed) {
        if (a.lease_lost) {
            /* The entries already stored are harmless: stores are idempotent
             * and the new leader starts from a full pull anyway.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "crowdsec: the polling lease moved to another child "
                         "mid-batch; discarding the rest of this one");
            return APR_EAGAIN;
        }
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
    apr_interval_time_t ttl;

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
    /* The per-child lifetime, not the shared cache's: this is added to
     * CrowdsecUpdateFrequency in the time a new decision takes to apply, and
     * it only has to be long enough to keep the shared cache's global lock off
     * the hot path for a repeat visitor.
     *
     * Capped at the shared lifetime because a memo entry can be seeded from an
     * already-aging shared one, and a longer memo would then keep serving a
     * verdict after the entry it came from had gone.
     */
    ttl = sconf->local_cache_timeout;
    if (ttl > sconf->cache_timeout) {
        ttl = sconf->cache_timeout;
    }
    slot->expiry = apr_time_now() + ttl;
    slot->used = 1;
    if (sconf->memo.mutex) {
        apr_thread_mutex_unlock(sconf->memo.mutex);
    }
}

/* In live mode the shared cache holds the verdict for one address: without it
 * every child process would query the API separately for the same client, so
 * a server with 150 children would multiply the API traffic by 150.
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
    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
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
    crowdsec_store_unlock(sconf);

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

    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
        return;
    }
    sconf->cache_provider->store(sconf->cache_instance, r->server, key,
                                 (unsigned int) keylen,
                                 apr_time_now() + sconf->cache_timeout,
                                 (unsigned char *) &val, sizeof(val),
                                 r->pool);
    crowdsec_store_unlock(sconf);
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

    if (!sconf->cache_instance || !sconf->meta) {
        return CROWDSEC_LOOKUP_FAIL;
    }

    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
        return CROWDSEC_LOOKUP_FAIL;
    }
    /* One lock for the primed check and the whole prefix walk. */
    primed = sconf->meta->primed_at;
    if (!primed) {
        crowdsec_store_unlock(sconf);
        apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "unprimed");
        return CROWDSEC_LOOKUP_UNPRIMED;
    }
    found = store_probe(r->server, sconf, &host, r->pool, rem);
    crowdsec_store_unlock(sconf);

    if (!found) {
        *rem = CROWDSEC_REM_ALLOW;
    }
    memo_put(sconf, ip, *rem);
    apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "cache");

    return CROWDSEC_LOOKUP_OK;
}
