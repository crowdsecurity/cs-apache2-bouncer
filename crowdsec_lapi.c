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
    /* Generation 0 means "none", which is what lets gen_applying be tested as
     * a plain nonzero, so the first live generation is 1.
     */
    sconf->meta->gen = 1;
    sconf->meta->gen_seq = 1;

    return APR_SUCCESS;
}

#define DECISION_VALUE_VERSION 2

/* Five bytes per decision. Shmcb's own per-entry overhead dominates either
 * way - the directive docs budget ~128 bytes per decision - so the sizing
 * guidance does not move.
 *
 * The generation is split into two bytes rather than declared apr_uint16_t so
 * the struct has no padding: it is memcpy'd into the socache whole, and
 * padding would be an uninitialised read on every store.
 *
 * Adding it is what bumps the version, because the layout changed and a
 * four-byte value read as five would be nonsense. That costs nothing in
 * practice: the socache and this control region are created together in
 * post_config and recreated together on a restart, so values from an older
 * layout never coexist with this code. It does mean a version mismatch must
 * read as a miss, and in stream mode a miss means the client is not blocked.
 */
typedef struct
{
    unsigned char version;
    unsigned char rem;
    unsigned char origin;       /* slot id in the shared metrics table */
    unsigned char gen_hi;
    unsigned char gen_lo;
} decision_value_t;

/* Hands out the next generation, skipping 0 - see crowdsec_meta. Caller holds
 * the lock.
 */
static apr_uint16_t gen_take(crowdsec_server_rec *sconf)
{
    apr_uint16_t n = (apr_uint16_t) (sconf->meta->gen_seq + 1);

    sconf->meta->gen_seq = n ? n : 1;

    return sconf->meta->gen_seq;
}

static void gen_put(decision_value_t *v, apr_uint16_t g)
{
    v->gen_hi = (unsigned char) (g >> 8);
    v->gen_lo = (unsigned char) (g & 0xffu);
}

/* Whether this value belongs to the snapshot in force. Caller holds the lock,
 * which every reader of meta already does.
 */
static int gen_ok(const crowdsec_server_rec *sconf, const decision_value_t *v)
{
    apr_uint16_t g = (apr_uint16_t) ((v->gen_hi << 8) | v->gen_lo);

    return g == sconf->meta->gen
        || (sconf->meta->gen_applying && g == sconf->meta->gen_applying);
}

/* Both halves of the test every read does: the wrong layout and the wrong
 * snapshot are the same answer, a miss.
 */
static int value_ok(const crowdsec_server_rec *sconf,
                    const decision_value_t *v, unsigned int vlen)
{
    return vlen == sizeof(*v) && v->version == DECISION_VALUE_VERSION
        && gen_ok(sconf, v);
}

/* Which array a family's counters live in. */
static int net_ipt(const crowdsec_net_t *n)
{
    return n->family == 6 ? CROWDSEC_IPT_V6 : CROWDSEC_IPT_V4;
}

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
    /* A full pull replaces the store, so it is the one moment we know the
     * absolute truth about what is in it. Counted here and swapped in at the
     * end; see the comment where that happens.
     */
    unsigned int full:1;
    apr_uint16_t gen;           /* generation this batch writes */
    apr_uint32_t fresh_active[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
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

/* Whether this key is already in the store, and under which origin. Only ever
 * asked to keep the active_decisions gauge straight, so it is skipped when
 * there is no gauge and on a full pull, which recounts from scratch: either
 * way the answer goes unused, and on a full pull it would be six figures of
 * extra socache reads under the global lock.
 */
static int probe_existing(apply_ctx_t *a, const unsigned char *key,
                          apr_size_t keylen, unsigned char *origin)
{
    decision_value_t old;
    unsigned int olen = sizeof(old);

    if (!a->sconf->metrics) {
        return 0;
    }
    if (a->sconf->cache_provider->retrieve(a->sconf->cache_instance, a->s, key,
                                           (unsigned int) keylen,
                                           (unsigned char *) &old, &olen,
                                           a->p) != APR_SUCCESS
        || !value_ok(a->sconf, &old, olen)) {
        return 0;
    }
    *origin = old.origin;

    return 1;
}

/* The slot tracking this key, or -1. Caller holds the lock. */
static int sample_slot(const sample_set_t *ss, const unsigned char *key,
                       apr_size_t keylen)
{
    int i;

    for (i = 0; i < CROWDSEC_SAMPLES_MAX; i++) {
        if ((apr_size_t) ss->len[i] == keylen
            && !memcmp(ss->key[i], key, keylen)) {
            return i;
        }
    }
    return -1;
}

/* Starts tracking this key if a slot is free. A full set is left as it is: its
 * keys are the oldest entries we wrote, and those are the ones shmcb
 * force-expires first, so replacing them with newer ones would trade away the
 * sensitivity this is here for.
 */
static void sample_note(apply_ctx_t *a, const unsigned char *key,
                        apr_size_t keylen, apr_time_t expires)
{
    sample_set_t *ss = &a->sconf->meta->samples;
    int slot = sample_slot(ss, key, keylen);
    int i;

    if (slot >= 0) {
        ss->expires[slot] = expires;    /* re-stored, with a new duration */
        return;
    }
    for (i = 0; i < CROWDSEC_SAMPLES_MAX; i++) {
        if (!ss->len[i]) {
            memcpy(ss->key[i], key, keylen);
            ss->len[i] = (unsigned char) keylen;
            ss->expires[i] = expires;
            ss->tracked++;
            return;
        }
    }
}

/* A decision the stream has withdrawn leaves the cache legitimately, so stop
 * expecting to find it.
 */
static void sample_forget(apply_ctx_t *a, const unsigned char *key,
                          apr_size_t keylen)
{
    sample_set_t *ss = &a->sconf->meta->samples;
    int slot = sample_slot(ss, key, keylen);

    if (slot >= 0) {
        ss->len[slot] = 0;
    }
}

static apr_status_t apply_one(void *ctx, int added,
                              const crowdsec_decision_t *d)
{
    apply_ctx_t *a = ctx;
    unsigned char key[CROWDSEC_KEY_MAX];
    apr_size_t keylen;
    decision_value_t val;
    apr_time_t expires = apr_time_now() + d->duration;
    unsigned char oid, had_origin = CROWDSEC_ORIGIN_UNKNOWN;
    int ipt = net_ipt(&d->net);
    int had = 0;

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

    /* Interning may take the metrics mutex, and we are holding the cache's.
     * That nesting is only ever in this direction - the metrics code never
     * touches the socache - so there is no cycle to deadlock on. It also only
     * happens the first time each origin is seen.
     */
    oid = crowdsec_metrics_origin_id(a->sconf,
                                     d->origin[0] ? d->origin : "unknown");

    if (!added) {
        /* The origin has to come out of the store before the entry does: the
         * stream says what to remove, not what it was attributed to.
         */
        had = probe_existing(a, key, keylen, &had_origin);
        /* A removal for something we never had is not an error. */
        a->sconf->cache_provider->remove(a->sconf->cache_instance, a->s,
                                         key, (unsigned int) keylen, a->p);
        sample_forget(a, key, keylen);
        if (had) {
            crowdsec_metrics_active_add(a->sconf, ipt, had_origin, -1);
        }
        return APR_SUCCESS;
    }

    if (!a->full) {
        had = probe_existing(a, key, keylen, &had_origin);
    }

    /* Every stream decision is a ban: a challenge from LAPI carries no
     * interstitial to serve and must fail closed, and captcha maps to ban
     * because this module does not implement captcha.
     */
    val.version = DECISION_VALUE_VERSION;
    val.rem = (unsigned char) CROWDSEC_REM_BAN;
    val.origin = oid;
    gen_put(&val, a->gen);

    if (a->sconf->cache_provider->store(a->sconf->cache_instance, a->s,
                                        key, (unsigned int) keylen, expires,
                                        (unsigned char *) &val, sizeof(val),
                                        a->p) != APR_SUCCESS) {
        a->store_failures++;
        return APR_SUCCESS;     /* keep going; the count is reported after */
    }
    plen_set(d->net.family == 6 ? &a->plens6 : &a->plens4, d->net.plen);
    a->stored++;

    if (a->full) {
        a->fresh_active[oid][ipt]++;
    }
    else if (!had) {
        crowdsec_metrics_active_add(a->sconf, ipt, oid, 1);
    }
    else if (had_origin != oid) {
        /* The same network, re-attributed - a blocklist picking up an address
         * the community list already had, say. The population has not grown,
         * so move the count rather than adding to it.
         */
        crowdsec_metrics_active_add(a->sconf, ipt, had_origin, -1);
        crowdsec_metrics_active_add(a->sconf, ipt, oid, 1);
    }

    /* A full pull writes six figures, so every hundredth is enough and leaves
     * the probes spread over the start of the batch - the part the cache
     * force-expires first. A delta writes too few entries for that to pick
     * anything at all, so each of its own takes a slot if one is free.
     */
    if (!a->full || (a->stored % CROWDSEC_SAMPLE_EVERY) == 0) {
        sample_note(a, key, keylen, expires);
    }
    return APR_SUCCESS;
}

/* Re-reads the tracked keys to see whether the cache still has what we wrote.
 * shmcb force-expires the oldest entry in a subcache to admit a new one and
 * only logs it at debug level, so without this a cache that is too small
 * silently stops blocking people.
 *
 * Runs on every pull, not only on the full ones that publish st->stored:
 * eviction can begin at any point, and a cache filled a few decisions at a
 * time never has a pull large enough to notice it from its own batch.
 */
static void check_retention(server_rec *s, apply_ctx_t *a,
                            crowdsec_store_stats_t *st)
{
    sample_set_t *ss = &a->sconf->meta->samples;
    apr_time_t now = apr_time_now();
    apr_size_t lost_now = 0;
    int i;

    for (i = 0; i < CROWDSEC_SAMPLES_MAX; i++) {
        decision_value_t val;
        unsigned int len = sizeof(val);

        if (!ss->len[i]) {
            continue;
        }
        if (ss->expires[i] <= now) {
            ss->len[i] = 0;     /* ran its course, which is not eviction */
            continue;
        }
        if (a->sconf->cache_provider->retrieve(a->sconf->cache_instance, s,
                                               ss->key[i],
                                               (unsigned int) ss->len[i],
                                               (unsigned char *) &val, &len,
                                               a->p) == APR_SUCCESS) {
            continue;
        }
        /* Freed so the slot can follow something that is still there. What was
         * lost stays in the set's counters, which only reset on a full pull.
         */
        ss->len[i] = 0;
        ss->lost++;
        lost_now++;
    }

    if (a->full) {
        /* A full pull has just rebuilt the store from a snapshot, so this is
         * the population. An incremental one knows only how much its own batch
         * added, which is not an answer to the question, so it leaves the
         * figure - and the age reported next to it - alone.
         */
        st->stored = (apr_uint32_t) a->stored;
        st->stored_at = now;
    }
    /* Scaled, because only CROWDSEC_SAMPLES_MAX keys are ever probed: the
     * share of the tracked keys that went missing is taken as the share of the
     * population that did.
     */
    st->retained = ss->tracked
        ? (apr_uint32_t) (st->stored
                          - (apr_uint64_t) ss->lost * st->stored / ss->tracked)
        : st->stored;

    if (lost_now) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: decision cache is too small: %"
                     APR_SIZE_T_FMT " tracked entries were dropped before "
                     "their decisions expired, %u of %u since the last full "
                     "pull. Increase the CrowdsecCache size; decisions are "
                     "being dropped and those clients are no longer blocked.",
                     lost_now, (unsigned int) ss->lost,
                     (unsigned int) ss->tracked);
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
    a.full = full ? 1 : 0;

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

    /* After the lease check, so the discard path above has nothing to undo.
     * A full pull takes a fresh generation and publishes it as the one being
     * applied; lookups accept both it and the live one until the commit below
     * makes it the live one, because the apply drops the lock in slices.
     */
    if (full) {
        a.gen = gen_take(sconf);
        sconf->meta->gen_applying = a.gen;
        /* The tracked keys belong to the snapshot being replaced, so the
         * eviction tally restarts with the one this pull is about to write.
         */
        memset(&sconf->meta->samples, 0, sizeof(sconf->meta->samples));
    }
    else {
        a.gen = sconf->meta->gen;
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

        if (full) {
            /* And the same for the entries themselves: a decision the snapshot
             * has stopped carrying stays in the socache - there is no way to
             * enumerate it and delete it - so retiring the generation it was
             * written in is what stops it matching. It then ages out on its
             * own expiry. Without this, a deletion the previous leader
             * consumed before dying would keep blocking its client for the
             * decision's full duration.
             */
            sconf->meta->gen = a.gen;
            sconf->meta->gen_applying = 0;

            /* The active_decisions gauge is kept up to date entry by entry as
             * incremental batches arrive, but that alone drifts upward: the
             * socache expires an entry when its decision runs out and tells
             * nobody, so the decrement never happens. The cache force-expiring
             * an entry to make room is just as silent. A full pull is the one
             * moment we know exactly what is in the store, so it replaces the
             * gauge outright - which is also why the push thread asks for a
             * full pull once per reporting window.
             */
            crowdsec_metrics_active_replace(sconf, a.fresh_active);
        }

        check_retention(s, &a, &st);
        st.last_pull = apr_time_now();
        st.pulls++;
        if (!st.primed_at) {
            st.primed_at = st.last_pull;
        }
        sconf->meta->stats = st;
        sconf->meta->primed_at = st.primed_at;
    }

    if (full && !parsed && a.locked) {
        /* Nothing was committed, so the generation we were writing is not a
         * snapshot and the entries already stored under it stop matching here.
         * The number itself is spent: gen_seq moved when we took it, so the
         * next full pull cannot hand it out again and revive them.
         *
         * apply_yield can also return with the lock lost, and then this cannot
         * run; the generation stays accepted until the next full pull commits.
         * Not worth an unlock path of its own.
         */
        sconf->meta->gen_applying = 0;
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
                       crowdsec_rem_t *rem, unsigned char *origin)
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
        && value_ok(sconf, &val, vlen)) {
        *rem = (crowdsec_rem_t) val.rem;
        *origin = val.origin;
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
            && value_ok(sconf, &val, vlen)) {
            *rem = (crowdsec_rem_t) val.rem;
            *origin = val.origin;
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
                    crowdsec_rem_t *rem, unsigned char *origin)
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
        *origin = slot->origin;
        hit = 1;
    }
    if (sconf->memo.mutex) {
        apr_thread_mutex_unlock(sconf->memo.mutex);
    }
    return hit;
}

static void memo_put(crowdsec_server_rec *sconf, const char *ip,
                     crowdsec_rem_t rem, unsigned char origin)
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
    slot->origin = origin;
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
 * This reuses the decision key space, which is only safe as long as no two
 * servers sharing a cache disagree on the mode: a live-mode allow sits at the
 * full-width key, and store_probe answers from the exact address before it
 * ever reaches the shorter prefixes, so it would shadow a stream range ban.
 * post_config refuses that configuration at startup rather than leaving this
 * as an assumption.
 *
 * The difference is that live mode stores allow as well as ban - absence means
 * "not asked yet" rather than "allowed" - and expires entries after
 * CrowdsecCacheTimeout rather than the decision's own duration.
 */
static int live_cache_get(request_rec *r, crowdsec_server_rec *sconf,
                          const crowdsec_net_t *host, crowdsec_rem_t *rem,
                          unsigned char *origin)
{
    unsigned char key[CROWDSEC_KEY_MAX];
    decision_value_t val;
    apr_size_t keylen;
    unsigned int vlen = sizeof(val);
    int hit = 0;

    if (!sconf->cache_instance || !sconf->meta) {
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
        && value_ok(sconf, &val, vlen)) {
        *rem = (crowdsec_rem_t) val.rem;
        *origin = val.origin;
        hit = 1;
    }
    crowdsec_store_unlock(sconf);

    return hit;
}

static void live_cache_put(request_rec *r, crowdsec_server_rec *sconf,
                           const crowdsec_net_t *host, crowdsec_rem_t rem,
                           unsigned char origin)
{
    unsigned char key[CROWDSEC_KEY_MAX];
    decision_value_t val;
    apr_size_t keylen;

    if (!sconf->cache_instance || !sconf->meta) {
        return;
    }
    keylen = crowdsec_key_encode(host, key, sizeof(key));
    if (!keylen) {
        return;
    }
    val.version = DECISION_VALUE_VERSION;
    val.rem = (unsigned char) rem;
    val.origin = origin;

    if (crowdsec_store_lock(sconf) != APR_SUCCESS) {
        return;
    }
    /* Under the lock, because meta is only ever read there. Live mode runs no
     * poller, so this is always the one generation the server ever has.
     */
    gen_put(&val, sconf->meta->gen);
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
                                    const char *ip, crowdsec_rem_t *rem,
                                    unsigned char *origin)
{
    char origin_name[CROWDSEC_ORIGIN_LEN];
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
    if (!crowdsec_decisions_probe(buf.data, buf.len, r->pool, &any,
                                  origin_name, sizeof(origin_name), &perr)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: could not parse the decisions reply: %s",
                      perr ? perr : "unknown");
        return CROWDSEC_LOOKUP_FAIL;
    }
    /* Every decision LAPI returns for this address is treated as a ban, for
     * the same reason the stream is.
     */
    *rem = any ? CROWDSEC_REM_BAN : CROWDSEC_REM_ALLOW;
    *origin = any ? crowdsec_metrics_origin_id(sconf,
                                               origin_name[0] ? origin_name
                                               : "unknown")
        : CROWDSEC_ORIGIN_UNKNOWN;

    return CROWDSEC_LOOKUP_OK;
}

/* ---------------------------------------------------------------- lookup */

crowdsec_lookup_t crowdsec_lapi_lookup(request_rec *r,
                                       crowdsec_server_rec *sconf,
                                       const char *ip, crowdsec_rem_t *rem,
                                       unsigned char *origin)
{
    crowdsec_net_t host;
    crowdsec_lookup_t lr;
    apr_time_t primed = 0;
    int found;

    *rem = CROWDSEC_REM_ALLOW;
    *origin = CROWDSEC_ORIGIN_UNKNOWN;

    if (memo_get(sconf, ip, rem, origin)) {
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
        if (live_cache_get(r, sconf, &host, rem, origin)) {
            memo_put(sconf, ip, *rem, *origin);
            apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "cache");
            return CROWDSEC_LOOKUP_OK;
        }
        lr = live_query(r, sconf, ip, rem, origin);
        if (lr == CROWDSEC_LOOKUP_OK) {
            live_cache_put(r, sconf, &host, *rem, *origin);
            memo_put(sconf, ip, *rem, *origin);
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
    found = store_probe(r->server, sconf, &host, r->pool, rem, origin);
    crowdsec_store_unlock(sconf);

    if (!found) {
        *rem = CROWDSEC_REM_ALLOW;
        *origin = CROWDSEC_ORIGIN_UNKNOWN;
    }
    memo_put(sconf, ip, *rem, *origin);
    apr_table_setn(r->subprocess_env, "CROWDSEC_SOURCE", "cache");

    return CROWDSEC_LOOKUP_OK;
}
