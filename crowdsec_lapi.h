/* Decision storage and retrieval: the shared socache store, the per-child
 * verdict memo, the live query, and the stream poller.
 */
#ifndef CROWDSEC_LAPI_H
#define CROWDSEC_LAPI_H

#include "crowdsec_config.h"
#include "crowdsec_verdict.h"

/* Outcome of asking "is this address under a decision?" */
typedef enum
{
    CROWDSEC_LOOKUP_OK = 0,     /* answered; *rem holds the remediation */
    CROWDSEC_LOOKUP_UNPRIMED,   /* stream mode, first pull not finished yet */
    CROWDSEC_LOOKUP_FAIL        /* could not reach LAPI, or the reply was junk */
} crowdsec_lookup_t;

/* One decision cache's statistics, kept in the shared cache so every child
 * reports the same numbers and the CrowdsecStatus handler can show them.
 */
typedef struct
{
    apr_time_t last_pull;
    apr_time_t primed_at;
    apr_time_t stored_at;       /* when stored was last measured */
    /* What the last full pull wrote, and how much of it the cache still has.
     * A full pull rebuilds the store from a snapshot, so it is the only kind
     * that knows the population; an incremental one reports the size of its
     * own batch, which says nothing about what is held, and so leaves stored
     * alone. retained is re-estimated on every pull, because the cache can
     * start evicting at any point.
     */
    apr_uint32_t stored;
    apr_uint32_t retained;
    apr_uint32_t pulls;
    apr_uint32_t leader_changes;
} crowdsec_store_stats_t;

/* Creates the shared control region (lease, primed flag, statistics, prefix
 * bitmaps). Called from post_config for the server that owns the cache; the
 * others are handed the same pointer.
 */
apr_status_t crowdsec_meta_create(apr_pool_t *pconf,
                                  crowdsec_server_rec *sconf);

apr_status_t crowdsec_memo_init(apr_pool_t *pchild, crowdsec_server_rec *sconf);

/* Answers from the memo, then the shared cache (stream) or LAPI (live).
 *
 * *origin receives the slot id of whoever decided, for the dropped metric. It
 * is CROWDSEC_ORIGIN_UNKNOWN whenever there is no decision behind the answer,
 * which includes every allow.
 */
crowdsec_lookup_t crowdsec_lapi_lookup(request_rec *r,
                                       crowdsec_server_rec *sconf,
                                       const char *ip, crowdsec_rem_t *rem,
                                       unsigned char *origin);

/* Starts one poller thread per stream-mode vhost. Safe to call when no vhost
 * uses stream mode, in which case it does nothing.
 */
apr_status_t crowdsec_poller_start(apr_pool_t *pchild, server_rec *s);

/* Reads the shared statistics. Returns 0 when there is no cache. */
int crowdsec_store_stats(server_rec *s, crowdsec_server_rec *sconf,
                         crowdsec_store_stats_t *out);

/* Exposed for the tests: applies one already-parsed stream body to the store,
 * exactly as the poller would.
 */
apr_status_t crowdsec_store_apply_stream(server_rec *s,
                                         crowdsec_server_rec *sconf,
                                         const char *body, apr_size_t len,
                                         int full,
                                         crowdsec_decision_stats_t *stats,
                                         apr_pool_t *ptemp);

#endif /* CROWDSEC_LAPI_H */
