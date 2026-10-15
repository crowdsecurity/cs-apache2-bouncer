/* JSON parsing of everything CrowdSec sends us, on a vendored yyjson.
 *
 * Decisions are delivered through a callback rather than returned as an array:
 * a startup stream pull can carry a six-figure number of entries, and
 * buffering them before storing would double the peak memory for no gain.
 */
#ifndef CROWDSEC_VERDICT_H
#define CROWDSEC_VERDICT_H

#include "crowdsec_internal.h"

/* Bounds on what we will accept from one response. These are tripwires for a
 * corrupt or hostile payload, not tuning knobs; a legitimate stream is far
 * below them.
 */
#define CROWDSEC_MAX_DECISIONS 2000000
#define CROWDSEC_MAX_FIELD_LEN 256

typedef struct
{
    crowdsec_net_t net;         /* already masked to its prefix */
    apr_interval_time_t duration;
} crowdsec_decision_t;

/* Returning anything but APR_SUCCESS aborts the parse. */
typedef apr_status_t (*crowdsec_decision_cb) (void *ctx, int added,
                                              const crowdsec_decision_t *d);

typedef struct
{
    apr_size_t added;           /* applied from "new" */
    apr_size_t removed;         /* applied from "deleted" */
    apr_size_t skipped_scope;   /* Country, AS, anything we cannot evaluate */
    apr_size_t skipped_expired; /* duration already elapsed */
    apr_size_t malformed;       /* unparseable value, bad duration, wrong type */
} crowdsec_decision_stats_t;

/* A /v1/decisions/stream body: {"new":[...],"deleted":[...]}. Either key may
 * be absent or null. On failure *err gets a short static reason.
 */
int crowdsec_stream_parse(const char *buf, apr_size_t len, apr_pool_t *p,
                          crowdsec_decision_cb cb, void *ctx,
                          crowdsec_decision_stats_t *stats,
                          const char **err);

/* A /v1/decisions?ip= body: null, [], or an array of decisions. LAPI has
 * already done the range matching, so the only question is whether anything
 * came back. *any is set to 0 or 1.
 */
int crowdsec_decisions_any(const char *buf, apr_size_t len, apr_pool_t *p,
                           int *any, const char **err);

#endif /* CROWDSEC_VERDICT_H */
