/* Usage metrics: the shared counters, and reporting them to the local API's
 * /v1/usage-metrics, which is what feeds cscli metrics show bouncers and the
 * Console's remediation panel.
 *
 * The counters live in their own shared region rather than in the decision
 * store's. They have to: metrics also run in live mode, where CrowdsecCache
 * may not be configured at all and struct crowdsec_meta is therefore never
 * created.
 */
#ifndef CROWDSEC_METRICS_H
#define CROWDSEC_METRICS_H

#include "crowdsec_config.h"

#include "crowdsec_metrics_json.h"

/* Reserved slots, interned before any decision is seen so that their ids are
 * compile-time constants. Slot 0 matters most: it is what a zeroed origin byte
 * in a decision value resolves to, so an un-attributable decision reads as
 * "blocked, origin unknown" rather than as someone else's traffic.
 */
#define CROWDSEC_ORIGIN_UNKNOWN 0
#define CROWDSEC_ORIGIN_APPSEC  1

/* 15 minutes, matching every other remediation component. */
#define CROWDSEC_METRICS_INTERVAL_DEFAULT apr_time_from_sec(900)

/* Short enough for a test to watch several windows, long enough that a typo
 * cannot turn the bouncer into a load generator against the local API.
 */
#define CROWDSEC_METRICS_INTERVAL_MIN apr_time_from_sec(10)

/* Opaque: the layout is private to crowdsec_metrics.c. */
struct crowdsec_metrics_shm;

/* ----------------------------------------------------------- lifecycle */

/* Registers the metrics mutex. Call from pre_config. */
apr_status_t crowdsec_metrics_pre_config(apr_pool_t *pconf);

/* Creates the shared region and its mutex for s, or points s at one an earlier
 * server already created for the same (url, key). Call from post_config for
 * every server; it decides for itself whether there is anything to do.
 */
apr_status_t crowdsec_metrics_create(apr_pool_t *pconf, apr_pool_t *plog,
                                    server_rec *base, server_rec *s);

/* Starts one push thread per region per child. Safe to call when no server
 * reports metrics, in which case it does nothing.
 */
apr_status_t crowdsec_metrics_start(apr_pool_t *pchild, server_rec *base);

/* --------------------------------------------------------- the counters */

/* Interns origin and returns its slot id, or CROWDSEC_ORIGIN_UNKNOWN when the
 * table is full. A lock-free scan on the hit path, which is all but the first
 * sighting of each origin.
 */
unsigned char crowdsec_metrics_origin_id(crowdsec_server_rec *sconf,
                                         const char *origin);

/* The request path. Both are a single atomic add; neither takes a lock. */
void crowdsec_metrics_processed(crowdsec_server_rec *sconf, int ipt);
void crowdsec_metrics_dropped(crowdsec_server_rec *sconf, int ipt,
                              unsigned char origin);

/* The active_decisions gauge, maintained by the decision store. delta is +1 or
 * -1; the count is floored at zero so an unbalanced removal cannot wrap it.
 */
void crowdsec_metrics_active_add(crowdsec_server_rec *sconf, int ipt,
                                 unsigned char origin, int delta);

/* Replaces the whole gauge with a freshly counted one. Called at the end of a
 * full pull, the only moment the store knows the absolute truth - see the
 * comment at the call site for why the gauge needs resynchronising at all.
 */
void crowdsec_metrics_active_replace(crowdsec_server_rec *sconf,
                                     const apr_uint32_t fresh
                                     [CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX]);

/* Whether the push thread has asked for the next pull to be a full one. Taking
 * the request clears it, so it is answered once.
 */
int crowdsec_metrics_resync_take(crowdsec_server_rec *sconf);

/* ------------------------------------------------------------- reporting */

/* Appends the metrics section of the CrowdsecStatus handler. */
void crowdsec_metrics_status(request_rec *r, crowdsec_server_rec *sconf);

#endif /* CROWDSEC_METRICS_H */
