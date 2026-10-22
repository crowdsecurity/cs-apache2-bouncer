/* The usage-metrics payload, and the counters it is built from.
 *
 * Deliberately apr-only, like crowdsec_verdict.h: the payload format is the
 * part most worth testing exhaustively, and keeping httpd out of it means the
 * unit test links against apr alone and needs no running server.
 */
#ifndef CROWDSEC_METRICS_JSON_H
#define CROWDSEC_METRICS_JSON_H

#include "crowdsec_internal.h"

/* How many distinct origins we can attribute to. An origin is "crowdsec",
 * "cscli", "CAPI", "console" or "lists:<blocklist name>", so a realistic count
 * is the number of blocklists subscribed to plus a handful. Past this,
 * attribution falls back to the unknown slot and is counted there rather than
 * silently merged into someone else's.
 *
 * The slot length is CROWDSEC_ORIGIN_LEN, shared with the decision parser so
 * that what it composes is what fits here. Both are free to raise - the whole
 * shared region is two pages either way.
 */
#define CROWDSEC_ORIGIN_MAX 64

/* Address families, as a label and as an array index. */
#define CROWDSEC_IPT_V4  0
#define CROWDSEC_IPT_V6  1
#define CROWDSEC_IPT_MAX 2

/* A copy of the counters, taken without a lock and handed to the builder. */
typedef struct
{
    char origins[CROWDSEC_ORIGIN_MAX][CROWDSEC_ORIGIN_LEN];
    apr_uint32_t norigins;
    apr_uint32_t processed[CROWDSEC_IPT_MAX];
    apr_uint32_t dropped[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
    apr_uint32_t active[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
    /* Sticky: set once a gauge slot has held anything, never cleared. It is
     * what lets the builder report an explicit zero for an origin whose
     * decisions have all gone - a blocklist that was unsubscribed, say.
     * Without it, absence would be indistinguishable from "unchanged" and the
     * Console would keep showing the last non-zero count for good.
     */
    unsigned char active_seen[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
    /* Live mode has no local decision store to count, so it emits no
     * active_decisions at all rather than a misleading zero.
     */
    unsigned int have_active:1;
} crowdsec_metrics_snap_t;

/* What does not change between windows. Resolved once per process. */
typedef struct
{
    const char *os_name;
    const char *os_version;
    apr_time_t startup;
} crowdsec_metrics_static_t;

/* Builds the payload for one window. Pure: no I/O, no globals, everything
 * allocated from p. Returns NULL only if an allocation fails.
 */
char *crowdsec_metrics_payload(apr_pool_t *p,
                               const crowdsec_metrics_static_t *st,
                               const crowdsec_metrics_snap_t *snap,
                               apr_time_t now, apr_interval_time_t window);

/* NAME and VERSION_ID out of an os-release file's contents. Never fails:
 * whatever it cannot find becomes a placeholder, because the local API rejects
 * a payload whose os.name or os.version is empty.
 */
void crowdsec_os_release_parse(const char *buf, apr_size_t len, apr_pool_t *p,
                               const char **name, const char **version);

#endif /* CROWDSEC_METRICS_JSON_H */
