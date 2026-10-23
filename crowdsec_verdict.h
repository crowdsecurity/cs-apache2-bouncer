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

/* Bounds on an AppSec verdict. user_headers and user_cookies come from the
 * engine, but their contents are influenced by whoever wrote the appsec
 * configuration, so they are bounded like any other input. The challenge page
 * itself is not capped here: it is already bounded by the response ceiling,
 * and a legitimate one is a few hundred kilobytes.
 */
#define CROWDSEC_MAX_HEADERS      32
#define CROWDSEC_MAX_HEADER_VALS   8
#define CROWDSEC_MAX_COOKIES       8
#define CROWDSEC_MAX_HEADER_NAME 256
#define CROWDSEC_MAX_HEADER_VAL  4096

typedef struct
{
    crowdsec_net_t net;         /* already masked to its prefix */
    apr_interval_time_t duration;
    /* The local API's id for this decision, or 0 when it was absent. Kept so a
     * removal can tell whether it is withdrawing the decision the store holds
     * for this network or another one that was shadowed by it.
     */
    apr_int64_t id;
    /* Who decided: "crowdsec", "cscli", "CAPI", "console", or
     * "lists:<blocklist name>" composed from origin and scenario. Inline
     * rather than a pointer into the document, because composing it is the one
     * thing that would otherwise allocate once per decision - and a full pull
     * carries six figures of them. Empty when the field was absent.
     */
    char origin[CROWDSEC_ORIGIN_LEN];
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
 *
 * origin receives the first decision's origin, composed the same way the
 * stream's is, so a live-mode block can be attributed too. It is the first
 * rather than the most severe because every decision here is enforced as a
 * ban, so there is no severity to compare. NUL-terminated, empty when there
 * was nothing to report; pass NULL to ignore it.
 */
int crowdsec_decisions_probe(const char *buf, apr_size_t len, apr_pool_t *p,
                             int *any, char *origin, apr_size_t originlen,
                             const char **err);

typedef struct
{
    const char *name;
    const char *value;
} crowdsec_hdr_t;

typedef struct
{
    crowdsec_rem_t rem;
    const char *action;         /* verbatim, for logging an unknown one */
    int http_status;            /* what the browser gets, not what we got */

    /* Only populated for action challenge. */
    const char *content_type;   /* kept apart: must go through ap_set_content_type */
    const char *body;
    apr_size_t body_len;
    const char **cookies;       /* complete Set-Cookie values */
    apr_size_t ncookies;
    crowdsec_hdr_t *headers;
    apr_size_t nheaders;
} crowdsec_appsec_verdict_t;

/* An AppSec response body. Must be called for a 200 as well as a 403: with
 * default_pass_action set, a 200 can still carry captcha or challenge.
 *
 * Everything in *out is copied into p, so the caller may use it after this
 * returns. Returns 1 on success; on failure *err gets a short static reason
 * and the caller applies its failure action.
 */
int crowdsec_appsec_parse(const char *buf, apr_size_t len, apr_pool_t *p,
                          crowdsec_appsec_verdict_t *out, const char **err);

#endif /* CROWDSEC_VERDICT_H */
