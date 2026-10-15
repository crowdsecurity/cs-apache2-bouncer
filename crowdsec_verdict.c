#include <string.h>

#include "apr_strings.h"

#include "yyjson.h"

#include "crowdsec_util.h"
#include "crowdsec_verdict.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"

/* One arena sized from the input, so parsing allocates exactly once and the
 * module keeps its no-malloc property. yyjson's reader is iterative, so the
 * only thing deep nesting costs is this arena, which the input length bounds.
 */
static yyjson_doc *parse_bounded(const char *buf, apr_size_t len,
                                 apr_pool_t *p, const char **err)
{
    yyjson_alc alc;
    yyjson_doc *doc;
    yyjson_read_err rerr;
    apr_size_t need;
    void *arena;

    if (!buf || !len) {
        *err = "empty body";
        return NULL;
    }
    need = yyjson_read_max_memory_usage(len, YYJSON_READ_NOFLAG);
    if (!need) {
        *err = "cannot size arena";
        return NULL;
    }
    arena = apr_palloc(p, need);
    if (!arena) {
        *err = "arena allocation failed";
        return NULL;
    }
    if (!yyjson_alc_pool_init(&alc, arena, need)) {
        *err = "arena init failed";
        return NULL;
    }

    /* The explicit length matters: the body carries no NUL guarantee and may
     * contain one. INSITU is deliberately not used - it would mutate the
     * caller's buffer and needs padding we have not reserved.
     */
    doc = yyjson_read_opts((char *) buf, len, YYJSON_READ_NOFLAG, &alc, &rerr);
    if (!doc) {
        *err = rerr.msg ? rerr.msg : "malformed json";
        return NULL;
    }
    return doc;
}

/* A string field, rejecting an embedded NUL: yyjson hands back a terminated
 * buffer, but a JSON escaped-zero makes the reported length exceed strlen, and
 * a value that disagrees with its own length has no business becoming a cache
 * key.
 */
static const char *str_field(yyjson_val *obj, const char *key)
{
    yyjson_val *v = yyjson_obj_get(obj, key);
    const char *s;
    size_t n;

    if (!v || !yyjson_is_str(v)) {
        return NULL;
    }
    s = yyjson_get_str(v);
    n = yyjson_get_len(v);
    if (!s || n > CROWDSEC_MAX_FIELD_LEN || n != strlen(s)) {
        return NULL;
    }
    return s;
}

/* Ip and Range are the only scopes we can evaluate; Country and AS need geo
 * data this module does not have. Matched case-insensitively because scope is
 * a free-text column.
 */
static int scope_supported(const char *scope)
{
    return scope
        && (!strcasecmp(scope, "ip") || !strcasecmp(scope, "range"));
}

static int one_decision(yyjson_val *item, int added,
                        crowdsec_decision_cb cb, void *ctx,
                        crowdsec_decision_stats_t *stats,
                        apr_status_t *cbrv)
{
    crowdsec_decision_t d;
    const char *scope, *value, *dur;

    if (!yyjson_is_obj(item)) {
        stats->malformed++;
        return 1;
    }
    scope = str_field(item, "scope");
    value = str_field(item, "value");

    if (!scope_supported(scope)) {
        stats->skipped_scope++;
        return 1;
    }
    if (!value) {
        stats->malformed++;
        return 1;
    }

    memset(&d, 0, sizeof(d));
    /* Validates the prefix length against the family before masking, so a
     * malformed value can never yield a key that aliases another network.
     */
    if (!crowdsec_cidr_parse(value, &d.net)) {
        stats->malformed++;
        return 1;
    }

    /* "deleted" entries are removals: their duration is irrelevant, and LAPI
     * sends the elapsed one, which would otherwise read as expired.
     */
    if (added) {
        dur = str_field(item, "duration");
        if (!dur || !crowdsec_parse_duration(dur, &d.duration)) {
            stats->malformed++;
            return 1;
        }
        if (d.duration <= 0) {
            stats->skipped_expired++;
            return 1;
        }
    }

    *cbrv = cb(ctx, added, &d);
    if (*cbrv != APR_SUCCESS) {
        return 0;
    }
    if (added) {
        stats->added++;
    }
    else {
        stats->removed++;
    }
    return 1;
}

static int walk_array(yyjson_val *arr, int added, crowdsec_decision_cb cb,
                      void *ctx, crowdsec_decision_stats_t *stats,
                      apr_size_t *seen, const char **err)
{
    yyjson_val *item;
    yyjson_arr_iter it;
    apr_status_t cbrv = APR_SUCCESS;

    if (!arr || yyjson_is_null(arr)) {
        return 1;               /* absent or null is a legal empty list */
    }
    if (!yyjson_is_arr(arr)) {
        *err = "new/deleted is not an array";
        return 0;
    }
    yyjson_arr_iter_init(arr, &it);
    while ((item = yyjson_arr_iter_next(&it))) {
        if (++(*seen) > CROWDSEC_MAX_DECISIONS) {
            *err = "too many decisions";
            return 0;
        }
        if (!one_decision(item, added, cb, ctx, stats, &cbrv)) {
            *err = "callback aborted";
            return 0;
        }
    }
    return 1;
}

int crowdsec_stream_parse(const char *buf, apr_size_t len, apr_pool_t *p,
                          crowdsec_decision_cb cb, void *ctx,
                          crowdsec_decision_stats_t *stats,
                          const char **err)
{
    yyjson_doc *doc;
    yyjson_val *root;
    apr_size_t seen = 0;
    int ok = 0;

    if (!err) {
        return 0;
    }
    *err = "internal";
    if (!cb || !stats || !p) {
        return 0;
    }
    memset(stats, 0, sizeof(*stats));

    doc = parse_bounded(buf, len, p, err);
    if (!doc) {
        return 0;
    }
    root = yyjson_doc_get_root(doc);

    if (!root || !yyjson_is_obj(root)) {
        *err = "stream root is not an object";
    }
    /* Deletions first: if a value somehow appears in both lists, the outcome
     * should be that it is present, not absent.
     */
    else if (walk_array(yyjson_obj_get(root, "deleted"), 0, cb, ctx, stats,
                        &seen, err)
             && walk_array(yyjson_obj_get(root, "new"), 1, cb, ctx, stats,
                           &seen, err)) {
        ok = 1;
        *err = NULL;
    }

    yyjson_doc_free(doc);

    return ok;
}

int crowdsec_decisions_any(const char *buf, apr_size_t len, apr_pool_t *p,
                           int *any, const char **err)
{
    yyjson_doc *doc;
    yyjson_val *root;
    int ok = 0;

    if (!err) {
        return 0;
    }
    *err = "internal";
    if (!any || !p) {
        return 0;
    }
    *any = 0;

    doc = parse_bounded(buf, len, p, err);
    if (!doc) {
        return 0;
    }
    root = yyjson_doc_get_root(doc);

    if (!root) {
        *err = "no root";
    }
    else if (yyjson_is_null(root)) {
        ok = 1;                 /* "null" is how LAPI says "no decisions" */
        *err = NULL;
    }
    else if (yyjson_is_arr(root)) {
        *any = yyjson_arr_size(root) > 0;
        ok = 1;
        *err = NULL;
    }
    else {
        *err = "decisions root is neither null nor an array";
    }

    yyjson_doc_free(doc);

    return ok;
}
