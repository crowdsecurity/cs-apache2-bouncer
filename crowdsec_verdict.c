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

/* The origin, with the rewrite every component applies: a blocklist decision
 * arrives as origin "lists" with the list's name in scenario, and reporting
 * them all as "lists" would collapse every blocklist into one line.
 *
 * Writes at most outlen-1 bytes plus a terminator, so a name longer than a
 * slot is truncated rather than dropped - a truncated attribution still beats
 * none. Leaves out empty on a missing or unusable field.
 */
static void decision_origin(yyjson_val *item, char *out, apr_size_t outlen)
{
    const char *origin = str_field(item, "origin");
    const char *scenario;

    out[0] = '\0';
    if (!origin || !*origin) {
        return;
    }
    if (!strcasecmp(origin, "lists")
        && (scenario = str_field(item, "scenario")) != NULL && *scenario) {
        apr_size_t n = apr_cpystrn(out, "lists:", outlen) - out;

        apr_cpystrn(out + n, scenario, outlen - n);
        return;
    }
    apr_cpystrn(out, origin, outlen);
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

    decision_origin(item, d.origin, sizeof(d.origin));

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

int crowdsec_decisions_probe(const char *buf, apr_size_t len, apr_pool_t *p,
                             int *any, char *origin, apr_size_t originlen,
                             const char **err)
{
    yyjson_doc *doc;
    yyjson_val *root;
    int ok = 0;

    if (!err) {
        return 0;
    }
    *err = "internal";
    if (!any || !p || (origin && !originlen)) {
        return 0;
    }
    *any = 0;
    if (origin) {
        origin[0] = '\0';
    }

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
        if (*any && origin) {
            yyjson_val *first = yyjson_arr_get(root, 0);

            if (first && yyjson_is_obj(first)) {
                decision_origin(first, origin, originlen);
            }
        }
        ok = 1;
        *err = NULL;
    }
    else {
        *err = "decisions root is neither null nor an array";
    }

    yyjson_doc_free(doc);

    return ok;
}

/* --------------------------------------------------------- appsec verdict */

/* A header the engine must not be allowed to set on our response.
 *
 * The framing ones would desync Apache on a keep-alive connection; a
 * Content-Encoding would make the browser try to inflate plain HTML; and
 * Server or Date would let a WAF response impersonate the origin. Content-Type
 * and Content-Length are handled through Apache's own setters instead, so the
 * values it computes are the ones that go out.
 */
static int header_denied(const char *name)
{
    static const char *const denied[] = {
        "transfer-encoding", "content-length", "connection", "keep-alive",
        "upgrade", "trailer", "te", "content-encoding", "date", "server",
        NULL
    };
    int i;

    for (i = 0; denied[i]; i++) {
        if (!strcasecmp(name, denied[i])) {
            return 1;
        }
    }
    return 0;
}

/* Copies a string out of the yyjson document, which is freed before we
 * return, after checking it can safely become a header value. Rejects an
 * embedded NUL by requiring the reported length to agree with strlen, and
 * rejects anything Apache's own parser would not accept in a field value -
 * which is what stops a CR or LF from splitting our response into two.
 */
static const char *dup_header_safe(apr_pool_t *p, yyjson_val *v,
                                   apr_size_t max)
{
    const char *s;
    size_t n;

    if (!v || !yyjson_is_str(v)) {
        return NULL;
    }
    s = yyjson_get_str(v);
    n = yyjson_get_len(v);
    if (!s || n == 0 || n > max || n != strlen(s)) {
        return NULL;
    }
    if (!crowdsec_hdr_value_ok(s)) {
        return NULL;
    }
    return apr_pstrmemdup(p, s, n);
}

static int parse_cookies(yyjson_val *arr, apr_pool_t *p,
                         crowdsec_appsec_verdict_t *out)
{
    yyjson_val *item;
    yyjson_arr_iter it;
    apr_size_t n;

    if (!arr || yyjson_is_null(arr)) {
        return 1;
    }
    if (!yyjson_is_arr(arr)) {
        return 0;
    }
    n = yyjson_arr_size(arr);
    if (n > CROWDSEC_MAX_COOKIES) {
        return 0;
    }
    out->cookies = apr_pcalloc(p, (n ? n : 1) * sizeof(*out->cookies));
    if (!out->cookies) {
        return 0;
    }
    yyjson_arr_iter_init(arr, &it);
    while ((item = yyjson_arr_iter_next(&it))) {
        const char *v = dup_header_safe(p, item, CROWDSEC_MAX_HEADER_VAL);

        if (!v) {
            return 0;
        }
        out->cookies[out->ncookies++] = v;
    }
    return 1;
}

static int parse_headers(yyjson_val *obj, apr_pool_t *p,
                         crowdsec_appsec_verdict_t *out)
{
    yyjson_val *key, *val;
    yyjson_obj_iter it;
    apr_size_t cap;

    if (!obj || yyjson_is_null(obj)) {
        return 1;
    }
    if (!yyjson_is_obj(obj)) {
        return 0;
    }
    if (yyjson_obj_size(obj) > CROWDSEC_MAX_HEADERS) {
        return 0;
    }
    /* Each name may carry several values, and each becomes its own header. */
    cap = yyjson_obj_size(obj) * CROWDSEC_MAX_HEADER_VALS;
    out->headers = apr_pcalloc(p, (cap ? cap : 1) * sizeof(*out->headers));
    if (!out->headers) {
        return 0;
    }

    yyjson_obj_iter_init(obj, &it);
    while ((key = yyjson_obj_iter_next(&it))) {
        const char *name;
        size_t nlen;

        val = yyjson_obj_iter_get_val(key);
        name = yyjson_get_str(key);
        nlen = yyjson_get_len(key);
        if (!name || !nlen || nlen > CROWDSEC_MAX_HEADER_NAME
            || nlen != strlen(name) || !crowdsec_hdr_name_ok(name)) {
            return 0;
        }
        if (header_denied(name)) {
            continue;           /* dropped, not an error */
        }
        if (!strcasecmp(name, "content-type")) {
            /* user_headers is map[string][]string, so a value is normally an
             * array even when it holds one item. Accept a bare string too,
             * since nothing in the protocol forbids it.
             */
            yyjson_val *first = val;

            if (yyjson_is_arr(val)) {
                if (yyjson_arr_size(val) != 1) {
                    return 0;   /* two content types is not meaningful */
                }
                first = yyjson_arr_get_first(val);
            }
            out->content_type = dup_header_safe(p, first,
                                                CROWDSEC_MAX_HEADER_VAL);
            if (!out->content_type) {
                return 0;
            }
            continue;
        }
        name = apr_pstrmemdup(p, name, nlen);

        if (yyjson_is_str(val)) {
            const char *v = dup_header_safe(p, val, CROWDSEC_MAX_HEADER_VAL);

            if (!v) {
                return 0;
            }
            out->headers[out->nheaders].name = name;
            out->headers[out->nheaders].value = v;
            out->nheaders++;
        }
        else if (yyjson_is_arr(val)) {
            yyjson_val *item;
            yyjson_arr_iter ait;

            if (yyjson_arr_size(val) > CROWDSEC_MAX_HEADER_VALS) {
                return 0;
            }
            yyjson_arr_iter_init(val, &ait);
            while ((item = yyjson_arr_iter_next(&ait))) {
                const char *v = dup_header_safe(p, item,
                                                CROWDSEC_MAX_HEADER_VAL);

                if (!v) {
                    return 0;
                }
                out->headers[out->nheaders].name = name;
                out->headers[out->nheaders].value = v;
                out->nheaders++;
            }
        }
        else {
            return 0;
        }
    }
    return 1;
}

int crowdsec_appsec_parse(const char *buf, apr_size_t len, apr_pool_t *p,
                          crowdsec_appsec_verdict_t *out, const char **err)
{
    yyjson_doc *doc;
    yyjson_val *root, *v;
    const char *action;
    int ok = 0;

    if (!err) {
        return 0;
    }
    *err = "internal";
    if (!out || !p) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    out->rem = CROWDSEC_REM_UNKNOWN;

    doc = parse_bounded(buf, len, p, err);
    if (!doc) {
        return 0;
    }
    root = yyjson_doc_get_root(doc);
    if (!root || !yyjson_is_obj(root)) {
        *err = "verdict root is not an object";
        goto done;
    }

    action = str_field(root, "action");
    if (!action) {
        *err = "no action";
        goto done;
    }
    out->action = apr_pstrdup(p, action);
    out->rem = crowdsec_action_to_rem(action);

    /* http_status is what the browser gets, and it is not the status we were
     * given: a challenge that grants a cookie answers 307 with a Location.
     */
    v = yyjson_obj_get(root, "http_status");
    if (!v || !yyjson_is_int(v)) {
        *err = "no http_status";
        goto done;
    }
    /* Check at full width, then narrow. yyjson_get_int is 32-bit, so a
     * status of 4294967496 would truncate to 200 and pass as valid.
     */
    if (yyjson_is_uint(v)) {
        uint64_t u = yyjson_get_uint(v);

        if (u < 100 || u > 599) {
            *err = "http_status out of range";
            goto done;
        }
        out->http_status = (int) u;
    }
    else {
        int64_t i = yyjson_get_sint(v);

        if (i < 100 || i > 599) {
            *err = "http_status out of range";
            goto done;
        }
        out->http_status = (int) i;
    }

    v = yyjson_obj_get(root, "user_body_content");
    if (v && !yyjson_is_null(v)) {
        const char *b;
        size_t blen;

        if (!yyjson_is_str(v)) {
            *err = "user_body_content is not a string";
            goto done;
        }
        b = yyjson_get_str(v);
        blen = yyjson_get_len(v);
        if (!b) {
            *err = "user_body_content is unreadable";
            goto done;
        }
        /* No NUL check here: this is a response body written by length, not a
         * header, so an embedded NUL is data rather than an injection. The
         * length is what matters.
         */
        out->body = apr_pmemdup(p, b, blen + 1);
        if (!out->body) {
            *err = "cannot copy the body";
            goto done;
        }
        out->body_len = blen;
    }

    if (!parse_cookies(yyjson_obj_get(root, "user_cookies"), p, out)) {
        *err = "user_cookies is unusable";
        goto done;
    }
    if (!parse_headers(yyjson_obj_get(root, "user_headers"), p, out)) {
        *err = "user_headers is unusable";
        goto done;
    }

    ok = 1;
    *err = NULL;

done:
    yyjson_doc_free(doc);

    return ok;
}
