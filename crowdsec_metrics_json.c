/* The usage-metrics payload, built by hand, and the os-release parser.
 *
 * By hand because yyjson is compiled with YYJSON_DISABLE_WRITER: this module
 * reads far more JSON than it writes, and one fixed-shape document is not
 * worth linking a serialiser - or widening the vendored library's footprint -
 * for. The shape is asserted in test/unit/t_metrics.c instead.
 */
#include <string.h>

#include "apr_strings.h"

#include "crowdsec_metrics_json.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"

/* ------------------------------------------------------------ the buffer */

/* A pool-backed string that grows geometrically. The payload is bounded by the
 * counter table - a few hundred items at most - so this never has to be
 * clever; it exists so the builder is not quadratic in apr_pstrcat.
 *
 * Allocation failure is recorded rather than checked at every append, so the
 * emit code below reads as straight-line formatting.
 */
typedef struct
{
    apr_pool_t *p;
    char *data;
    apr_size_t len;
    apr_size_t alloc;
    int failed;
} jbuf_t;

static void jb_need(jbuf_t *b, apr_size_t extra)
{
    apr_size_t want;
    char *bigger;

    if (b->failed) {
        return;
    }
    /* The +1 keeps room for the terminator without a special case at the end. */
    if (b->len + extra + 1 <= b->alloc) {
        return;
    }
    /* Overflow here would mean a payload measured in exabytes, which the fixed
     * table makes impossible - but the check costs nothing and the alternative
     * is a wrapped size and a heap overflow.
     */
    if (extra > APR_SIZE_MAX / 2 - b->len - 1) {
        b->failed = 1;
        return;
    }
    want = b->alloc ? b->alloc : 2048;
    while (want < b->len + extra + 1) {
        want *= 2;
    }
    bigger = apr_palloc(b->p, want);
    if (!bigger) {
        b->failed = 1;
        return;
    }
    if (b->len) {
        memcpy(bigger, b->data, b->len);
    }
    b->data = bigger;
    b->alloc = want;
}

static void jb_raw(jbuf_t *b, const char *s, apr_size_t n)
{
    jb_need(b, n);
    if (b->failed) {
        return;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
}

static void jb_lit(jbuf_t *b, const char *s)
{
    jb_raw(b, s, strlen(s));
}

static void jb_int(jbuf_t *b, apr_int64_t v)
{
    char tmp[32];

    /* apr_snprintf, not sprintf: the latter is poisoned, and this is the one
     * place the module formats a number.
     */
    apr_snprintf(tmp, sizeof(tmp), "%" APR_INT64_T_FMT, v);
    jb_lit(b, tmp);
}

/* A JSON string body, without the surrounding quotes.
 *
 * Origins arrive from the local API, so they are not ours to trust: a name
 * carrying a quote or a control byte would otherwise end the string early and
 * let the rest of it be read as structure. Bytes at or above 0x80 pass through
 * untouched, which is what keeps a UTF-8 blocklist name intact.
 */
static void jb_escaped(jbuf_t *b, const char *s)
{
    const unsigned char *u = (const unsigned char *) s;
    apr_size_t i;

    for (i = 0; u[i]; i++) {
        switch (u[i]) {
        case '"':
            jb_lit(b, "\\\"");
            break;
        case '\\':
            jb_lit(b, "\\\\");
            break;
        case '\n':
            jb_lit(b, "\\n");
            break;
        case '\r':
            jb_lit(b, "\\r");
            break;
        case '\t':
            jb_lit(b, "\\t");
            break;
        default:
            if (u[i] < 0x20) {
                char esc[7];

                apr_snprintf(esc, sizeof(esc), "\\u%04x", (unsigned int) u[i]);
                jb_lit(b, esc);
            }
            else {
                jb_raw(b, (const char *) &u[i], 1);
            }
            break;
        }
    }
}

/* ------------------------------------------------------------- the items */

static const char *ipt_label(int ipt)
{
    return ipt == CROWDSEC_IPT_V6 ? "ipv6" : "ipv4";
}

/* One metrics item. origin NULL omits the label, which is what processed
 * wants: neither reference bouncer attributes a processed request to an
 * origin, because at the point it is counted there is not yet a decision to
 * attribute it to.
 */
static void jb_item(jbuf_t *b, int *first, const char *name,
                    apr_int64_t value, const char *unit, int ipt,
                    const char *origin)
{
    if (!*first) {
        jb_lit(b, ",");
    }
    *first = 0;

    jb_lit(b, "{\"name\":\"");
    jb_lit(b, name);
    jb_lit(b, "\",\"value\":");
    jb_int(b, value);
    jb_lit(b, ",\"unit\":\"");
    jb_lit(b, unit);
    jb_lit(b, "\",\"labels\":{\"ip_type\":\"");
    jb_lit(b, ipt_label(ipt));
    if (origin) {
        jb_lit(b, "\",\"origin\":\"");
        jb_escaped(b, origin);
    }
    jb_lit(b, "\"}}");
}

char *crowdsec_metrics_payload(apr_pool_t *p,
                               const crowdsec_metrics_static_t *st,
                               const crowdsec_metrics_snap_t *snap,
                               apr_time_t now, apr_interval_time_t window)
{
    jbuf_t b;
    apr_uint32_t o;
    int ipt, first = 1;
    apr_uint32_t norigins;

    if (!p || !st || !snap) {
        return NULL;
    }
    memset(&b, 0, sizeof(b));
    b.p = p;

    norigins = snap->norigins;
    if (norigins > CROWDSEC_ORIGIN_MAX) {
        norigins = CROWDSEC_ORIGIN_MAX;
    }

    /* name is deliberately absent: the local API resolves the component's name
     * from the API key the request authenticated with, and sending a second
     * opinion would only let the two disagree.
     */
    jb_lit(&b, "{\"remediation_components\":[{\"type\":\"");
    jb_lit(&b, CROWDSEC_BOUNCER_NAME);
    jb_lit(&b, "\",\"version\":\"");
    jb_lit(&b, CROWDSEC_BOUNCER_VERSION);
    jb_lit(&b, "\",\"utc_startup_timestamp\":");
    jb_int(&b, apr_time_sec(st->startup));
    jb_lit(&b, ",\"os\":{\"name\":\"");
    jb_escaped(&b, st->os_name ? st->os_name : "Linux");
    jb_lit(&b, "\",\"version\":\"");
    jb_escaped(&b, st->os_version ? st->os_version : "unknown");
    /* feature_flags must serialise as an array. The local API types it as
     * []string and answers 400 for an object, which is how the whole payload
     * gets silently dropped - see lua-cs-bouncer issue #134.
     */
    jb_lit(&b, "\"},\"feature_flags\":[],\"metrics\":[{\"meta\":{"
           "\"utc_now_timestamp\":");
    jb_int(&b, apr_time_sec(now));
    jb_lit(&b, ",\"window_size_seconds\":");
    jb_int(&b, apr_time_sec(window));
    jb_lit(&b, "},\"items\":[");

    /* processed is emitted even at zero, for both families. It is the one
     * number that says "this component is alive and saw no traffic", which an
     * absent item cannot.
     */
    for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
        jb_item(&b, &first, "processed", snap->processed[ipt], "request", ipt,
                NULL);
    }

    /* dropped is a counter delta, so an absent item and a zero one mean the
     * same thing; emitting zeroes for every origin would be pure noise.
     */
    for (o = 0; o < norigins; o++) {
        for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
            if (snap->dropped[o][ipt]) {
                jb_item(&b, &first, "dropped", snap->dropped[o][ipt],
                        "request", ipt, snap->origins[o]);
            }
        }
    }

    /* active_decisions is a gauge, where zero is a real reading: it is how a
     * blocklist that has been unsubscribed reports that its decisions are
     * gone. Hence the sticky flag rather than a non-zero test.
     */
    if (snap->have_active) {
        for (o = 0; o < norigins; o++) {
            for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
                if (snap->active_seen[o][ipt]) {
                    jb_item(&b, &first, "active_decisions",
                            snap->active[o][ipt], "ip", ipt,
                            snap->origins[o]);
                }
            }
        }
    }

    /* log_processors is explicit rather than omitted, matching what every
     * other component sends.
     */
    jb_lit(&b, "]}]}],\"log_processors\":null}");

    if (b.failed) {
        return NULL;
    }
    b.data[b.len] = '\0';

    return b.data;
}

/* -------------------------------------------------------- os-release */

/* The longest os.name or os.version the local API accepts. */
#define OS_FIELD_MAX 255

/* One KEY=VALUE line, if it is the key we want.
 *
 * os-release is shell syntax, so a value may be quoted; the quoting that
 * occurs in practice is a plain surrounding pair, which is all this undoes. A
 * value with embedded shell escapes would be reported with them intact, which
 * is cosmetically wrong and harmless - it is a label, not a path.
 */
static const char *line_value(const char *line, apr_size_t len,
                              const char *key, apr_pool_t *p)
{
    apr_size_t klen = strlen(key);
    apr_size_t i = 0;

    /* Leading whitespace, then the key, then '='. */
    while (i < len && (line[i] == ' ' || line[i] == '\t')) {
        i++;
    }
    if (len - i < klen + 1 || memcmp(line + i, key, klen)
        || line[i + klen] != '=') {
        return NULL;
    }
    i += klen + 1;

    if (i < len && (line[i] == '"' || line[i] == '\'')) {
        char q = line[i];

        i++;
        if (len > i && line[len - 1] == q) {
            len--;
        }
    }
    if (len <= i) {
        return NULL;            /* present but empty: treat as absent */
    }
    if (len - i > OS_FIELD_MAX) {
        len = i + OS_FIELD_MAX;
    }
    return apr_pstrmemdup(p, line + i, len - i);
}

void crowdsec_os_release_parse(const char *buf, apr_size_t len, apr_pool_t *p,
                               const char **name, const char **version)
{
    apr_size_t at = 0;

    if (!name || !version || !p) {
        return;
    }
    /* Placeholders, not NULL: the local API requires both fields to be
     * non-empty, so failing to identify the host must not fail the payload.
     */
    *name = "Linux";
    *version = "unknown";

    if (!buf || !len) {
        return;
    }

    while (at < len) {
        const char *nl = memchr(buf + at, '\n', len - at);
        apr_size_t llen = nl ? (apr_size_t) (nl - (buf + at)) : len - at;
        const char *v;

        /* A file written on, or copied through, Windows. */
        if (llen && buf[at + llen - 1] == '\r') {
            llen--;
        }
        if (llen && buf[at] != '#') {
            /* PRETTY_NAME is not used: NAME plus VERSION_ID is what every
             * other component reports, and mixing the two would make the same
             * host look like two in the Console.
             */
            if ((v = line_value(buf + at, llen, "NAME", p)) != NULL) {
                *name = v;
            }
            else if ((v = line_value(buf + at, llen, "VERSION_ID", p))
                     != NULL) {
                *version = v;
            }
        }
        if (!nl) {
            break;
        }
        at = (apr_size_t) (nl - buf) + 1;
    }
}
