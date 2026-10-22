#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "apr_strings.h"

#include "crowdsec_http.h"
#include "crowdsec_util.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"

/* curl gained CURL_WRITEFUNC_ERROR in 7.87; before that any short return
 * aborts the transfer just the same.
 */
#ifndef CURL_WRITEFUNC_ERROR
#define CURL_WRITEFUNC_ERROR 0xFFFFFFFF
#endif

#define BUF_INITIAL 8192

static int curl_global_ready;

/* Which option this libcurl accepts for the protocol allowlist. The headers
 * decide what can be compiled, but the library decides what works: built
 * against 7.85+ headers and loaded against an older runtime, PROTOCOLS_STR is
 * rejected and the allowlist would be lost without anyone noticing, because
 * curl_easy_setopt failures are not fatal.
 */
static enum { PROTO_NONE, PROTO_STR, PROTO_BITMASK } curl_proto_mode;

/* curl 8.x marks CURLOPT_PROTOCOLS deprecated and we build with -Werror. */
#ifndef CURL_IGNORE_DEPRECATION
#define CURL_IGNORE_DEPRECATION(statements) statements
#endif

static void probe_proto_mode(void)
{
    CURL *h;
    CURLcode rc = CURLE_UNKNOWN_OPTION;

    curl_proto_mode = PROTO_NONE;
    h = curl_easy_init();
    if (!h) {
        return;
    }

#if LIBCURL_VERSION_NUM >= 0x075500   /* 7.85.0 */
    rc = curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
#endif
    if (rc == CURLE_OK) {
        curl_proto_mode = PROTO_STR;
    }
    else {
        CURL_IGNORE_DEPRECATION(
            rc = curl_easy_setopt(h, CURLOPT_PROTOCOLS,
                                  (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));)
        if (rc == CURLE_OK) {
            curl_proto_mode = PROTO_BITMASK;
        }
    }
    curl_easy_cleanup(h);
}

int crowdsec_http_proto_ok(void)
{
    return curl_proto_mode != PROTO_NONE;
}

static apr_status_t http_global_cleanup(void *data)
{
    (void) data;

    if (curl_global_ready) {
        curl_global_cleanup();
        curl_global_ready = 0;
    }
    return APR_SUCCESS;
}

apr_status_t crowdsec_http_child_init(apr_pool_t *pchild)
{
    /* Must run before any other curl call, and must not run in the parent:
     * it is documented as not thread-safe and it initialises TLS library
     * state that does not survive a fork cleanly. child_init is
     * single-threaded per child, which is exactly what it wants.
     */
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return APR_EGENERAL;
    }
    curl_global_ready = 1;
    apr_pool_cleanup_register(pchild, NULL, http_global_cleanup,
                              apr_pool_cleanup_null);

    /* Must follow curl_global_init, and once per child is enough: the answer
     * depends only on the library we are linked against.
     */
    probe_proto_mode();

    return APR_SUCCESS;
}

static apr_status_t handle_get(void **out, void *params, apr_pool_t *p)
{
    CURL *h;

    (void) params;
    (void) p;

    h = curl_easy_init();

    if (!h) {
        return APR_EGENERAL;
    }
    *out = h;

    return APR_SUCCESS;
}

static apr_status_t handle_free(void *res, void *params, apr_pool_t *p)
{
    (void) params;
    (void) p;

    curl_easy_cleanup((CURL *) res);

    return APR_SUCCESS;
}

apr_status_t crowdsec_http_pool_create(apr_pool_t *pchild, int nmax,
                                       apr_reslist_t **out)
{
    if (nmax < 1) {
        nmax = 1;
    }
    /* smax == hmax so handles are kept rather than churned, and a 60s ttl so
     * an idle keep-alive connection is eventually recycled instead of being
     * reused after the peer has forgotten it. APR clamps all three to 1 when
     * built without threads, which is the right behaviour under prefork.
     */
    return apr_reslist_create(out, 0, nmax, nmax, apr_time_from_sec(60),
                              handle_get, handle_free, NULL, pchild);
}

static void buf_init(crowdsec_buf_t *b, apr_pool_t *p, apr_off_t ceiling)
{
    b->pool = p;
    b->data = NULL;
    b->len = 0;
    b->alloc = 0;
    b->ceiling = ceiling;
    b->exceeded = 0;
}

static size_t buf_write(char *in, size_t size, size_t nmemb, void *ctx)
{
    crowdsec_buf_t *b = ctx;
    size_t add;
    apr_size_t want;

    /* size * nmemb cannot overflow in practice (curl caps it at
     * CURL_MAX_WRITE_SIZE) but the multiply is free to check.
     */
    if (size && nmemb > (size_t) -1 / size) {
        return CURL_WRITEFUNC_ERROR;
    }
    add = size * nmemb;
    if (!add) {
        return 0;
    }

    /* The ceiling is a bug tripwire, not a policy limit: fail the exchange
     * rather than hand a truncated body to a JSON parser.
     */
    if (b->ceiling > 0
        && (apr_off_t) add > b->ceiling - (apr_off_t) b->len) {
        b->exceeded = 1;
        return CURL_WRITEFUNC_ERROR;
    }

    want = b->len + add + 1;    /* +1 for the NUL we always keep */
    if (want > b->alloc) {
        apr_size_t grow = b->alloc ? b->alloc : BUF_INITIAL;
        char *bigger;

        while (grow < want) {
            grow *= 2;
        }
        /* APR pools have no realloc, so this copies. The cost is bounded:
         * total allocation across doublings is under 2x the final size, and
         * it all goes back when the request pool is cleared.
         */
        bigger = apr_palloc(b->pool, grow);
        if (!bigger) {
            return CURL_WRITEFUNC_ERROR;
        }
        if (b->len) {
            memcpy(bigger, b->data, b->len);
        }
        b->data = bigger;
        b->alloc = grow;
    }

    memcpy(b->data + b->len, in, add);
    b->len += add;
    b->data[b->len] = '\0';

    return add;
}

int crowdsec_http_header_add(apr_pool_t *p, struct curl_slist **list,
                             const char *name, const char *value)
{
    struct curl_slist *next;
    char *line;

    if (!p || !list || !name || !value) {
        return 0;
    }
    /* The headline injection guard: a CR, LF or NUL anywhere here would
     * otherwise end this header and start another one of the attacker's
     * choosing. Apache normally rejects such bytes during parsing, but this
     * must not depend on that.
     */
    if (!*name || !crowdsec_hdr_name_ok(name)
        || !crowdsec_hdr_value_ok(value)) {
        return 0;
    }

    /* curl_slist_append copies, so this only has to outlive the call. */
    line = apr_pstrcat(p, name, ": ", value, NULL);
    if (!line) {
        return 0;
    }
    next = curl_slist_append(*list, line);
    if (!next) {
        /* curl_slist_append does not free what it was given on failure, so
         * *list is still live and still owned by the pool cleanup.
         */
        return 0;
    }
    *list = next;

    return 1;
}

int crowdsec_http_header_add_raw(struct curl_slist **list, const char *line)
{
    struct curl_slist *next;

    if (!list || !line || !crowdsec_hdr_value_ok(line)) {
        return 0;
    }
    next = curl_slist_append(*list, line);
    if (!next) {
        return 0;
    }
    *list = next;

    return 1;
}

apr_status_t crowdsec_http_headers_cleanup(void *data)
{
    struct curl_slist **list = data;

    if (list && *list) {
        curl_slist_free_all(*list);
        *list = NULL;
    }
    return APR_SUCCESS;
}

const char *crowdsec_http_err_str(crowdsec_http_err_t e)
{
    switch (e) {
    case CROWDSEC_HTTP_OK:
        return "ok";
    case CROWDSEC_HTTP_CONNECT:
        return "connect-fail";
    case CROWDSEC_HTTP_TIMEOUT:
        return "timeout";
    case CROWDSEC_HTTP_TOOBIG:
        return "oversize";
    default:
        return "error";
    }
}

/* curl calls this every few hundred milliseconds during a transfer. The
 * caller's hook returns non-zero to abort, which curl reports as an error.
 */
static int xferinfo(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
    const crowdsec_http_req_t *req = clientp;

    (void) dltotal;
    (void) dlnow;
    (void) ultotal;
    (void) ulnow;

    return req->progress ? req->progress(req->progress_data) : 0;
}

static long ms_of(apr_interval_time_t t)
{
    long ms;

    if (t <= 0) {
        return 0;               /* curl reads 0 as "no limit" */
    }
    /* Round a positive budget up to 1ms rather than down to 0, which curl
     * would read as "no limit" and turn a tight timeout into none at all.
     */
    ms = (long) apr_time_as_msec(t);

    return ms > 0 ? ms : 1;
}

/* Confines us to http and https, so a mistyped CrowdsecURL cannot turn a
 * decision lookup into a file:// or scp:// fetch.
 */
static void apply_proto_allowlist(CURL *h)
{
#if LIBCURL_VERSION_NUM >= 0x075500   /* 7.85.0 */
    if (curl_proto_mode == PROTO_STR) {
        curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
        return;
    }
#endif
    if (curl_proto_mode == PROTO_BITMASK) {
        CURL_IGNORE_DEPRECATION(
            curl_easy_setopt(h, CURLOPT_PROTOCOLS,
                             (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));)
    }
    /* PROTO_NONE: nothing this libcurl takes; child init logged it once. */
}

static void apply_hardening(CURL *h)
{
    /* Without this, an http_proxy in the server's environment silently routes
     * our decision lookups and the WAF's view of request bodies through a
     * third party.
     */
    curl_easy_setopt(h, CURLOPT_PROXY, "");
    curl_easy_setopt(h, CURLOPT_NOPROXY, "*");

    /* A redirect from the engine is never meaningful and would let a
     * misconfigured endpoint point us anywhere.
     */
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);

    /* curl's fallback DNS timeout uses alarm(), which is not thread-safe and
     * would land in whichever thread happens to be running under a threaded
     * MPM.
     */
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);

    /* We talk to a local engine; h2 negotiation buys nothing and h2c upgrade
     * handling is one more thing to get wrong.
     */
    curl_easy_setopt(h, CURLOPT_HTTP_VERSION,
                     (long) CURL_HTTP_VERSION_1_1);

    apply_proto_allowlist(h);
}

crowdsec_http_err_t crowdsec_http_exchange(apr_reslist_t *handles,
                                           const crowdsec_http_req_t *req,
                                           apr_pool_t *p,
                                           long *status,
                                           crowdsec_buf_t *buf,
                                           char *errbuf, apr_size_t errlen)
{
    CURL *h = NULL;
    CURLcode rc;
    char curlerr[CURL_ERROR_SIZE];
    crowdsec_http_err_t err = CROWDSEC_HTTP_OK;

    if (!handles || !req || !req->url || !status || !buf) {
        return CROWDSEC_HTTP_ERROR;
    }
    *status = 0;
    buf_init(buf, p, req->ceiling);
    curlerr[0] = '\0';

    if (apr_reslist_acquire(handles, (void **) &h) != APR_SUCCESS || !h) {
        if (errbuf && errlen) {
            apr_cpystrn(errbuf, "no curl handle available", errlen);
        }
        return CROWDSEC_HTTP_ERROR;
    }

    /* Resets options but deliberately keeps the connection cache, DNS cache
     * and session IDs - which is what makes handle reuse worth anything.
     */
    curl_easy_reset(h);
    apply_hardening(h);

    curl_easy_setopt(h, CURLOPT_URL, req->url);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerr);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, buf_write);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, buf);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS,
                     ms_of(req->connect_timeout));
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, ms_of(req->timeout));

    /* A response that trickles one byte at a time would otherwise spend the
     * entire budget without ever timing out. The window is the caller's
     * choice: see low_speed_time.
     */
    /* Always assign: a pooled handle keeps the previous caller's value, and
     * leaking our own User-Agent into an AppSec request would perturb the
     * JA4H fingerprint the rule engine computes. NULL sends none.
     */
    curl_easy_setopt(h, CURLOPT_USERAGENT, req->user_agent);

    if (req->progress) {
        curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, xferinfo);
        curl_easy_setopt(h, CURLOPT_XFERINFODATA, (void *) req);
        curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
    }
    else {
        curl_easy_setopt(h, CURLOPT_NOPROGRESS, 1L);
    }
    if (req->low_speed_time > 0) {
        curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 1L);
        curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME,
                         (long) apr_time_sec(req->low_speed_time));
    }

    if (req->unix_socket) {
        curl_easy_setopt(h, CURLOPT_UNIX_SOCKET_PATH, req->unix_socket);
    }
    if (req->headers) {
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, req->headers);
    }
    if (req->post) {
        curl_easy_setopt(h, CURLOPT_POST, 1L);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, req->body ? req->body : "");
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t) req->body_len);
    }
    else {
        curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
    }

    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER,
                     req->ssl_verify ? 1L : 0L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST,
                     req->ssl_verify ? 2L : 0L);
    if (req->ca_file) {
        curl_easy_setopt(h, CURLOPT_CAINFO, req->ca_file);
    }

    rc = curl_easy_perform(h);

    if (rc == CURLE_OK) {
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, status);
    }
    else if (buf->exceeded) {
        err = CROWDSEC_HTTP_TOOBIG;
    }
    else {
        switch (rc) {
        case CURLE_OPERATION_TIMEDOUT:
            err = CROWDSEC_HTTP_TIMEOUT;
            break;
        case CURLE_COULDNT_CONNECT:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
            err = CROWDSEC_HTTP_CONNECT;
            break;
        default:
            err = CROWDSEC_HTTP_ERROR;
            break;
        }
    }

    if (errbuf && errlen) {
        apr_cpystrn(errbuf, curlerr[0] ? curlerr : curl_easy_strerror(rc),
                    errlen);
    }
    /* CURLOPT_ERRORBUFFER keeps a pointer to a stack buffer that is about to
     * go away, so clear it before the handle outlives this frame.
     */
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, NULL);

    if (err == CROWDSEC_HTTP_OK) {
        apr_reslist_release(handles, h);
    }
    else {
        /* Never hand a half-dead connection to the next request. */
        apr_reslist_invalidate(handles, h);
    }

    return err;
}
