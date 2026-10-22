#include <string.h>

#include "crowdsec_appsec.h"

#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"

#include "apr_buckets.h"
#include "apr_strings.h"

#include "crowdsec_http.h"
#include "crowdsec_util.h"

#include "crowdsec_poison.h"

/* The control headers. The engine strips all of these before the request
 * reaches the rule engine, so forwarding the client's own headers underneath
 * them is safe.
 */
#define H_IP      "X-Crowdsec-Appsec-Ip"
#define H_URI     "X-Crowdsec-Appsec-Uri"
#define H_HOST    "X-Crowdsec-Appsec-Host"
#define H_VERB    "X-Crowdsec-Appsec-Verb"
#define H_KEY     "X-Crowdsec-Appsec-Api-Key"
#define H_UA      "X-Crowdsec-Appsec-User-Agent"
#define H_VERSION "X-Crowdsec-Appsec-Http-Version"
#define H_TXID    "X-Crowdsec-Appsec-Transaction-Id"

#define BODY_READ_CHUNK 8192

static ap_filter_rec_t *replay_filter_handle;

/* Headers libcurl must own, because it is framing this request rather than
 * relaying ours. Content-Length and Host never reach the rule engine anyway -
 * Go moves them out of the header map - and in bypass mode our body length
 * differs from the client's declared one.
 */
static int hop_by_hop(const char *name)
{
    static const char *const owned[] = {
        "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "proxy-connection", "te", "trailer",
        "transfer-encoding", "upgrade", "content-length", "expect", "host",
        NULL
    };
    int i;

    for (i = 0; owned[i]; i++) {
        if (!strcasecmp(name, owned[i])) {
            return 1;
        }
    }
    return 0;
}

int crowdsec_is_challenge_path(const char *uri, const char *prefix)
{
    /* The engine routes on the value of X-Crowdsec-Appsec-Uri, so this is only
     * about deciding to consult it at all, and never letting anything under
     * the prefix reach the origin.
     *
     * The whole prefix is matched rather than the engine's individual asset
     * names: a route added to pkg/appsec/challenge would otherwise go
     * unforwarded until this module caught up, leaving a challenged visitor
     * waiting for an asset forever. The prefix ends in a slash - the
     * directive enforces it - so a sibling directory cannot match.
     */
    if (!uri || !prefix || !*prefix) {
        return 0;
    }
    return !strncmp(uri, prefix, strlen(prefix));
}

/* ------------------------------------------------------------- body input */

/* Reads the body into one contiguous buffer, stopping at cap + 1 bytes.
 *
 * The extra byte is how truncation is detected without ever reading more than
 * can be kept: anything pulled off the wire and discarded would be missing
 * from the body the real handler goes on to read. Everything captured is
 * replayed; only the first cap bytes are offered for inspection.
 *
 * ap_get_brigade is used rather than ap_get_client_block: the latter is
 * documented as single-use and advances r->read_length, which would make the
 * real handler's ap_should_client_block() report no body at all.
 */
static apr_status_t capture_body(request_rec *r, crowdsec_req_rec *st,
                                 apr_off_t cap)
{
    apr_bucket_brigade *bb;
    apr_status_t rv = APR_SUCCESS;
    apr_size_t alloc = 0;
    apr_off_t budget, want;
    int idle = 0;

    st->body = NULL;
    st->body_len = 0;
    st->inspect_len = 0;
    st->truncated = 0;

    if (cap <= 0) {
        return APR_SUCCESS;     /* body forwarding switched off */
    }
    /* One byte past the limit: if it arrives, there was more body than the
     * limit allows, and we know that without having thrown anything away.
     */
    budget = cap + 1;

    /* Seed the buffer from the declared length, so a typical body allocates
     * once instead of doubling through up to eight full copies. A length that
     * lies only costs a wrong initial size: growth and the budget still
     * govern, and HTTP_IN has already validated the header by the time it
     * produces body bytes.
     */
    {
        const char *cl = apr_table_get(r->headers_in, "Content-Length");
        apr_off_t hint;
        char *end;

        if (cl && *cl >= '0' && *cl <= '9'
            && apr_strtoff(&hint, cl, &end, 10) == APR_SUCCESS
            && !*end && hint > 0) {
            if (hint > budget) {
                hint = budget;
            }
            alloc = (apr_size_t) hint + 1;      /* +1 for the NUL we keep */
            st->body = apr_palloc(r->pool, alloc);
            if (!st->body) {
                return APR_ENOMEM;
            }
        }
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    for (;;) {
        apr_bucket *e;
        int saw_eos = 0;

        /* Ask only for what there is still room to keep. Anything handed
         * over has already left the socket, so discarding it would make it
         * missing from the body the real handler reads - which is precisely
         * the bug this avoids.
         */
        want = budget - (apr_off_t) st->body_len;
        if (want > BODY_READ_CHUNK) {
            want = BODY_READ_CHUNK;
        }
        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, want);
        if (rv != APR_SUCCESS) {
            apr_brigade_cleanup(bb);
            st->read_rv = rv;
            return rv;
        }

        for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e)) {
            const char *data;
            apr_size_t len;
            apr_size_t take;

            if (APR_BUCKET_IS_EOS(e)) {
                saw_eos = 1;
                break;
            }
            if (APR_BUCKET_IS_METADATA(e)) {
                continue;
            }
            if (apr_bucket_read(e, &data, &len, APR_BLOCK_READ)
                != APR_SUCCESS) {
                apr_brigade_cleanup(bb);
                return APR_EGENERAL;
            }
            if (!len) {
                continue;
            }

            /* Whatever arrived is kept in full. A filter may return a
             * little more than was asked for, and the buffer growing by one
             * bucket is far better than a handler reading a body with a hole
             * in it.
             */
            take = len;

            if (st->body_len + take + 1 > alloc) {
                apr_size_t grow = alloc ? alloc : BODY_READ_CHUNK;
                char *bigger;

                while (grow < st->body_len + take + 1) {
                    grow *= 2;
                }
                bigger = apr_palloc(r->pool, grow);
                if (!bigger) {
                    apr_brigade_cleanup(bb);
                    return APR_ENOMEM;
                }
                if (st->body_len) {
                    memcpy(bigger, st->body, st->body_len);
                }
                st->body = bigger;
                alloc = grow;
            }
            memcpy(st->body + st->body_len, data, take);
            st->body_len += take;
            st->body[st->body_len] = '\0';
        }
        apr_brigade_cleanup(bb);

        if (saw_eos) {
            goto finished;
        }
        if ((apr_off_t) st->body_len >= budget) {
            goto finished;
        }
        /* apr_bucket_read may legitimately hand back nothing; bail rather than
         * spin if it keeps doing so.
         */
        if (!st->body_len && ++idle > 64) {
            goto finished;
        }
    }

finished:
    if ((apr_off_t) st->body_len > cap) {
        /* The extra byte proves there was more. Everything captured is still
         * replayed; inspection sees only up to the limit.
         */
        st->truncated = 1;
        st->inspect_len = (apr_size_t) cap;
    }
    else {
        st->inspect_len = st->body_len;
    }

    return APR_SUCCESS;
}

/* Hands the captured body back to whoever reads the body next.
 *
 * Registered at AP_FTYPE_PROTOCOL - 1 so it sits immediately in front of
 * HTTP_IN: at AP_FTYPE_RESOURCE it would precede INFLATE and the handler would
 * receive raw compressed bytes.
 */
static apr_status_t replay_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block, apr_off_t readbytes)
{
    crowdsec_req_rec *st = f->ctx;

    /* A subrequest gets a copy of the main request's filter chain, and the
     * body belongs to the main request.
     */
    if (!st || f->r != st->r || f->r->main) {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_EXHAUSTIVE
        && mode != AP_MODE_SPECULATIVE) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (st->replay_off < st->body_len) {
        apr_size_t n = st->body_len - st->replay_off;

        if (mode == AP_MODE_READBYTES && readbytes > 0
            && (apr_off_t) n > readbytes) {
            n = (apr_size_t) readbytes;
        }
        /* A pool bucket rather than a transient one: transient data must be
         * set aside before the next filter call, and the buffer lives in
         * r->pool, which the bucket's cleanup accounts for.
         */
        APR_BRIGADE_INSERT_TAIL(bb,
                                apr_bucket_pool_create(st->body
                                                       + st->replay_off, n,
                                                       f->r->pool,
                                                       f->c->bucket_alloc));
        if (mode != AP_MODE_SPECULATIVE) {
            st->replay_off += n;
        }
        return APR_SUCCESS;
    }

    ap_remove_input_filter(f);

    if (st->truncated) {
        /* In bypass mode the rest of the body is still on the wire, so the
         * handler must keep reading rather than see a premature end.
         */
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));

    return APR_SUCCESS;
}

void crowdsec_appsec_replay(request_rec *r, crowdsec_req_rec *st)
{
    if (!st || st->filter_installed || !st->body_len) {
        return;
    }
    ap_add_input_filter_handle(replay_filter_handle, st, r, r->connection);
    st->filter_installed = 1;
}

crowdsec_req_rec *crowdsec_appsec_inherit_body(request_rec *r)
{
    request_rec *prev;

    /* ap_internal_redirect resets input_filters to proto_input_filters, which
     * drops our ftype-29 filter from the chain, and the original request
     * already drained HTTP_IN when it captured the body. Without re-installing
     * against the captured copy, the redirect target's handler reads nothing -
     * a POST through any mod_rewrite rule silently loses its body.
     */
    for (prev = r->prev; prev; prev = prev->prev) {
        crowdsec_req_rec *old = ap_get_module_config(prev->request_config,
                                                     &crowdsec_module);

        if (old && old->body && old->body_len) {
            crowdsec_req_rec *st = apr_pcalloc(r->pool, sizeof(*st));

            /* Same bytes, fresh offset: the original never reached a handler,
             * so nothing was replayed from it.
             */
            st->r = r;
            st->body = old->body;
            st->body_len = old->body_len;
            st->inspect_len = old->inspect_len;
            st->truncated = old->truncated;
            ap_set_module_config(r->request_config, &crowdsec_module, st);
            crowdsec_appsec_replay(r, st);

            return st;
        }
    }
    return NULL;
}

void crowdsec_appsec_register(apr_pool_t *p)
{
    replay_filter_handle =
        ap_register_input_filter("CROWDSEC_BODY", replay_filter, NULL,
                                 (ap_filter_type) (AP_FTYPE_PROTOCOL - 1));
}

/* -------------------------------------------------------- request forward */

typedef struct
{
    apr_pool_t *pool;
    struct curl_slist **list;
    int ok;
} hdr_ctx_t;

static int forward_one_header(void *vctx, const char *key, const char *value)
{
    hdr_ctx_t *ctx = vctx;

    if (!ctx->ok || !key) {
        return 1;
    }
    if (hop_by_hop(key)) {
        return 1;
    }
    /* A client must not be able to set our control headers. Dropped rather
     * than rejected: the engine strips these names anyway, so dropping costs
     * nothing, and answering 400 would make a usable oracle.
     */
    if (!strncasecmp(key, "X-Crowdsec-Appsec-", 18)) {
        return 1;
    }
    if (!crowdsec_http_header_add(ctx->pool, ctx->list, key, value)) {
        /* Apache will normally have rejected a header containing CR, LF or
         * NUL long before this, so reaching here means either another module
         * synthesised it or the parser changed. Either way, refuse the
         * request rather than silently forward a different header set than
         * the origin will see.
         */
        ctx->ok = 0;
    }
    return 1;
}

static const char *client_host(request_rec *r)
{
    /* The header as sent, not r->hostname, which Apache has lowercased and
     * stripped of brackets: host-based virtual-patching rules compare against
     * what the client wrote.
     */
    const char *h = apr_table_get(r->headers_in, "Host");

    if (h && *h && crowdsec_hdr_value_ok(h)) {
        return h;
    }
    if (r->hostname && *r->hostname) {
        return r->hostname;
    }
    return r->server->server_hostname;
}

static const char *transaction_id(request_rec *r)
{
    /* r->log_id only exists once something has been logged for this request,
     * so it is not a general-purpose identifier. mod_unique_id's value is the
     * next best thing; failing both, the engine generates a uuid.
     */
    if (r->log_id && *r->log_id) {
        return r->log_id;
    }
    return apr_table_get(r->subprocess_env, "UNIQUE_ID");
}

crowdsec_appsec_res_t crowdsec_appsec_check(request_rec *r,
                                            crowdsec_server_rec *sconf,
                                            crowdsec_config_rec *conf,
                                            crowdsec_req_rec *st,
                                            const char *ip)
{
    crowdsec_http_req_t req;
    crowdsec_buf_t buf;
    crowdsec_http_err_t herr;
    hdr_ctx_t hctx;
    struct curl_slist **hdrs;
    const char *target, *host, *ua, *version, *txid, *perr = NULL;
    long status = 0;
    char errbuf[256];
    apr_off_t cap;
    request_rec *orig = r;

    if (!sconf->appsec_url || !sconf->curl_handles) {
        return CROWDSEC_APPSEC_FAIL;
    }

    /* The raw request target, not r->uri: by now Apache has URL-decoded and
     * collapsed that, so sending it would hand the rule engine a normalised
     * path with the query string already gone - and the engine takes its
     * arguments from this header, not from the URL we connect to.
     *
     * And the one the client sent: after an internal redirect r is the
     * rewrite's target, and a rule in front of an application has to see the
     * path it was attacked on, not the file a RewriteRule mapped it to.
     */
    while (orig->prev) {
        orig = orig->prev;
    }
    target = orig->unparsed_uri;
    if (!target || target[0] != '/') {
        /* An absolute-form target cannot be forwarded honestly: trimming it
         * loses the authority, and passing it whole makes the engine's idea of
         * the host disagree with the host header we send.
         */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "crowdsec: request target '%s' cannot be inspected",
                      target ? target : "(none)");
        return CROWDSEC_APPSEC_BADREQ;
    }
    if (!crowdsec_target_ok(target) || !crowdsec_target_ok(ip)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: request target or client address contains "
                      "characters that cannot be sent in a header");
        return CROWDSEC_APPSEC_BADREQ;
    }

    cap = conf->appsec_body_limit_set ? conf->appsec_body_limit
        : CROWDSEC_BODY_LIMIT_DEFAULT;

    if (capture_body(r, st, cap) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, st->read_rv, r,
                      "crowdsec: could not read the request body");
        /* Inherits the right status for the cause: 413 when LimitRequestBody
         * was hit, 408 on a read timeout, 501 for an unimplemented encoding.
         */
        return CROWDSEC_APPSEC_BADREQ;
    }

    if (st->truncated) {
        crowdsec_cap_t act = conf->appsec_body_limit_action_set
            ? conf->appsec_body_limit_action : CROWDSEC_CAP_DROP;

        if (act == CROWDSEC_CAP_DROP) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "crowdsec: request body exceeds "
                          "CrowdsecAppsecBodyLimit (%" APR_OFF_T_FMT
                          "); blocking it", cap);
            return CROWDSEC_APPSEC_DROP;
        }
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "crowdsec: request body exceeds "
                      "CrowdsecAppsecBodyLimit (%" APR_OFF_T_FMT ") and "
                      "CrowdsecAppsecBodyLimitAction is bypass, so it is NOT "
                      "inspected", cap);
        apr_table_setn(r->subprocess_env, "CROWDSEC_APPSEC_STATUS",
                       "body-bypass");
        /* An allow, not a failure: bypass is a deliberate policy choice, so
         * routing it through appsec_failure() would let
         * CrowdsecAppsecFailureAction deny block the very request
         * CrowdsecAppsecBodyLimitAction bypass promises to let through.
         * Merging an allow keeps any ban the local API already found, and the
         * normal allow path replays the captured prefix.
         */
        st->verdict.action = "allow";
        st->verdict.http_status = HTTP_OK;
        st->verdict.rem = CROWDSEC_REM_ALLOW;
        return CROWDSEC_APPSEC_OK;
    }

    /* The holder lives in the pool, not on the stack: this cleanup runs when
     * r->pool is destroyed, after this function has returned, and a registered
     * stack address would by then be a dead frame - handing
     * curl_slist_free_all whatever happened to occupy it.
     */
    hdrs = apr_pcalloc(r->pool, sizeof(*hdrs));
    apr_pool_cleanup_register(r->pool, hdrs, crowdsec_http_headers_cleanup,
                              apr_pool_cleanup_null);

    /* The client's own headers first, then ours on top. */
    hctx.pool = r->pool;
    hctx.list = hdrs;
    hctx.ok = 1;
    apr_table_do(forward_one_header, &hctx, r->headers_in, NULL);
    if (!hctx.ok) {
        return CROWDSEC_APPSEC_BADREQ;
    }

    host = client_host(r);
    ua = apr_table_get(r->headers_in, "User-Agent");
    version = crowdsec_http_version_hdr(r->proto_num);
    txid = transaction_id(r);

    if (!crowdsec_http_header_add(r->pool, hdrs, H_KEY, sconf->appsec_key)
        || !crowdsec_http_header_add(r->pool, hdrs, H_IP, ip)
        || !crowdsec_http_header_add(r->pool, hdrs, H_URI, target)
        || !crowdsec_http_header_add(r->pool, hdrs, H_VERB, r->method)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: could not build the appsec request headers");
        return CROWDSEC_APPSEC_BADREQ;
    }
    /* Without a host the engine gives the rule engine no SERVER_NAME, so
     * host-based rules silently never match.
     */
    if (host) {
        crowdsec_http_header_add(r->pool, hdrs, H_HOST, host);
    }
    /* If no user agent is forwarded the engine deletes the header entirely,
     * which is the right outcome for a client that sent none.
     */
    if (ua && crowdsec_hdr_value_ok(ua)) {
        crowdsec_http_header_add(r->pool, hdrs, H_UA, ua);
    }
    if (version) {
        crowdsec_http_header_add(r->pool, hdrs, H_VERSION, version);
    }
    if (txid && crowdsec_hdr_value_ok(txid)) {
        crowdsec_http_header_add(r->pool, hdrs, H_TXID, txid);
    }

    /* Suppress what libcurl would otherwise add on its own. Each extra header
     * changes the set and count the engine fingerprints, so a request relayed
     * by this module would hash differently from the same request relayed by
     * any other remediation component.
     */
    crowdsec_http_header_add_raw(hdrs, "Accept:");
    crowdsec_http_header_add_raw(hdrs, "Expect:");
    crowdsec_http_header_add_raw(hdrs, "Content-Type:");
    if (!ua) {
        crowdsec_http_header_add_raw(hdrs, "User-Agent:");
    }
    if (!apr_table_get(r->headers_in, "Accept-Encoding")) {
        crowdsec_http_header_add_raw(hdrs, "Accept-Encoding:");
    }

    memset(&req, 0, sizeof(req));
    req.url = apr_pstrcat(r->pool, sconf->appsec_url, sconf->appsec_path,
                          NULL);
    req.unix_socket = sconf->appsec_socket;
    req.headers = *hdrs;
    req.connect_timeout = sconf->appsec_connect_timeout;
    req.timeout = sconf->appsec_timeout;
    req.low_speed_time = apr_time_from_sec(1);
    req.ceiling = CROWDSEC_CEILING_APPSEC;
    req.ssl_verify = 1;

    /* A body means POST, so no intermediary drops it. The verb the engine
     * inspects is the one in the header either way.
     */
    if (st->inspect_len) {
        req.post = 1;
        req.body = st->body;
        req.body_len = st->inspect_len;
    }

    errbuf[0] = '\0';
    herr = crowdsec_http_exchange(sconf->curl_handles, &req, r->pool, &status,
                                  &buf, errbuf, sizeof(errbuf));
    if (herr != CROWDSEC_HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: appsec request to '%s' failed (%s): %s",
                      sconf->appsec_url, crowdsec_http_err_str(herr), errbuf);
        apr_table_setn(r->subprocess_env, "CROWDSEC_APPSEC_STATUS",
                       crowdsec_http_err_str(herr));
        return CROWDSEC_APPSEC_FAIL;
    }

    /* 401 means the key was rejected and 500 that the engine could not
     * process the request; neither is a verdict. A 404 almost always means
     * CrowdsecAppsecPath disagrees with the datasource's path.
     */
    if (status == 401 || status == 403 || status == 404 || status >= 500) {
        if (status != 403) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "crowdsec: appsec returned %ld%s", status,
                          status == 401 ? " (is the API key valid?)"
                          : status == 404
                          ? " (does CrowdsecAppsecPath match the datasource "
                          "path?)" : "");
            apr_table_setn(r->subprocess_env, "CROWDSEC_APPSEC_STATUS",
                           apr_psprintf(r->pool, "http-%ld", status));
            return CROWDSEC_APPSEC_FAIL;
        }
    }

    /* The body is parsed for a 200 as well as a 403: with default_pass_action
     * configured, a 200 can still carry captcha or challenge.
     */
    if (!crowdsec_appsec_parse(buf.data, buf.len, r->pool, &st->verdict,
                               &perr)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "crowdsec: appsec returned %ld with an unusable body: "
                      "%s", status, perr ? perr : "unknown");
        apr_table_setn(r->subprocess_env, "CROWDSEC_APPSEC_STATUS",
                       "parse-fail");
        /* A 403 we cannot read is still a block: the engine decided something,
         * and failing open here would turn a malformed verdict into a bypass.
         */
        if (status == 403) {
            st->verdict.rem = CROWDSEC_REM_BAN;
            return CROWDSEC_APPSEC_OK;
        }
        return CROWDSEC_APPSEC_FAIL;
    }

    apr_table_setn(r->subprocess_env, "CROWDSEC_APPSEC_STATUS",
                   st->verdict.action);

    return CROWDSEC_APPSEC_OK;
}

/* --------------------------------------------------------- serving a page */

int crowdsec_appsec_serve(request_rec *r, const crowdsec_appsec_verdict_t *v)
{
    apr_size_t i;

    if (!v->body || !v->body_len) {
        /* Nothing to serve, so this cannot be honoured. The caller turns it
         * into a block rather than letting the request through.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Each name is cleared from both tables before being written.
     *
     * err_headers_out is not a safe place to put these and headers_out alone
     * is not enough either: the two are merged with apr_table_overlay, a plain
     * concatenation with no de-duplication, so a Content-Security-Policy the
     * engine sends and one the operator set would both go on the wire and the
     * browser would enforce their intersection - a blank challenge page.
     */
    for (i = 0; i < v->nheaders; i++) {
        apr_table_unset(r->headers_out, v->headers[i].name);
        apr_table_unset(r->err_headers_out, v->headers[i].name);
    }
    for (i = 0; i < v->nheaders; i++) {
        /* addn, so a name carrying several values keeps all of them. The
         * unset above already removed whatever was there.
         */
        apr_table_addn(r->headers_out, v->headers[i].name,
                       v->headers[i].value);
    }

    if (v->ncookies) {
        apr_table_unset(r->headers_out, "Set-Cookie");
        apr_table_unset(r->err_headers_out, "Set-Cookie");
        for (i = 0; i < v->ncookies; i++) {
            /* One header per cookie. Comma-joining them would corrupt the
             * attributes, and setn would discard all but the last.
             */
            apr_table_addn(r->headers_out, "Set-Cookie", v->cookies[i]);
        }
    }

    /* Content-Type has to go through this: ap_http_header_filter overwrites
     * whatever a table holds from r->content_type, which is NULL at this
     * phase because the type checker never runs on a short-circuited request.
     */
    ap_set_content_type(r, v->content_type ? v->content_type
                        : "text/html; charset=utf-8");
    ap_set_content_length(r, (apr_off_t) v->body_len);

    /* Never assume 200: granting a challenge cookie answers 307 with a
     * Location.
     */
    r->status = v->http_status;
    r->status_line = NULL;

    if (!r->header_only) {
        const char *p = v->body;
        apr_size_t left = v->body_len;

        /* ap_rwrite takes an int, so a body over 2GB has to be written in
         * pieces. A challenge page is a few hundred kilobytes, but the loop
         * costs nothing and the alternative is a silent truncation.
         */
        while (left) {
            int n = (left > (apr_size_t) INT_MAX) ? INT_MAX : (int) left;

            if (ap_rwrite(p, n, r) < 0) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            p += n;
            left -= (apr_size_t) n;
        }
    }

    /* DONE rather than the status: it tells Apache the response is already
     * complete, so the handler is skipped and ap_die leaves r->status alone.
     * Returning the status instead would route through
     * ap_send_error_response, which resets the output filters and discards
     * everything written above.
     */
    return DONE;
}
