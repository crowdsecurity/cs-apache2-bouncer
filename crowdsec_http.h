/* The one HTTP client, shared by the LAPI live query, the stream poller and
 * AppSec. Handles are pooled per child process and reused, so a 200ms AppSec
 * budget is not spent on a TCP handshake.
 */
#ifndef CROWDSEC_HTTP_H
#define CROWDSEC_HTTP_H

#include "apr_reslist.h"

#include "crowdsec_internal.h"

/* Why an exchange failed. Anything other than OK means we never saw a usable
 * response and the caller applies its failure action; OK means *status holds
 * what the server said, including 401 and 500.
 */
typedef enum {
    CROWDSEC_HTTP_OK = 0,
    CROWDSEC_HTTP_CONNECT,      /* could not reach the endpoint */
    CROWDSEC_HTTP_TIMEOUT,
    CROWDSEC_HTTP_TOOBIG,       /* blew the sanity ceiling: a bug, not policy */
    CROWDSEC_HTTP_ERROR
} crowdsec_http_err_t;

/* A response body. Grows geometrically from 8 KiB so the common tiny reply
 * costs one block, and stops at ceiling.
 */
typedef struct
{
    apr_pool_t *pool;
    char *data;                 /* always NUL-terminated at len */
    apr_size_t len;
    apr_size_t alloc;
    apr_off_t ceiling;
    int exceeded;
} crowdsec_buf_t;

typedef struct
{
    const char *url;
    const char *unix_socket;    /* AF_UNIX path, or NULL for TCP */
    int post;                   /* 0 = GET, 1 = POST */
    struct curl_slist *headers;
    const char *body;
    apr_size_t body_len;
    apr_interval_time_t connect_timeout;
    apr_interval_time_t timeout;
    /* How long the transfer may make no progress before we give up. Keep it
     * tight on the request path, where a stalled reply must not consume the
     * budget, but generous for a stream pull: a server assembling a large
     * blocklist can legitimately take seconds before the first byte, and a
     * one-second window would abort every pull. 0 disables the check.
     */
    apr_interval_time_t low_speed_time;
    apr_off_t ceiling;
    int ssl_verify;
    const char *ca_file;        /* or NULL for the system store */
} crowdsec_http_req_t;

/* Once per child, before any other call here. Returns APR_SUCCESS or logs
 * nothing - the caller owns the logging.
 */
apr_status_t crowdsec_http_child_init(apr_pool_t *pchild);

/* A pool of nmax reusable handles on pchild. nmax should be the MPM's thread
 * count so acquire() can never block.
 */
apr_status_t crowdsec_http_pool_create(apr_pool_t *pchild, int nmax,
                                       apr_reslist_t **out);

/* One request/response. On CROWDSEC_HTTP_OK, *status is the HTTP status and
 * buf holds the body. errbuf gets curl's message on failure.
 *
 * A transport failure invalidates the handle rather than returning it, so a
 * half-dead keep-alive connection is never handed to the next request.
 */
crowdsec_http_err_t crowdsec_http_exchange(apr_reslist_t *handles,
                                           const crowdsec_http_req_t *req,
                                           apr_pool_t *p,
                                           long *status,
                                           crowdsec_buf_t *buf,
                                           char *errbuf, apr_size_t errlen);

/* Append "Name: value" after checking both halves, so a CR, LF or NUL from a
 * client header can never inject a second header. Returns 0 and leaves *list
 * untouched if the name or value is unacceptable, or on allocation failure.
 *
 * *list must be freed with crowdsec_http_headers_free; registering that with
 * a pool cleanup is the only safe way to use this, because curl_slist_append
 * does not free the list it was handed when it fails.
 */
int crowdsec_http_header_add(apr_pool_t *p, struct curl_slist **list,
                             const char *name, const char *value);

/* Append a literal line, for curl's own "Accept:" style suppressions. */
int crowdsec_http_header_add_raw(struct curl_slist **list, const char *line);

void crowdsec_http_headers_free(struct curl_slist *list);

/* apr_pool_cleanup_register handler; data is a struct curl_slist ** */
apr_status_t crowdsec_http_headers_cleanup(void *data);

const char *crowdsec_http_err_str(crowdsec_http_err_t e);

#endif /* CROWDSEC_HTTP_H */
