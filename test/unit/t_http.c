/* CLI driver for crowdsec_http, so the bats harness can supply real servers
 * (oversize, slow, closed port) instead of this file reimplementing one.
 *
 *   t_http selftest                       -- header validation, no network
 *   t_http <url> <ceiling> <timeout_ms>   -- one exchange, prints the outcome
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"

#include "crowdsec_http.h"

static int failures;

#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("not ok - %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                           \
    } while (0)

static int selftest(apr_pool_t *p)
{
    struct curl_slist *l = NULL;

    /* the injection cases this guard exists for */
    CHECK(!crowdsec_http_header_add(p, &l, "X\rY", "v"), "CR in name");
    CHECK(!crowdsec_http_header_add(p, &l, "X\nY", "v"), "LF in name");
    CHECK(!crowdsec_http_header_add(p, &l, "X Y", "v"), "SP in name");
    CHECK(!crowdsec_http_header_add(p, &l, "X:Y", "v"), "colon in name");
    CHECK(!crowdsec_http_header_add(p, &l, "X", "a\rb"), "CR in value");
    CHECK(!crowdsec_http_header_add(p, &l, "X", "a\nb"), "LF in value");
    CHECK(!crowdsec_http_header_add(p, &l, "X", "a\r\nEvil: 1"), "CRLF splice");
    CHECK(!crowdsec_http_header_add(p, &l, "", "v"), "empty name");
    CHECK(!crowdsec_http_header_add(p, &l, "X", NULL), "NULL value");
    CHECK(!crowdsec_http_header_add(p, &l, NULL, "v"), "NULL name");
    CHECK(l == NULL, "nothing was appended by any rejected call");

    /* and the cases that must be accepted */
    CHECK(crowdsec_http_header_add(p, &l, "X-Api-Key", "abc123"), "normal");
    CHECK(crowdsec_http_header_add(p, &l, "X", ""), "empty value is legal");
    CHECK(crowdsec_http_header_add(p, &l, "X", "a b\tc"), "SP and HT in value");
    CHECK(crowdsec_http_header_add(p, &l, "X", "caf\xc3\xa9"), "obs-text");
    CHECK(crowdsec_http_header_add_raw(&l, "Accept:"), "suppression line");
    CHECK(l != NULL, "accepted calls built a list");

    crowdsec_http_headers_free(l);

    if (failures) {
        printf("FAILED: %d\n", failures);
        return 1;
    }
    printf("ok - http selftest passed\n");
    return 0;
}

int main(int argc, const char *const *argv)
{
    apr_pool_t *p;
    apr_reslist_t *handles;
    crowdsec_http_req_t req;
    crowdsec_buf_t buf;
    crowdsec_http_err_t err;
    long status = 0;
    char errbuf[256];
    int rv;

    if (apr_app_initialize(&argc, &argv, NULL) != APR_SUCCESS) {
        printf("Bail out! apr init\n");
        return 1;
    }
    apr_pool_create(&p, NULL);

    /* No arguments is the selftest, so `make check` exercises this binary
     * without needing a server; the bats harness passes a URL instead.
     */
    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "selftest"))) {
        rv = selftest(p);
        apr_terminate();
        return rv;
    }
    if (argc != 4) {
        printf("usage: t_http selftest | t_http <url> <ceiling> <timeout_ms>\n");
        apr_terminate();
        return 2;
    }

    if (crowdsec_http_child_init(p) != APR_SUCCESS) {
        printf("err=init-failed\n");
        apr_terminate();
        return 1;
    }
    if (crowdsec_http_pool_create(p, 2, &handles) != APR_SUCCESS) {
        printf("err=pool-failed\n");
        apr_terminate();
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.url = argv[1];
    req.ceiling = (apr_off_t) apr_atoi64(argv[2]);
    req.timeout = apr_time_from_msec(apr_atoi64(argv[3]));
    req.connect_timeout = apr_time_from_msec(200);
    req.low_speed_time = apr_time_from_sec(1);
    req.ssl_verify = 1;

    errbuf[0] = '\0';
    err = crowdsec_http_exchange(handles, &req, p, &status, &buf,
                                 errbuf, sizeof(errbuf));

    printf("err=%s status=%ld len=%" APR_SIZE_T_FMT " msg=%s\n",
           crowdsec_http_err_str(err), status, buf.len, errbuf);

    /* A second exchange on the same pool: proves a released handle is reusable
     * and an invalidated one does not wedge the pool.
     */
    errbuf[0] = '\0';
    err = crowdsec_http_exchange(handles, &req, p, &status, &buf,
                                 errbuf, sizeof(errbuf));
    printf("again=%s status=%ld\n", crowdsec_http_err_str(err), status);

    apr_terminate();
    return 0;
}
