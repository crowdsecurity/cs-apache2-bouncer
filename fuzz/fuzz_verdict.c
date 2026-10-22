/* AppSec verdict parser.
 *
 * The value here is not "it did not crash" - it is the post-conditions. Every
 * string this parser emits ends up in a response header, a Set-Cookie, or a
 * status line, so the properties worth asserting are the ones that stop a
 * malformed verdict from turning into header injection downstream.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "apr_pools.h"
#include "apr_general.h"

#include "crowdsec_verdict.h"
#include "crowdsec_util.h"

/* One pool for the whole run, cleared between inputs: less churn than creating
 * and destroying one per input, and the parser cannot tell the difference.
 *
 * On resident memory, measured rather than assumed: 300k runs of a single
 * 36-byte input peak at 345MB, which is ASan's free-chunk quarantine (default
 * 256MB), not an allocation problem here - capping it with
 * quarantine_size_mb=16 drops the same run to 60MB. So run these with a
 * bounded quarantine, or -rss_limit_mb reports an out-of-memory that says
 * nothing about the parser. See fuzz/README.md.
 */
static int initialised;
static apr_pool_t *pool;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    apr_pool_t *p;
    crowdsec_appsec_verdict_t v;
    const char *err = NULL;
    char *buf;
    apr_size_t i, j;

    if (!initialised) {
        if (apr_initialize() != APR_SUCCESS) {
            return 0;
        }
        if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
            return 0;
        }
        initialised = 1;
    }
    p = pool;

    /* The parser takes an explicit length and must never need a terminator,
     * but copy into pool memory so ASan can see a read past the end.
     */
    buf = apr_palloc(p, size ? size : 1);
    if (size) {
        memcpy(buf, data, size);
    }

    memset(&v, 0, sizeof(v));
    if (crowdsec_appsec_parse(buf, size, p, &v, &err)) {
        /* A browser-facing status, or Apache will emit something absurd. */
        assert(v.http_status >= 100 && v.http_status <= 599);

        /* An action is always recorded, even an unrecognised one: the caller
         * logs it verbatim.
         */
        assert(v.action != NULL);

        assert(v.ncookies <= CROWDSEC_MAX_COOKIES);
        assert(v.nheaders <= CROWDSEC_MAX_HEADERS);

        /* Anything reaching a header has to survive Apache's own field
         * scanner, and its length has to agree with its NUL - a JSON string
         * may encode an interior NUL, which would truncate the value on the
         * wire and leave the rest unchecked.
         */
        for (i = 0; i < v.nheaders; i++) {
            assert(v.headers[i].name != NULL);
            assert(v.headers[i].value != NULL);
            assert(crowdsec_hdr_name_ok(v.headers[i].name));
            assert(crowdsec_hdr_value_ok(v.headers[i].value));
            assert(strlen(v.headers[i].name) <= CROWDSEC_MAX_HEADER_NAME);
            assert(strlen(v.headers[i].value) <= CROWDSEC_MAX_HEADER_VAL);
        }
        for (j = 0; j < v.ncookies; j++) {
            assert(v.cookies[j] != NULL);
            assert(crowdsec_hdr_value_ok(v.cookies[j]));
        }
        if (v.content_type) {
            assert(crowdsec_hdr_value_ok(v.content_type));
        }
        /* body_len is what ap_rwrite is given; a NULL body with a length
         * would walk off into nothing.
         */
        if (v.body_len) {
            assert(v.body != NULL);
        }
    }
    else {
        assert(err != NULL);    /* a failure always says why */
    }

    apr_pool_clear(p);

    return 0;
}
