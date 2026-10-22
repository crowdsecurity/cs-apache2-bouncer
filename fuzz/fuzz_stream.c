/* Decision-stream parser.
 *
 * Every decision this emits becomes a fixed-width binary cache key, so the
 * properties worth asserting are about the key rather than about surviving
 * the parse: a value that produced a key for the wrong network would block,
 * or fail to block, an address nobody decided on.
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

typedef struct
{
    apr_size_t calls;
} ctx_t;

static apr_status_t check_one(void *vctx, int added,
                              const crowdsec_decision_t *d)
{
    ctx_t *ctx = vctx;
    unsigned char key[CROWDSEC_KEY_MAX];
    apr_size_t len;
    int width, bit;

    assert(d != NULL);
    ctx->calls++;

    /* Only the two families the key encoding knows how to size. */
    assert(d->net.family == 4 || d->net.family == 6);
    width = (d->net.family == 6) ? 16 : 4;
    assert(d->net.plen >= 0 && d->net.plen <= width * 8);

    /* The contract is that the address arrives masked to its prefix. If any
     * host bit survived, two different CIDRs could encode to the same key,
     * or one network's key could be attributed to another.
     */
    for (bit = d->net.plen; bit < width * 8; bit++) {
        assert(((d->net.addr[bit / 8] >> (7 - (bit % 8))) & 1) == 0);
    }
    /* Bytes past the family's width are never meaningful. */
    for (bit = width; bit < 16; bit++) {
        assert(d->net.addr[bit] == 0);
    }

    /* An expired addition is dropped by the parser rather than handed out.
     * Removals are exempt on purpose: LAPI sends the already-elapsed duration
     * for those, so the parser leaves it at zero and never reads it.
     */
    if (added) {
        assert(d->duration > 0);
    }

    /* And the whole point: it has to encode to a well-formed key. */
    len = crowdsec_key_encode(&d->net, key, sizeof(key));
    assert(len == (apr_size_t) (3 + width));
    assert(key[1] == (unsigned char) d->net.family);
    assert(key[2] == (unsigned char) d->net.plen);

    return APR_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    apr_pool_t *p;
    crowdsec_decision_stats_t stats;
    ctx_t ctx;
    const char *err = NULL;
    char *buf;

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

    buf = apr_palloc(p, size ? size : 1);
    if (size) {
        memcpy(buf, data, size);
    }

    memset(&stats, 0, sizeof(stats));
    memset(&ctx, 0, sizeof(ctx));

    if (crowdsec_stream_parse(buf, size, p, check_one, &ctx, &stats, &err)) {
        /* The callback runs once per applied decision, in either direction. */
        assert(ctx.calls == stats.added + stats.removed);
        assert(stats.added + stats.removed <= CROWDSEC_MAX_DECISIONS);
    }
    else {
        assert(err != NULL);
    }

    apr_pool_clear(p);

    return 0;
}
