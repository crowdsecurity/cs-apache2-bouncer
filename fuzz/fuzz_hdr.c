/* The header and target sanitisers.
 *
 * These decide whether a client-supplied header may be forwarded to the rule
 * engine, and whether an engine-supplied one may be written to a response. A
 * byte wrongly accepted here is a header-injection primitive, so the
 * assertions are about the classes themselves rather than about crashing.
 */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crowdsec_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s;
    size_t i;
    int name_ok, value_ok, target_ok;

    /* The sanitisers take NUL-terminated strings, so terminate at the first
     * NUL the way every caller does.
     */
    s = malloc(size + 1);
    if (!s) {
        return 0;
    }
    if (size) {
        memcpy(s, data, size);
    }
    s[size] = '\0';

    name_ok = crowdsec_hdr_name_ok(s);
    value_ok = crowdsec_hdr_value_ok(s);
    target_ok = crowdsec_target_ok(s);

    /* The real invariant: nothing containing CR, LF or NUL may ever be
     * accepted by any of the three. That is what makes splitting a header
     * impossible rather than merely unlikely.
     */
    for (i = 0; i < strlen(s); i++) {
        if (s[i] == '\r' || s[i] == '\n') {
            assert(!name_ok);
            assert(!value_ok);
            assert(!target_ok);
        }
    }

    /* The classes nest: a token is always valid field content, and anything
     * without HT or SP that is valid field content is a valid target.
     */
    if (name_ok) {
        assert(value_ok);
        assert(target_ok);
    }
    if (target_ok) {
        assert(value_ok);
    }
    /* An empty string is accepted by all three; callers reject it separately. */

    free(s);

    return 0;
}
