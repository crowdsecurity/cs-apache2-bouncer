/* Pure helpers: no Apache runtime, no globals, no allocation beyond what the
 * caller passes in. Everything here is unit-testable and fuzzable standalone.
 */
#ifndef CROWDSEC_UTIL_H
#define CROWDSEC_UTIL_H

#include "crowdsec_internal.h"

/* Validation, mirroring Apache's own scanners so we accept exactly what the
 * server's parser does. Each returns 1 when every byte of s conforms.
 *
 * name  <- RFC7230 token          (ap_scan_http_token)
 * value <- VCHAR/obs-text/HT/SP   (ap_scan_http_field_content)
 * target<- VCHAR/obs-text         (ap_scan_vchar_obstext)
 *
 * An empty string conforms; callers that need non-empty must check separately.
 */
int crowdsec_hdr_name_ok(const char *s);
int crowdsec_hdr_value_ok(const char *s);
int crowdsec_target_ok(const char *s);

/* X-Crowdsec-Appsec-Http-Version wants exactly two digits. Returns a static
 * string, or NULL when the version has no two-digit spelling and the header
 * must be omitted rather than guessed.
 */
const char *crowdsec_http_version_hdr(int proto_num);

/* "1m", "512k", "1024" -> bytes. Rejects negatives, trailing junk, unknown
 * suffixes, and anything over CROWDSEC_SIZE_CEILING. Returns 1 on success.
 */
int crowdsec_parse_size(const char *s, apr_off_t *out);

/* How much of a chunk still fits under cap. Written to avoid computing
 * used+chunk, which can overflow. Returns 1 while there is room.
 */
int crowdsec_body_take(apr_off_t used, apr_size_t chunk, apr_off_t cap,
                       apr_size_t *take);

/* "10.0.0.0/24", "1.2.3.4", "2001:db8::/32", "::1". A bare address gets the
 * family's full prefix length. Rejects a prefix length outside the family's
 * range, so a malformed entry can never alias another network.
 */
int crowdsec_cidr_parse(const char *s, crowdsec_net_t *out);

/* Copy in, truncated to plen bits, with the host bits zeroed. */
void crowdsec_ip_mask(const crowdsec_net_t *in, int plen, crowdsec_net_t *out);

/* Fixed-width binary socache key. Returns the length written, or 0 if buflen
 * is too small. Never emits a key shorter than 4 bytes, which shmcb rejects.
 */
apr_size_t crowdsec_key_encode(const crowdsec_net_t *n, unsigned char *buf,
                               apr_size_t buflen);

/* allow < unknown < captcha < challenge < ban */
crowdsec_rem_t crowdsec_rem_merge(crowdsec_rem_t a, crowdsec_rem_t b);

/* An AppSec action string, or any admin-defined one, to a remediation.
 * Unrecognised maps to CROWDSEC_REM_UNKNOWN for the caller's fallback.
 */
crowdsec_rem_t crowdsec_action_to_rem(const char *action);

#endif /* CROWDSEC_UTIL_H */
