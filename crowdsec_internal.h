/* Shared declarations for mod_crowdsec.
 *
 * Include this last: the poison pragma at the bottom would otherwise reject
 * the system headers that legitimately declare the banned functions.
 */
#ifndef CROWDSEC_INTERNAL_H
#define CROWDSEC_INTERNAL_H

#include "crowdsec_version.h"

/* How this bouncer identifies itself to the local API. The bouncer spec asks
 * for "<name>/<version>", and it is what makes cscli bouncers list show a type
 * and version instead of N/A. Not sent to AppSec: that request carries the
 * client's own User-Agent, because the rule engine fingerprints it (JA4H).
 */
#define CROWDSEC_BOUNCER_NAME "crowdsec-apache2-bouncer"
#define CROWDSEC_BOUNCER_UA CROWDSEC_BOUNCER_NAME "/" CROWDSEC_BOUNCER_VERSION

#include "apr.h"
#include "apr_errno.h"
#include "apr_pools.h"
#include "apr_time.h"

/* Remediations, ordered by severity. The merge of a LAPI decision and an
 * AppSec verdict is max(), so the order here is the policy.
 */
typedef enum {
    CROWDSEC_REM_ALLOW = 0,
    CROWDSEC_REM_UNKNOWN,
    CROWDSEC_REM_CAPTCHA,
    CROWDSEC_REM_CHALLENGE,
    CROWDSEC_REM_BAN
} crowdsec_rem_t;

/* A network, or a single host when plen is the family width. */
typedef struct
{
    int family;                 /* 4 or 6 */
    int plen;                   /* 0..32 for v4, 0..128 for v6 */
    unsigned char addr[16];     /* network order; first 4 bytes used for v4 */
} crowdsec_net_t;

/* Longest key crowdsec_key_encode can emit: spread byte + family + plen +
 * 16 address bytes.
 */
#define CROWDSEC_KEY_MAX 19

/* Longest origin string we keep: "lists:" plus a blocklist name. Shared
 * between the decision parser, which composes it, and the metrics table, which
 * interns it, so the two cannot disagree about what fits.
 */
#define CROWDSEC_ORIGIN_LEN 96

/* Refuse a configured size above this. The engine's own default max_body_size
 * is 10 MiB, so anything past 64 MiB is a misconfiguration we reject at
 * startup rather than discover under load.
 */
#define CROWDSEC_SIZE_CEILING (64 * 1024 * 1024)

/* Ten years. A decision longer than this is indistinguishable from forever,
 * and clamping keeps the microsecond arithmetic away from overflow.
 */
#define CROWDSEC_DURATION_MAX (APR_TIME_C(10) * 365 * 24 * 3600 * APR_USEC_PER_SEC)

#endif /* CROWDSEC_INTERNAL_H */
