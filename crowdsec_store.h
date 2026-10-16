/* The shared control region, and the lock that guards every touch of it.
 *
 * Internal to crowdsec_lapi.c, which owns the memory, and crowdsec_poller.c,
 * which refreshes the lease in it. Not part of the module's interface.
 */
#ifndef CROWDSEC_STORE_H
#define CROWDSEC_STORE_H

#include "crowdsec_config.h"

/* Which prefix lengths currently exist in the store, so a lookup probes two
 * or three candidates instead of all 33 or 129.
 */
typedef struct
{
    unsigned char bits[17];     /* 129 bits, enough for v6; v4 uses 5 */
} plen_set_t;

typedef struct
{
    apr_int64_t holder;         /* pid of the child doing the polling */
    apr_time_t last_run;
} lease_t;

/* Shared control state, about 90 bytes and fixed for the life of the server.
 * It gets its own region rather than a slot in the socache because losing any
 * of it is unrecoverable - no prefix bitmap means range decisions stop
 * matching, no primed flag means CrowdsecFallback decides every request - and
 * force-expiring the oldest entry in a subcache is normal socache operation.
 * Every field is read and written under sconf->cache_mutex.
 */
struct crowdsec_meta
{
    lease_t lease;
    apr_time_t primed_at;
    crowdsec_store_stats_t stats;
    plen_set_t plens4;
    plen_set_t plens6;
};

/* Every socache call needs the mutex: shmcb's retrieve mutates shared state
 * when it discards an expired entry, so even reads are writes. A NULL mutex
 * means no cache is configured and there is nothing to guard.
 */
apr_status_t crowdsec_store_lock(crowdsec_server_rec *sconf);
void crowdsec_store_unlock(crowdsec_server_rec *sconf);

#endif /* CROWDSEC_STORE_H */
