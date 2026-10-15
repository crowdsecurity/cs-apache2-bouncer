/* Configuration structures, shared between mod_crowdsec.c and the LAPI layer.
 *
 * Separate from crowdsec_internal.h because that one is deliberately apr-only
 * so the unit tests can link it without httpd.
 */
#ifndef CROWDSEC_CONFIG_H
#define CROWDSEC_CONFIG_H

#include "httpd.h"
#include "http_config.h"
#include "ap_expr.h"
#include "ap_socache.h"
#include "util_mutex.h"

#include "apr_hash.h"
#include "apr_reslist.h"
#include "apr_thread_mutex.h"
#include "apr_thread_proc.h"

#include "crowdsec_internal.h"

#define CROWDSEC_CACHE_TIMEOUT_DEFAULT  apr_time_from_sec(60)
#define CROWDSEC_UPDATE_FREQ_DEFAULT    apr_time_from_sec(10)
#define CROWDSEC_CONNECT_TIMEOUT_DEFAULT apr_time_from_sec(1)
#define CROWDSEC_TIMEOUT_DEFAULT        apr_time_from_sec(5)

/* A stream pull can be megabytes on a blocklist, a live query is tiny. Both
 * are sanity ceilings, not policy: hitting one is a bug, so they sit far above
 * anything legitimate. Not configurable, by design.
 */
#define CROWDSEC_CEILING_LIVE    (1 * 1024 * 1024)
#define CROWDSEC_CEILING_STREAM  (256 * 1024 * 1024)

/* Fixed-size, direct-mapped per-child verdict cache. Fixed so there is no
 * eviction policy to get wrong and no allocation after child_init; a collision
 * simply costs a cache miss.
 */
#define CROWDSEC_MEMO_SLOTS 1024
#define CROWDSEC_IP_MAX     46  /* INET6_ADDRSTRLEN without the NUL */

typedef enum
{
    CROWDSEC_MODE_LIVE = 0,
    CROWDSEC_MODE_STREAM
} crowdsec_mode_t;

typedef enum
{
    CROWDSEC_FAIL = 0,
    CROWDSEC_BLOCK,
    CROWDSEC_ALLOW
} crowdsec_fallback_t;

typedef enum
{
    TOO_MANY_REQS = HTTP_TOO_MANY_REQUESTS,
    FORBIDDEN = HTTP_FORBIDDEN,
    INT_ERROR = HTTP_INTERNAL_SERVER_ERROR
} http_code;

typedef struct
{
    char ip[CROWDSEC_IP_MAX + 1];
    apr_time_t expiry;
    crowdsec_rem_t rem;
    unsigned int used:1;
} crowdsec_memo_slot_t;

typedef struct
{
    crowdsec_memo_slot_t *slots;
    apr_thread_mutex_t *mutex;  /* NULL under a non-threaded MPM */
} crowdsec_memo_t;

typedef struct
{
    /* --- configuration --- */
    const char *url;
    const char *key;
    crowdsec_mode_t mode;
    apr_interval_time_t update_frequency;
    apr_interval_time_t connect_timeout;
    apr_interval_time_t timeout;
    apr_interval_time_t cache_timeout;

    /* shared decision cache */
    apr_global_mutex_t *cache_mutex;
    const ap_socache_provider_t *cache_provider;
    ap_socache_instance_t *cache_instance;

    /* --- per-child runtime, set in child_init, never merged --- */
    apr_reslist_t *curl_handles;
    crowdsec_memo_t memo;
    volatile int poller_stop;
    apr_thread_t *poller;
    server_rec *poller_server;
    unsigned int curl_ok:1;

    /* --- explicitly-set bits, for the merge --- */
    unsigned int url_set:1;
    unsigned int key_set:1;
    unsigned int mode_set:1;
    unsigned int update_frequency_set:1;
    unsigned int connect_timeout_set:1;
    unsigned int timeout_set:1;
    unsigned int cache_provider_set:1;
    unsigned int cache_timeout_set:1;
} crowdsec_server_rec;

typedef struct
{
    ap_expr_info_t *location;
    unsigned int enable:1;
    crowdsec_fallback_t fallback:2;
    http_code blockedhttpcode;
    crowdsec_rem_t remediation_fallback;
    unsigned int trust_useragent_ip:1;

    unsigned int enable_set:1;
    unsigned int fallback_set:1;
    unsigned int location_set:1;
    unsigned int blockedhttpcode_set:1;
    unsigned int remediation_fallback_set:1;
    unsigned int trust_useragent_ip_set:1;
} crowdsec_config_rec;

extern module AP_MODULE_DECLARE_DATA crowdsec_module;

/* The address we treat as the client, honouring CrowdsecTrustUseragentIP. */
const char *crowdsec_client_ip(request_rec *r, crowdsec_config_rec *conf);

/* Resolves CrowdsecBlockedHTTPCode's default at the point of use rather than
 * in the config creator, so an unset parent scope is not mistaken for one
 * that set it explicitly.
 */
int crowdsec_blocked_code(crowdsec_config_rec *conf);

#endif /* CROWDSEC_CONFIG_H */
