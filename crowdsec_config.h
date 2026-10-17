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
#include "apr_shm.h"
#include "util_mutex.h"

#include "apr_hash.h"
#include "apr_reslist.h"
#include "apr_thread_mutex.h"
#include "apr_thread_proc.h"

#include "crowdsec_internal.h"

#define CROWDSEC_CACHE_TIMEOUT_DEFAULT  apr_time_from_sec(60)
#define CROWDSEC_LOCAL_CACHE_TIMEOUT_DEFAULT apr_time_from_sec(2)
#define CROWDSEC_UPDATE_FREQ_DEFAULT    apr_time_from_sec(10)
#define CROWDSEC_CONNECT_TIMEOUT_DEFAULT apr_time_from_sec(1)
#define CROWDSEC_TIMEOUT_DEFAULT        apr_time_from_sec(5)

/* A stream pull can be megabytes on a blocklist, a live query is tiny. Both
 * are sanity ceilings, not policy: hitting one is a bug, so they sit far above
 * anything legitimate. Not configurable, by design.
 */
#define CROWDSEC_CEILING_LIVE    (1 * 1024 * 1024)
#define CROWDSEC_CEILING_STREAM  (256 * 1024 * 1024)
/* A challenge page with its inlined detection bundle measures a few hundred
 * kilobytes, so this is two orders of magnitude of headroom.
 */
#define CROWDSEC_CEILING_APPSEC  (32 * 1024 * 1024)

#define CROWDSEC_APPSEC_CONNECT_TIMEOUT_DEFAULT apr_time_from_msec(200)
#define CROWDSEC_APPSEC_TIMEOUT_DEFAULT         apr_time_from_sec(1)
#define CROWDSEC_APPSEC_PATH_DEFAULT            "/"
#define CROWDSEC_APPSEC_INTERNAL_DEFAULT        "/crowdsec-internal/challenge/"
#define CROWDSEC_BODY_LIMIT_DEFAULT             (1024 * 1024)

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

/* What an oversized request body does. drop blocks it; bypass lets it past
 * uninspected, which is a WAF bypass an attacker can trigger at will by
 * padding, hence the default and the warnings.
 */
typedef enum
{
    CROWDSEC_CAP_DROP = 0,
    CROWDSEC_CAP_BYPASS
} crowdsec_cap_t;

typedef enum
{
    CROWDSEC_APPSEC_PASSTHROUGH = 0,
    CROWDSEC_APPSEC_DENY
} crowdsec_appsec_fail_t;

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
    apr_interval_time_t local_cache_timeout;

    /* appsec endpoint */
    const char *appsec_url;
    const char *appsec_socket;  /* set when appsec_url was unix:... */
    const char *appsec_path;
    const char *appsec_key;     /* same bouncer key as the local API */
    apr_interval_time_t appsec_connect_timeout;
    apr_interval_time_t appsec_timeout;
    const char *appsec_internal_path;

    /* shared decision cache. cache_owned marks the one server_rec whose own
     * CrowdsecCache created the instance; vhosts that merely inherit it share
     * the same instance pointer and must not initialise or destroy it again.
     */
    apr_global_mutex_t *cache_mutex;
    const ap_socache_provider_t *cache_provider;
    ap_socache_instance_t *cache_instance;
    unsigned int cache_owned:1;

    /* Lease, primed flag, statistics and prefix bitmaps. Fixed-size control
     * state, so it lives in its own shared region rather than in the socache:
     * that is a cache, free to evict anything, and losing the prefix bitmaps
     * stops range decisions matching while losing the primed flag hands every
     * request to CrowdsecFallback. Guarded by cache_mutex. Layout is private
     * to crowdsec_lapi.c.
     */
    apr_shm_t *meta_shm;
    struct crowdsec_meta *meta;

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
    unsigned int local_cache_timeout_set:1;
    unsigned int appsec_url_set:1;
    unsigned int appsec_path_set:1;
    unsigned int appsec_connect_timeout_set:1;
    unsigned int appsec_timeout_set:1;
    unsigned int appsec_internal_path_set:1;
} crowdsec_server_rec;

typedef struct
{
    ap_expr_info_t *location;
    unsigned int enable:1;
    crowdsec_fallback_t fallback:2;
    http_code blockedhttpcode;
    crowdsec_rem_t remediation_fallback;
    unsigned int trust_useragent_ip:1;

    unsigned int appsec_enable:1;
    unsigned int appsec_always_send:1;
    crowdsec_appsec_fail_t appsec_failure_action:2;
    crowdsec_cap_t appsec_body_limit_action:2;
    apr_off_t appsec_body_limit;

    unsigned int enable_set:1;
    unsigned int fallback_set:1;
    unsigned int location_set:1;
    unsigned int blockedhttpcode_set:1;
    unsigned int remediation_fallback_set:1;
    unsigned int trust_useragent_ip_set:1;
    unsigned int appsec_enable_set:1;
    unsigned int appsec_always_send_set:1;
    unsigned int appsec_failure_action_set:1;
    unsigned int appsec_body_limit_set:1;
    unsigned int appsec_body_limit_action_set:1;
} crowdsec_config_rec;

/* Implemented in crowdsec_config.c. Declared here because the module struct in
 * mod_crowdsec.c is the only consumer, and these travel with the structures
 * above rather than with request handling.
 */
void *create_crowdsec_dir_config(apr_pool_t *p, char *d);
void *merge_crowdsec_dir_config(apr_pool_t *p, void *basev, void *addv);
void *create_crowdsec_server_config(apr_pool_t *p, server_rec *s);
void *merge_crowdsec_server_config(apr_pool_t *p, void *basev, void *addv);

extern const command_rec crowdsec_cmds[];

extern module AP_MODULE_DECLARE_DATA crowdsec_module;

/* The address we treat as the client, honouring CrowdsecTrustUseragentIP. */
const char *crowdsec_client_ip(request_rec *r, crowdsec_config_rec *conf);

/* Resolves CrowdsecBlockedHTTPCode's default at the point of use rather than
 * in the config creator, so an unset parent scope is not mistaken for one
 * that set it explicitly.
 */
int crowdsec_blocked_code(crowdsec_config_rec *conf);

#endif /* CROWDSEC_CONFIG_H */
