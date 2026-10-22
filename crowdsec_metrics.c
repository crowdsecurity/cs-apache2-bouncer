/* Usage metrics: the shared counters, and the thread that reports them.
 *
 * Apache is multi-process, so the counters cannot live in a registry the way
 * the Go and Lua bouncers' do - they go in shared memory, and the request path
 * reaches them with an atomic add rather than a lock. Taking the global mutex
 * per request would undo the whole point of the per-child memo.
 */
#include <string.h>
#include <unistd.h>

#include "crowdsec_metrics.h"

#include "http_log.h"
#include "http_protocol.h"

#include "apr_atomic.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"

#include "crowdsec_http.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"

/* AP_DECLARE_MODULE tags mod_crowdsec.c only; without this, lines logged
 * here show as [:level] and "LogLevel crowdsec:..." does not reach them.
 */
APLOG_USE_MODULE(crowdsec);

static const char *const metrics_mutex_type = "crowdsec-metrics";

/* How long a leader may be silent before another child takes over. Fixed
 * rather than derived from the push interval on purpose: at the default 15
 * minute interval, two intervals of grace would mean half an hour of no
 * metrics after a child is killed.
 */
#define LEASE_STALE     apr_time_from_sec(120)
#define LEASE_CLAIM_EVERY apr_time_from_sec(30)

/* Long enough that a transient outage does not cost a window, short enough
 * that a permanently misconfigured endpoint cannot accumulate forever. A
 * window this old is worthless anyway.
 */
#define WINDOW_CEILING  apr_time_from_sec(24 * 3600)

/* The reply to a metrics push is a status and nothing we read. */
#define CEILING_METRICS (64 * 1024)

typedef struct
{
    apr_int64_t holder;         /* pid of the child doing the pushing */
    apr_time_t last_run;
} metrics_lease_t;

/* The shared region. Fixed for the life of the server, about two pages.
 *
 * The counters are touched with apr_atomic_* and no lock. The mutex guards
 * only origin interning and the window bookkeeping, both of which are rare.
 */
struct crowdsec_metrics_shm
{
    metrics_lease_t lease;
    apr_time_t startup;         /* set in post_config, so children agree */
    apr_time_t window_start;
    apr_time_t last_push;
    apr_uint32_t pushes;
    apr_uint32_t failures;
    long last_status;

    /* Written once per origin under the mutex, then published by raising
     * norigins. A reader takes norigins atomically and scans below it, so it
     * never looks at a slot that is still being filled in.
     */
    apr_uint32_t norigins;
    apr_uint32_t origin_overflow;
    char origins[CROWDSEC_ORIGIN_MAX][CROWDSEC_ORIGIN_LEN];

    apr_uint32_t resync_wanted;

    apr_uint32_t processed[CROWDSEC_IPT_MAX];
    apr_uint32_t dropped[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
    apr_uint32_t active[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
    /* Sticky flags, written without atomics: a single byte going 0 -> 1 and
     * never back needs none, and a lost write only delays the first explicit
     * zero for that origin by one pull.
     */
    unsigned char active_seen[CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX];
};

/* The OS fields, read once per child before any thread starts. The startup
 * timestamp is not here: it comes from the region, so every child reports the
 * same one and a leader change does not move it.
 */
static crowdsec_metrics_static_t os_info;

/* ------------------------------------------------------------- the lock */

static apr_status_t metrics_lock(crowdsec_server_rec *sconf)
{
    if (!sconf->metrics_mutex) {
        return APR_SUCCESS;
    }
    return apr_global_mutex_lock(sconf->metrics_mutex);
}

static void metrics_unlock(crowdsec_server_rec *sconf)
{
    if (sconf->metrics_mutex) {
        apr_global_mutex_unlock(sconf->metrics_mutex);
    }
}

/* --------------------------------------------------------- the counters */

static int ipt_ok(int ipt)
{
    return ipt >= 0 && ipt < CROWDSEC_IPT_MAX;
}

/* An id is only usable once the slot it names has been published, so a value
 * from a stale decision value or memo entry cannot read another origin's name.
 */
static int origin_ok(struct crowdsec_metrics_shm *m, unsigned char o)
{
    return o < CROWDSEC_ORIGIN_MAX && o < apr_atomic_read32(&m->norigins);
}

unsigned char crowdsec_metrics_origin_id(crowdsec_server_rec *sconf,
                                         const char *origin)
{
    struct crowdsec_metrics_shm *m = sconf ? sconf->metrics : NULL;
    apr_uint32_t n, i;

    if (!m || !origin || !*origin) {
        return CROWDSEC_ORIGIN_UNKNOWN;
    }

    /* The hit path, which is every sighting but the first: no lock, and no
     * write, so request handling never serialises on this.
     *
     * A slot below norigins has had its name written before the count that
     * exposes it, so this cannot read a half-filled name. Even if it somehow
     * did, the slot starts zeroed and is written once, so the worst case is a
     * failed match - which falls through to the locked path below and gets the
     * right answer there.
     */
    n = apr_atomic_read32(&m->norigins);
    if (n > CROWDSEC_ORIGIN_MAX) {
        n = CROWDSEC_ORIGIN_MAX;
    }
    for (i = 0; i < n; i++) {
        if (!strcmp(m->origins[i], origin)) {
            return (unsigned char) i;
        }
    }

    if (metrics_lock(sconf) != APR_SUCCESS) {
        return CROWDSEC_ORIGIN_UNKNOWN;
    }
    /* Re-scan: another child may have interned it since the read above. */
    n = m->norigins;
    if (n > CROWDSEC_ORIGIN_MAX) {
        n = CROWDSEC_ORIGIN_MAX;
    }
    for (i = 0; i < n; i++) {
        if (!strcmp(m->origins[i], origin)) {
            metrics_unlock(sconf);
            return (unsigned char) i;
        }
    }
    if (n >= CROWDSEC_ORIGIN_MAX) {
        /* Attributed to the unknown slot rather than to whoever happens to
         * hold slot n % MAX, and counted so the status handler can say so.
         */
        m->origin_overflow++;
        metrics_unlock(sconf);
        return CROWDSEC_ORIGIN_UNKNOWN;
    }
    apr_cpystrn(m->origins[n], origin, CROWDSEC_ORIGIN_LEN);
    /* Publish last. apr_atomic_set32 is a barrier on every implementation,
     * which is what keeps the lock-free scan above honest.
     */
    apr_atomic_set32(&m->norigins, n + 1);
    metrics_unlock(sconf);

    return (unsigned char) n;
}

void crowdsec_metrics_processed(crowdsec_server_rec *sconf, int ipt)
{
    if (!sconf || !sconf->metrics || !ipt_ok(ipt)) {
        return;
    }
    apr_atomic_inc32(&sconf->metrics->processed[ipt]);
}

void crowdsec_metrics_dropped(crowdsec_server_rec *sconf, int ipt,
                              unsigned char origin)
{
    struct crowdsec_metrics_shm *m = sconf ? sconf->metrics : NULL;

    if (!m || !ipt_ok(ipt)) {
        return;
    }
    if (!origin_ok(m, origin)) {
        origin = CROWDSEC_ORIGIN_UNKNOWN;
    }
    apr_atomic_inc32(&m->dropped[origin][ipt]);
}

void crowdsec_metrics_active_add(crowdsec_server_rec *sconf, int ipt,
                                 unsigned char origin, int delta)
{
    struct crowdsec_metrics_shm *m = sconf ? sconf->metrics : NULL;

    if (!m || !ipt_ok(ipt) || !delta) {
        return;
    }
    if (!origin_ok(m, origin)) {
        origin = CROWDSEC_ORIGIN_UNKNOWN;
    }
    if (delta > 0) {
        apr_atomic_inc32(&m->active[origin][ipt]);
        m->active_seen[origin][ipt] = 1;
        return;
    }
    /* Floored rather than wrapped. A decrement with no matching increment
     * should not be possible - removals only decrement what a retrieve just
     * found - but a gauge of four billion would be a far worse way to find out
     * that it is.
     */
    for (;;) {
        apr_uint32_t cur = apr_atomic_read32(&m->active[origin][ipt]);

        if (!cur) {
            return;
        }
        if (apr_atomic_cas32(&m->active[origin][ipt], cur - 1, cur) == cur) {
            return;
        }
    }
}

void crowdsec_metrics_active_replace(crowdsec_server_rec *sconf,
                                     const apr_uint32_t fresh
                                     [CROWDSEC_ORIGIN_MAX][CROWDSEC_IPT_MAX])
{
    struct crowdsec_metrics_shm *m = sconf ? sconf->metrics : NULL;
    apr_uint32_t o;
    int ipt;

    if (!m || !fresh) {
        return;
    }
    for (o = 0; o < CROWDSEC_ORIGIN_MAX; o++) {
        for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
            apr_atomic_set32(&m->active[o][ipt], fresh[o][ipt]);
            if (fresh[o][ipt]) {
                m->active_seen[o][ipt] = 1;
            }
        }
    }
}

int crowdsec_metrics_resync_take(crowdsec_server_rec *sconf)
{
    struct crowdsec_metrics_shm *m = sconf ? sconf->metrics : NULL;

    if (!m) {
        return 0;
    }
    return apr_atomic_xchg32(&m->resync_wanted, 0) != 0;
}

/* ------------------------------------------------------------- lifecycle */

apr_status_t crowdsec_metrics_pre_config(apr_pool_t *pconf)
{
    return ap_mutex_register(pconf, metrics_mutex_type, NULL, APR_LOCK_DEFAULT,
                             0);
}

/* Two servers pointing at the same url with the same key are one component as
 * far as the local API is concerned, so they must share one set of counters
 * and one pusher - otherwise each would report a fraction of the traffic under
 * the same name.
 */
static int same_endpoint(const crowdsec_server_rec *a,
                         const crowdsec_server_rec *b)
{
    if (!a->url || !b->url || strcmp(a->url, b->url)) {
        return 0;
    }
    if (!a->key || !b->key) {
        return a->key == b->key;
    }
    return !strcmp(a->key, b->key);
}

static apr_status_t region_create(apr_pool_t *pconf, apr_pool_t *plog,
                                  server_rec *s, crowdsec_server_rec *sconf,
                                  int index)
{
    apr_status_t rv;

    rv = apr_shm_create(&sconf->metrics_shm,
                        sizeof(struct crowdsec_metrics_shm), NULL, pconf);
    if (rv != APR_SUCCESS) {
        /* Anonymous shared memory is unavailable on some platforms, so fall
         * back to a named segment, as the decision store's region does.
         */
        const char *path = apr_psprintf(pconf, "crowdsec_metrics%d.shm",
                                        index);

        path = ap_runtime_dir_relative(pconf, path);
        apr_file_remove(path, pconf);
        rv = apr_shm_create(&sconf->metrics_shm,
                            sizeof(struct crowdsec_metrics_shm), path, pconf);
    }
    if (rv != APR_SUCCESS) {
        return rv;
    }
    sconf->metrics = apr_shm_baseaddr_get(sconf->metrics_shm);
    memset(sconf->metrics, 0, sizeof(*sconf->metrics));

    /* An instance id per region: ap_global_mutex_create derives a lock file
     * name from the type, so several regions sharing the type would otherwise
     * all try to use one file.
     */
    rv = ap_global_mutex_create(&sconf->metrics_mutex, NULL,
                                metrics_mutex_type,
                                apr_psprintf(pconf, "%d", index), s, pconf, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog,
                      "failed to create the %s mutex", metrics_mutex_type);
        return rv;
    }

    sconf->metrics->startup = apr_time_now();
    sconf->metrics->window_start = sconf->metrics->startup;
    sconf->metrics_owned = 1;

    /* The reserved slots, interned before anything else can claim them so
     * their ids are the constants the rest of the module uses.
     */
    crowdsec_metrics_origin_id(sconf, "unknown");
    crowdsec_metrics_origin_id(sconf, "appsec");

    return APR_SUCCESS;
}

apr_status_t crowdsec_metrics_create(apr_pool_t *pconf, apr_pool_t *plog,
                                    server_rec *base, server_rec *s)
{
    crowdsec_server_rec *sconf = ap_get_module_config(s->module_config,
                                                      &crowdsec_module);
    server_rec *o;
    int index = 0;

    if (!sconf || !sconf->metrics_enable) {
        return APR_SUCCESS;
    }
    /* /v1/usage-metrics is a local API endpoint, and CrowdsecURL is the only
     * thing that gives us one: CrowdsecAppsecURL points at the AppSec
     * datasource, a different component that serves no such endpoint. An
     * AppSec-only vhost is a supported configuration, so say what it means
     * rather than leaving the Console mysteriously empty.
     */
    if (!sconf->url) {
        if (sconf->appsec_url) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "crowdsec: no CrowdsecURL, so no usage metrics are "
                         "reported for this server; AppSec has no metrics "
                         "endpoint of its own");
        }
        return APR_SUCCESS;
    }

    for (o = base; o && o != s; o = o->next) {
        crowdsec_server_rec *oconf = ap_get_module_config(o->module_config,
                                                          &crowdsec_module);

        if (!oconf || !oconf->metrics_owned) {
            continue;
        }
        index++;
        if (same_endpoint(oconf, sconf)) {
            sconf->metrics_shm = oconf->metrics_shm;
            sconf->metrics = oconf->metrics;
            sconf->metrics_mutex = oconf->metrics_mutex;
            return APR_SUCCESS;
        }
    }
    return region_create(pconf, plog, s, sconf, index);
}

/* --------------------------------------------------------------- the push */

static void load_os_info(apr_pool_t *p)
{
    /* /usr/lib/os-release is the fallback the spec names, and the only one
     * present on an image with an empty /etc.
     */
    static const char *const paths[] = {
        "/etc/os-release", "/usr/lib/os-release", NULL
    };
    char buf[8192];
    int i;

    crowdsec_os_release_parse(NULL, 0, p, &os_info.os_name,
                              &os_info.os_version);

    for (i = 0; paths[i]; i++) {
        apr_file_t *fh = NULL;
        apr_size_t len = sizeof(buf);

        if (apr_file_open(&fh, paths[i], APR_FOPEN_READ, APR_OS_DEFAULT, p)
            != APR_SUCCESS) {
            continue;
        }
        /* A short read is fine: the parser takes whatever it is given and
         * falls back to placeholders for anything it cannot find.
         */
        if (apr_file_read(fh, buf, &len) == APR_SUCCESS && len) {
            crowdsec_os_release_parse(buf, len, p, &os_info.os_name,
                                      &os_info.os_version);
        }
        apr_file_close(fh);
        break;
    }
}

/* Copies the counters out, so the payload is built from a stable picture and
 * the window can be closed against exactly what was reported. Increments do
 * not take the lock, so one landing mid-copy simply belongs to the next
 * window.
 */
static void snapshot(crowdsec_server_rec *sconf, crowdsec_metrics_snap_t *snap)
{
    struct crowdsec_metrics_shm *m = sconf->metrics;

    memset(snap, 0, sizeof(*snap));
    snap->norigins = apr_atomic_read32(&m->norigins);
    if (snap->norigins > CROWDSEC_ORIGIN_MAX) {
        snap->norigins = CROWDSEC_ORIGIN_MAX;
    }
    memcpy(snap->origins, m->origins, sizeof(snap->origins));
    memcpy(snap->processed, m->processed, sizeof(snap->processed));
    memcpy(snap->dropped, m->dropped, sizeof(snap->dropped));
    memcpy(snap->active, m->active, sizeof(snap->active));
    memcpy(snap->active_seen, m->active_seen, sizeof(snap->active_seen));
    snap->have_active = (sconf->mode == CROWDSEC_MODE_STREAM) ? 1 : 0;
}

/* Takes back exactly what was reported, leaving anything counted since. */
static void window_close(crowdsec_server_rec *sconf,
                         const crowdsec_metrics_snap_t *snap, apr_time_t now)
{
    struct crowdsec_metrics_shm *m = sconf->metrics;
    apr_uint32_t o;
    int ipt;

    for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
        if (snap->processed[ipt]) {
            apr_atomic_sub32(&m->processed[ipt], snap->processed[ipt]);
        }
    }
    for (o = 0; o < CROWDSEC_ORIGIN_MAX; o++) {
        for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
            if (snap->dropped[o][ipt]) {
                apr_atomic_sub32(&m->dropped[o][ipt], snap->dropped[o][ipt]);
            }
        }
    }
    /* active is a gauge, not a delta: it is never taken back. */

    if (metrics_lock(sconf) == APR_SUCCESS) {
        m->window_start = now;
        m->last_push = now;
        m->pushes++;
        metrics_unlock(sconf);
    }
}

static apr_status_t do_push(server_rec *s, crowdsec_server_rec *sconf,
                            apr_pool_t *ptemp)
{
    crowdsec_metrics_snap_t *snap;
    crowdsec_metrics_static_t st;
    crowdsec_http_req_t req;
    crowdsec_buf_t buf;
    crowdsec_http_err_t herr;
    struct curl_slist **hdrs;
    const char *body;
    apr_time_t now, start;
    apr_interval_time_t window;
    long status = 0;
    char errbuf[256];

    if (!sconf->curl_handles || !sconf->metrics) {
        return APR_EINVAL;
    }

    if (metrics_lock(sconf) != APR_SUCCESS) {
        return APR_EGENERAL;
    }
    start = sconf->metrics->window_start;
    metrics_unlock(sconf);

    now = apr_time_now();
    /* Measured, not assumed. A push delayed by a slow endpoint or a leader
     * change must not claim a window it did not cover.
     */
    window = now - start;
    if (window <= 0) {
        window = sconf->metrics_interval;
    }
    /* Clamped, so a clock jump or an unset start cannot put a window measured
     * in decades in front of whoever reads the Console. Past the ceiling the
     * window is discarded anyway.
     */
    if (window > WINDOW_CEILING) {
        window = WINDOW_CEILING;
    }

    snap = apr_palloc(ptemp, sizeof(*snap));
    if (!snap) {
        return APR_ENOMEM;
    }
    snapshot(sconf, snap);

    st = os_info;
    st.startup = sconf->metrics->startup;

    body = crowdsec_metrics_payload(ptemp, &st, snap, now, window);
    if (!body) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: could not build the usage metrics payload");
        return APR_ENOMEM;
    }

    /* The holder lives in the pool, not on the stack: the cleanup runs when
     * the pool is destroyed, by which time a stack address would be a dead
     * frame. See live_query for the same reasoning.
     */
    hdrs = apr_pcalloc(ptemp, sizeof(*hdrs));
    apr_pool_cleanup_register(ptemp, hdrs, crowdsec_http_headers_cleanup,
                              apr_pool_cleanup_null);
    if (sconf->key
        && !crowdsec_http_header_add(ptemp, hdrs, "X-Api-Key", sconf->key)) {
        return APR_EINVAL;
    }
    if (!crowdsec_http_header_add(ptemp, hdrs, "Content-Type",
                                  "application/json")) {
        return APR_EINVAL;
    }
    crowdsec_http_header_add_raw(hdrs, "Accept:");

    memset(&req, 0, sizeof(req));
    req.url = apr_pstrcat(ptemp, sconf->url, "/v1/usage-metrics", NULL);
    req.post = 1;
    req.body = body;
    req.body_len = strlen(body);
    req.connect_timeout = sconf->connect_timeout;
    /* Off the request path, so a generous budget costs nobody latency. */
    req.timeout = sconf->timeout * 2;
    req.low_speed_time = apr_time_from_sec(10);
    req.ceiling = CEILING_METRICS;
    req.ssl_verify = 1;
    req.user_agent = CROWDSEC_BOUNCER_UA;
    req.headers = *hdrs;

    errbuf[0] = '\0';
    herr = crowdsec_http_exchange(sconf->curl_handles, &req, ptemp, &status,
                                  &buf, errbuf, sizeof(errbuf));

    if (metrics_lock(sconf) == APR_SUCCESS) {
        sconf->metrics->last_status = (herr == CROWDSEC_HTTP_OK) ? status : -1;
        if (herr != CROWDSEC_HTTP_OK || (status != 201 && status != 200)) {
            sconf->metrics->failures++;
        }
        metrics_unlock(sconf);
    }

    if (herr != CROWDSEC_HTTP_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: reporting usage metrics to '%s' failed (%s): "
                     "%s", sconf->url, crowdsec_http_err_str(herr), errbuf);
        return APR_EGENERAL;
    }
    /* 201 is what the local API answers; 200 is accepted so a proxy that
     * normalises the status does not cost every window.
     */
    if (status != 201 && status != 200) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "crowdsec: reporting usage metrics to '%s' returned %ld%s",
                     sconf->url, status,
                     status == 404 ? " (is the local API older than the "
                     "usage-metrics endpoint?)"
                     : status == 403 ? " (is the API key valid?)" : "");
        return APR_EGENERAL;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "crowdsec: reported usage metrics for a %" APR_TIME_T_FMT
                 "s window", apr_time_sec(window));

    window_close(sconf, snap, now);

    /* The gauge is only authoritative just after a full pull - see the comment
     * in crowdsec_store_apply_stream - so ask the poller for one. It has the
     * whole next window to get round to it.
     */
    if (sconf->mode == CROWDSEC_MODE_STREAM) {
        apr_atomic_set32(&sconf->metrics->resync_wanted, 1);
    }
    return APR_SUCCESS;
}

/* ------------------------------------------------------------- the lease */

static int lease_claim(crowdsec_server_rec *sconf, int *took_over)
{
    struct crowdsec_metrics_shm *m = sconf->metrics;
    apr_int64_t me = (apr_int64_t) getpid();
    apr_time_t now = apr_time_now();
    int leader = 0;

    *took_over = 0;

    if (metrics_lock(sconf) != APR_SUCCESS) {
        return 0;
    }
    if (m->lease.holder == me) {
        leader = 1;
    }
    else if (!m->lease.holder || now - m->lease.last_run > LEASE_STALE) {
        *took_over = m->lease.holder ? 1 : 0;
        leader = 1;
    }
    if (leader) {
        m->lease.holder = me;
        m->lease.last_run = now;
    }
    metrics_unlock(sconf);

    return leader;
}

static void lease_release(crowdsec_server_rec *sconf)
{
    struct crowdsec_metrics_shm *m = sconf->metrics;

    if (metrics_lock(sconf) != APR_SUCCESS) {
        return;
    }
    /* Only if it is still ours, so a child exiting late cannot evict whoever
     * took over from it.
     */
    if (m->lease.holder == (apr_int64_t) getpid()) {
        m->lease.holder = 0;
        m->lease.last_run = 0;
    }
    metrics_unlock(sconf);
}

static void *APR_THREAD_FUNC metrics_main(apr_thread_t *thd, void *data)
{
    crowdsec_server_rec *sconf = data;
    server_rec *s = sconf->metrics_server;
    apr_pool_t *tpool = NULL;
    apr_time_t last_claim = 0;
    int was_leader = 0;
    int leader = 0;

    apr_pool_create(&tpool, apr_thread_pool_get(thd));

    while (!sconf->metrics_stop) {
        apr_time_t now = apr_time_now();
        apr_interval_time_t slept = 0;

        if (now - last_claim >= LEASE_CLAIM_EVERY) {
            int took_over = 0;

            last_claim = now;
            leader = lease_claim(sconf, &took_over);
            if (leader && !was_leader) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                             "crowdsec: this child (%d) is now reporting "
                             "usage metrics%s", (int) getpid(),
                             took_over ? " (the previous one stopped)" : "");
            }
            was_leader = leader;
        }

        if (leader) {
            apr_time_t start;
            apr_interval_time_t age;

            if (metrics_lock(sconf) == APR_SUCCESS) {
                start = sconf->metrics->window_start;
                metrics_unlock(sconf);
            }
            else {
                start = now;
            }
            age = now - start;

            /* Re-taken right before pushing rather than trusting the
             * periodic check: the window is far longer than the claim
             * interval, so the lease may have moved since. One mutex take per
             * actual push is a cheap way not to report the same window twice
             * under the same component name.
             */
            if (age >= sconf->metrics_interval) {
                int took_over = 0;

                leader = lease_claim(sconf, &took_over);
                was_leader = leader;
            }

            if (leader && age >= sconf->metrics_interval) {
                apr_pool_t *ptemp;

                apr_pool_create(&ptemp, tpool);
                if (do_push(s, sconf, ptemp) != APR_SUCCESS
                    && age >= WINDOW_CEILING) {
                    /* Nothing is reset on a failure, so a window grows until
                     * the endpoint comes back and the whole period is reported
                     * with an honest window_size_seconds. Past a day that is
                     * no longer useful, and letting it grow without bound
                     * would eventually wrap the counters.
                     */
                    crowdsec_metrics_snap_t *snap = apr_palloc(ptemp,
                                                               sizeof(*snap));

                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                                 "crowdsec: usage metrics have not been "
                                 "accepted for %" APR_TIME_T_FMT "s; "
                                 "discarding the window and starting a new "
                                 "one", apr_time_sec(age));
                    if (snap) {
                        snapshot(sconf, snap);
                        window_close(sconf, snap, now);
                    }
                }
                apr_pool_destroy(ptemp);
            }
        }

        /* Slices, so a shutdown is noticed promptly rather than after a whole
         * claim interval.
         */
        while (slept < apr_time_from_sec(1) && !sconf->metrics_stop) {
            apr_sleep(apr_time_from_msec(200));
            slept += apr_time_from_msec(200);
        }
    }

    if (was_leader) {
        lease_release(sconf);
    }
    apr_pool_destroy(tpool);
    apr_thread_exit(thd, APR_SUCCESS);

    return NULL;
}

static apr_status_t metrics_cleanup(void *data)
{
    crowdsec_server_rec *sconf = data;
    apr_status_t rv;

    sconf->metrics_stop = 1;
    if (sconf->metrics_thread) {
        apr_thread_join(&rv, sconf->metrics_thread);
        sconf->metrics_thread = NULL;
    }
    return APR_SUCCESS;
}

static int thread_exists_for_region(server_rec *base,
                                    const crowdsec_server_rec *want)
{
    server_rec *s;

    for (s = base; s; s = s->next) {
        const crowdsec_server_rec *other =
            ap_get_module_config(s->module_config, &crowdsec_module);

        if (other && other != want && other->metrics_thread
            && other->metrics == want->metrics) {
            return 1;
        }
    }
    return 0;
}

apr_status_t crowdsec_metrics_start(apr_pool_t *pchild, server_rec *base)
{
    server_rec *s;
    int any = 0;

    for (s = base; s; s = s->next) {
        crowdsec_server_rec *sconf = ap_get_module_config(s->module_config,
                                                          &crowdsec_module);

        if (!sconf || !sconf->metrics || sconf->metrics_thread) {
            continue;
        }
        if (!any) {
            load_os_info(pchild);
            any = 1;
        }
        /* One thread per region, not per vhost: vhosts that inherited the
         * region each have their own server_rec, so a per-struct check alone
         * would start a thread for every one of them - all in this child, so
         * all with the same pid, so the lease would call each of them the
         * leader and they would all push.
         */
        if (thread_exists_for_region(base, sconf)) {
            continue;
        }
        sconf->metrics_server = s;
        sconf->metrics_stop = 0;
        if (apr_thread_create(&sconf->metrics_thread, NULL, metrics_main,
                              sconf, pchild) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         "crowdsec: could not start the usage metrics thread; "
                         "this child will not report");
            continue;
        }
        /* A pre-cleanup, for the reason spelled out in crowdsec_poller_start:
         * an ordinary one runs after the thread's own pool has been destroyed.
         */
        apr_pool_pre_cleanup_register(pchild, sconf, metrics_cleanup);
    }
    return APR_SUCCESS;
}

/* ------------------------------------------------------------- the status */

void crowdsec_metrics_status(request_rec *r, crowdsec_server_rec *sconf)
{
    struct crowdsec_metrics_shm *m = sconf ? sconf->metrics : NULL;
    crowdsec_metrics_snap_t *snap;
    apr_time_t now = apr_time_now();
    apr_time_t start = 0, last = 0;
    apr_uint32_t pushes = 0, failures = 0, overflow = 0;
    long status = 0;
    apr_uint32_t o;
    int ipt;

    if (!m) {
        ap_rputs("metrics: off\n", r);
        return;
    }
    snap = apr_palloc(r->pool, sizeof(*snap));
    if (!snap) {
        return;
    }
    snapshot(sconf, snap);

    if (metrics_lock(sconf) == APR_SUCCESS) {
        start = m->window_start;
        last = m->last_push;
        pushes = m->pushes;
        failures = m->failures;
        overflow = m->origin_overflow;
        status = m->last_status;
        metrics_unlock(sconf);
    }

    ap_rputs("metrics: on\n", r);
    ap_rprintf(r, "metrics_interval_s: %" APR_TIME_T_FMT "\n",
               apr_time_sec(sconf->metrics_interval));
    ap_rprintf(r, "metrics_window_age_s: %" APR_TIME_T_FMT "\n",
               start ? apr_time_sec(now - start) : -1);
    ap_rprintf(r, "metrics_last_push_age_s: %" APR_TIME_T_FMT "\n",
               last ? apr_time_sec(now - last) : -1);
    ap_rprintf(r, "metrics_pushes: %u\n", (unsigned int) pushes);
    ap_rprintf(r, "metrics_failures: %u\n", (unsigned int) failures);
    ap_rprintf(r, "metrics_last_status: %ld\n", status);
    ap_rprintf(r, "metrics_origins: %u\n", (unsigned int) snap->norigins);
    ap_rprintf(r, "metrics_origin_overflow: %u\n", (unsigned int) overflow);

    /* One line per non-trivial counter, in the same shape the payload uses, so
     * a test can assert on attribution without intercepting the POST.
     */
    for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
        ap_rprintf(r, "processed{ip_type=%s}: %u\n",
                   ipt == CROWDSEC_IPT_V6 ? "ipv6" : "ipv4",
                   (unsigned int) snap->processed[ipt]);
    }
    for (o = 0; o < snap->norigins; o++) {
        for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
            if (snap->dropped[o][ipt]) {
                ap_rprintf(r, "dropped{ip_type=%s,origin=%s}: %u\n",
                           ipt == CROWDSEC_IPT_V6 ? "ipv6" : "ipv4",
                           snap->origins[o],
                           (unsigned int) snap->dropped[o][ipt]);
            }
        }
    }
    if (snap->have_active) {
        for (o = 0; o < snap->norigins; o++) {
            for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
                if (snap->active_seen[o][ipt]) {
                    ap_rprintf(r, "active_decisions{ip_type=%s,origin=%s}: "
                               "%u\n",
                               ipt == CROWDSEC_IPT_V6 ? "ipv6" : "ipv4",
                               snap->origins[o],
                               (unsigned int) snap->active[o][ipt]);
                }
            }
        }
    }
}
