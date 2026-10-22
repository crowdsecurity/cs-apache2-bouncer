/* Unit tests for the usage-metrics payload and the os-release parser. Links
 * apr only, no httpd, so the document's exact shape can be asserted without a
 * running server.
 *
 * The assertions are on the raw string rather than on a parsed tree on
 * purpose: the two mistakes that actually break this payload - an empty array
 * serialised as {}, and an unescaped label - both survive a round trip through
 * a decoder.
 */
#include <stdio.h>
#include <string.h>

#include "apr_general.h"
#include "apr_strings.h"

#include "crowdsec_metrics_json.h"

static int failures;

#define CHECK(cond, ...)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            failures++;                                                 \
            printf("not ok - %s:%d ", __FILE__, __LINE__);              \
            printf(__VA_ARGS__);                                        \
            printf("\n");                                               \
        }                                                               \
    } while (0)

static crowdsec_metrics_static_t static_info(void)
{
    crowdsec_metrics_static_t st;

    st.os_name = "Debian GNU/Linux";
    st.os_version = "12";
    st.startup = apr_time_from_sec(1760000000);

    return st;
}

/* Interns an origin the way the shared table would, so the snapshot the
 * builder sees matches what the running module produces.
 */
static void intern(crowdsec_metrics_snap_t *s, const char *name)
{
    apr_cpystrn(s->origins[s->norigins], name, CROWDSEC_ORIGIN_LEN);
    s->norigins++;
}

static void test_empty(void)
{
    apr_pool_t *p;
    crowdsec_metrics_snap_t snap;
    crowdsec_metrics_static_t st = static_info();
    char *out;

    apr_pool_create(&p, NULL);
    memset(&snap, 0, sizeof(snap));

    out = crowdsec_metrics_payload(p, &st, &snap,
                                   apr_time_from_sec(1760000900),
                                   apr_time_from_sec(900));
    CHECK(out != NULL, "payload returned NULL");
    if (out) {
        /* The two array fields that must never serialise as objects. */
        CHECK(strstr(out, "\"feature_flags\":[]") != NULL,
              "feature_flags is not an empty array: %s", out);
        CHECK(strstr(out, "\"feature_flags\":{}") == NULL,
              "feature_flags serialised as an object");
        CHECK(strstr(out, "\"log_processors\":null") != NULL,
              "log_processors is not null: %s", out);
        CHECK(strstr(out, "\"type\":\"crowdsec-apache2-bouncer\"") != NULL,
              "wrong type: %s", out);
        /* name is resolved by the local API from the API key, so we must not
         * send one.
         */
        CHECK(strstr(out, "\"name\":\"crowdsec-apache2-bouncer\"") == NULL,
              "payload sends a component name");
        CHECK(strstr(out, "\"utc_startup_timestamp\":1760000000") != NULL,
              "wrong startup timestamp: %s", out);
        CHECK(strstr(out, "\"utc_now_timestamp\":1760000900") != NULL,
              "wrong now timestamp: %s", out);
        CHECK(strstr(out, "\"window_size_seconds\":900") != NULL,
              "wrong window: %s", out);
        CHECK(strstr(out, "\"os\":{\"name\":\"Debian GNU/Linux\","
                     "\"version\":\"12\"}") != NULL,
              "wrong os block: %s", out);
        /* An idle window still reports processed, for both families: an
         * absent item cannot say "alive, no traffic".
         */
        CHECK(strstr(out, "\"name\":\"processed\",\"value\":0,\"unit\":"
                     "\"request\",\"labels\":{\"ip_type\":\"ipv4\"}") != NULL,
              "no zero ipv4 processed item: %s", out);
        CHECK(strstr(out, "\"ip_type\":\"ipv6\"") != NULL,
              "no ipv6 processed item: %s", out);
        /* Nothing was dropped and nothing is active, so neither appears. */
        CHECK(strstr(out, "dropped") == NULL, "dropped emitted at zero: %s",
              out);
        CHECK(strstr(out, "active_decisions") == NULL,
              "active_decisions emitted with no store: %s", out);
    }
    apr_pool_destroy(p);
}

static void test_items(void)
{
    apr_pool_t *p;
    crowdsec_metrics_snap_t snap;
    crowdsec_metrics_static_t st = static_info();
    char *out;

    apr_pool_create(&p, NULL);
    memset(&snap, 0, sizeof(snap));

    intern(&snap, "unknown");
    intern(&snap, "appsec");
    intern(&snap, "CAPI");
    intern(&snap, "lists:firehol_level1");

    snap.processed[CROWDSEC_IPT_V4] = 42;
    snap.processed[CROWDSEC_IPT_V6] = 3;
    snap.dropped[2][CROWDSEC_IPT_V4] = 7;
    snap.dropped[1][CROWDSEC_IPT_V6] = 1;
    snap.active[3][CROWDSEC_IPT_V4] = 1183;
    snap.active_seen[3][CROWDSEC_IPT_V4] = 1;
    snap.have_active = 1;

    out = crowdsec_metrics_payload(p, &st, &snap,
                                   apr_time_from_sec(1760000900),
                                   apr_time_from_sec(900));
    CHECK(out != NULL, "payload returned NULL");
    if (out) {
        CHECK(strstr(out, "\"name\":\"processed\",\"value\":42,\"unit\":"
                     "\"request\",\"labels\":{\"ip_type\":\"ipv4\"}") != NULL,
              "wrong processed item: %s", out);
        CHECK(strstr(out, "\"name\":\"dropped\",\"value\":7,\"unit\":"
                     "\"request\",\"labels\":{\"ip_type\":\"ipv4\","
                     "\"origin\":\"CAPI\"}") != NULL,
              "wrong dropped item: %s", out);
        CHECK(strstr(out, "\"name\":\"dropped\",\"value\":1,\"unit\":"
                     "\"request\",\"labels\":{\"ip_type\":\"ipv6\","
                     "\"origin\":\"appsec\"}") != NULL,
              "no appsec-attributed drop: %s", out);
        CHECK(strstr(out, "\"name\":\"active_decisions\",\"value\":1183,"
                     "\"unit\":\"ip\",\"labels\":{\"ip_type\":\"ipv4\","
                     "\"origin\":\"lists:firehol_level1\"}") != NULL,
              "wrong active_decisions item: %s", out);
        /* processed carries no origin label: at the point it is counted there
         * is no decision to attribute it to.
         */
        CHECK(strstr(out, "\"processed\",\"value\":42,\"unit\":\"request\","
                     "\"labels\":{\"ip_type\":\"ipv4\",\"origin\"") == NULL,
              "processed carries an origin label: %s", out);
        /* A slot that was never touched must not appear. */
        CHECK(strstr(out, "\"origin\":\"unknown\"") == NULL,
              "untouched origin emitted: %s", out);
        /* No trailing or doubled commas between items. */
        CHECK(strstr(out, ",,") == NULL, "doubled comma: %s", out);
        CHECK(strstr(out, ",]") == NULL, "trailing comma: %s", out);
        CHECK(strstr(out, "[,") == NULL, "leading comma: %s", out);
    }
    apr_pool_destroy(p);
}

/* A gauge that has fallen to zero must say so. Reporting nothing would leave
 * the Console showing the last non-zero reading for good, which is what
 * lua-cs-bouncer does.
 */
static void test_active_zero_is_reported(void)
{
    apr_pool_t *p;
    crowdsec_metrics_snap_t snap;
    crowdsec_metrics_static_t st = static_info();
    char *out;

    apr_pool_create(&p, NULL);
    memset(&snap, 0, sizeof(snap));
    intern(&snap, "lists:gone");
    snap.active[0][CROWDSEC_IPT_V4] = 0;
    snap.active_seen[0][CROWDSEC_IPT_V4] = 1;
    snap.have_active = 1;

    out = crowdsec_metrics_payload(p, &st, &snap, apr_time_from_sec(2),
                                   apr_time_from_sec(900));
    CHECK(out && strstr(out, "\"name\":\"active_decisions\",\"value\":0,"
                        "\"unit\":\"ip\",\"labels\":{\"ip_type\":\"ipv4\","
                        "\"origin\":\"lists:gone\"}") != NULL,
          "an emptied gauge is not reported as zero: %s", out ? out : "(null)");

    /* ...but only where the store exists to count it. */
    snap.have_active = 0;
    out = crowdsec_metrics_payload(p, &st, &snap, apr_time_from_sec(2),
                                   apr_time_from_sec(900));
    CHECK(out && strstr(out, "active_decisions") == NULL,
          "live mode emitted active_decisions: %s", out ? out : "(null)");

    apr_pool_destroy(p);
}

/* Origins come from the local API, so a name is not ours to trust. */
static void test_escaping(void)
{
    apr_pool_t *p;
    crowdsec_metrics_snap_t snap;
    crowdsec_metrics_static_t st = static_info();
    char *out;

    apr_pool_create(&p, NULL);
    memset(&snap, 0, sizeof(snap));
    intern(&snap, "lists:a\"b\\c\td\x01" "e\xc3\xa9");
    snap.dropped[0][CROWDSEC_IPT_V4] = 1;

    out = crowdsec_metrics_payload(p, &st, &snap, apr_time_from_sec(2),
                                   apr_time_from_sec(900));
    CHECK(out != NULL, "payload returned NULL");
    if (out) {
        CHECK(strstr(out, "\"origin\":\"lists:a\\\"b\\\\c\\td\\u0001"
                     "e\xc3\xa9\"") != NULL,
              "origin not escaped as expected: %s", out);
        /* The injection this exists to stop: a bare quote would close the
         * string and let the rest be read as structure.
         */
        CHECK(strstr(out, "\"lists:a\"b") == NULL,
              "an unescaped quote reached the output: %s", out);
    }

    /* The os fields come off disk and get the same treatment. */
    st.os_name = "a\"b";
    st.os_version = "1\\2";
    out = crowdsec_metrics_payload(p, &st, &snap, apr_time_from_sec(2),
                                   apr_time_from_sec(900));
    CHECK(out && strstr(out, "\"name\":\"a\\\"b\",\"version\":\"1\\\\2\"")
          != NULL, "os fields not escaped: %s", out ? out : "(null)");

    apr_pool_destroy(p);
}

/* A full table, to prove nothing overruns and the item count is bounded. */
static void test_full_table(void)
{
    apr_pool_t *p;
    crowdsec_metrics_snap_t snap;
    crowdsec_metrics_static_t st = static_info();
    char *out;
    int i, ipt;

    apr_pool_create(&p, NULL);
    memset(&snap, 0, sizeof(snap));

    for (i = 0; i < CROWDSEC_ORIGIN_MAX; i++) {
        char name[CROWDSEC_ORIGIN_LEN];

        /* A name that fills the slot exactly, to catch an off-by-one in the
         * copy: apr_cpystrn truncates to LEN-1 plus a terminator.
         */
        memset(name, 'x', sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
        apr_snprintf(name, sizeof(name), "lists:%0*d", CROWDSEC_ORIGIN_LEN - 8,
                     i);
        intern(&snap, name);
        for (ipt = 0; ipt < CROWDSEC_IPT_MAX; ipt++) {
            snap.dropped[i][ipt] = (apr_uint32_t) (i + 1);
            snap.active[i][ipt] = (apr_uint32_t) (i + 100);
            snap.active_seen[i][ipt] = 1;
        }
    }
    snap.have_active = 1;

    out = crowdsec_metrics_payload(p, &st, &snap, apr_time_from_sec(2),
                                   apr_time_from_sec(900));
    CHECK(out != NULL, "full table returned NULL");
    if (out) {
        apr_size_t n = strlen(out);
        const char *at = out;
        int items = 0;

        while ((at = strstr(at, "\"name\":\"")) != NULL) {
            items++;
            at += 8;
        }
        /* 2 processed + 128 dropped + 128 active, plus the os block's "name". */
        CHECK(items == 2 + 128 + 128 + 1, "unexpected item count %d", items);
        CHECK(out[n - 1] == '}', "payload does not end cleanly: %s",
              out + (n > 40 ? n - 40 : 0));
    }
    apr_pool_destroy(p);
}

/* An origin table reporting more slots than exist must not be believed. */
static void test_norigins_clamped(void)
{
    apr_pool_t *p;
    crowdsec_metrics_snap_t snap;
    crowdsec_metrics_static_t st = static_info();

    apr_pool_create(&p, NULL);
    memset(&snap, 0, sizeof(snap));
    snap.norigins = CROWDSEC_ORIGIN_MAX + 9000;

    CHECK(crowdsec_metrics_payload(p, &st, &snap, apr_time_from_sec(2),
                                   apr_time_from_sec(900)) != NULL,
          "an over-large norigins was not clamped");
    apr_pool_destroy(p);
}

static void test_os_release(void)
{
    apr_pool_t *p;
    const char *name, *version;
    struct {
        const char *in;
        const char *name;
        const char *version;
    } t[] = {
        { "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n",
          "Debian GNU/Linux", "12" },
        /* Unquoted, as Arch and some containers write it. */
        { "NAME=Alpine Linux\nVERSION_ID=3.19.1\n",
          "Alpine Linux", "3.19.1" },
        { "NAME='Rocky Linux'\nVERSION_ID='9.3'\n", "Rocky Linux", "9.3" },
        /* Rolling releases have no VERSION_ID at all. */
        { "NAME=\"Arch Linux\"\n", "Arch Linux", "unknown" },
        /* No trailing newline. */
        { "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"", "Ubuntu", "24.04" },
        { "NAME=\"Ubuntu\"\r\nVERSION_ID=\"24.04\"\r\n", "Ubuntu", "24.04" },
        /* PRETTY_NAME and CODENAME must not be mistaken for NAME. */
        { "PRETTY_NAME=\"Debian 12 (bookworm)\"\nNAME=\"Debian\"\n"
          "VERSION_CODENAME=bookworm\nVERSION_ID=\"12\"\n", "Debian", "12" },
        /* Comments and blank lines. */
        { "# a comment\n\nNAME=\"Fedora\"\n#NAME=\"nope\"\n",
          "Fedora", "unknown" },
        /* Present but empty: a placeholder beats an empty label, which the
         * local API rejects outright.
         */
        { "NAME=\nVERSION_ID=\"\"\n", "Linux", "unknown" },
        /* Nothing we recognise. */
        { "ID=debian\nHOME_URL=\"https://example.com\"\n",
          "Linux", "unknown" },
        { "", "Linux", "unknown" },
        /* Truncated mid-line, as a short read would leave it. The opening
         * quote is still stripped, so a half-written file yields a usable
         * name rather than one with a stray quote in it.
         */
        { "NAME=\"Debian GNU/Li", "Debian GNU/Li", "unknown" },
        /* Leading whitespace is tolerated. */
        { "  NAME=\"SLES\"\n\tVERSION_ID=\"15.5\"\n", "SLES", "15.5" },
    };
    unsigned i;

    apr_pool_create(&p, NULL);
    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        crowdsec_os_release_parse(t[i].in, strlen(t[i].in), p, &name,
                                  &version);
        CHECK(!strcmp(name, t[i].name), "case %u: name %s, wanted %s", i,
              name, t[i].name);
        CHECK(!strcmp(version, t[i].version), "case %u: version %s, wanted %s",
              i, version, t[i].version);
    }

    /* A value longer than the local API's 255-byte label cap is truncated, not
     * dropped: a long name is still better than no name.
     */
    {
        char big[600];

        apr_cpystrn(big, "NAME=", sizeof(big));
        memset(big + 5, 'z', 500);
        big[505] = '\0';
        crowdsec_os_release_parse(big, strlen(big), p, &name, &version);
        CHECK(strlen(name) == 255, "long name not truncated to 255: %"
              APR_SIZE_T_FMT, strlen(name));
    }

    /* NULL-safe, because the file may not exist. */
    crowdsec_os_release_parse(NULL, 0, p, &name, &version);
    CHECK(!strcmp(name, "Linux") && !strcmp(version, "unknown"),
          "NULL buffer did not yield placeholders");

    apr_pool_destroy(p);
}

int main(void)
{
    if (apr_initialize() != APR_SUCCESS) {
        printf("not ok - apr_initialize\n");
        return 1;
    }
    test_empty();
    test_items();
    test_active_zero_is_reported();
    test_escaping();
    test_full_table();
    test_norigins_clamped();
    test_os_release();
    apr_terminate();

    if (failures) {
        printf("FAILED: %d\n", failures);
        return 1;
    }
    printf("ok - all metrics tests passed\n");
    return 0;
}
