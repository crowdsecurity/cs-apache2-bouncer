/* Parser tests. Also the fuzz target's reference: every assertion here about
 * what must be rejected is a property fuzz_verdict re-checks on random input.
 */
#include <stdio.h>
#include <string.h>

#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"

#include "crowdsec_util.h"
#include "crowdsec_verdict.h"

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

/* Records what the parser handed us, so the tests can assert on the keys that
 * would actually reach the cache.
 */
#define MAX_SEEN 64
typedef struct
{
    int n;
    int added[MAX_SEEN];
    unsigned char key[MAX_SEEN][CROWDSEC_KEY_MAX];
    apr_size_t keylen[MAX_SEEN];
    apr_interval_time_t dur[MAX_SEEN];
    apr_status_t rv;            /* what to return, for the abort test */
} collector_t;

static apr_status_t collect(void *ctx, int added,
                            const crowdsec_decision_t *d)
{
    collector_t *c = ctx;

    if (c->n < MAX_SEEN) {
        c->added[c->n] = added;
        c->keylen[c->n] = crowdsec_key_encode(&d->net, c->key[c->n],
                                              CROWDSEC_KEY_MAX);
        c->dur[c->n] = d->duration;
        c->n++;
    }
    return c->rv;
}

static int run(apr_pool_t *p, const char *json, collector_t *c,
               crowdsec_decision_stats_t *st, const char **err)
{
    memset(c, 0, sizeof(*c));
    c->rv = APR_SUCCESS;
    *err = NULL;
    return crowdsec_stream_parse(json, strlen(json), p, collect, c, st, err);
}

static void test_stream_basic(apr_pool_t *p)
{
    collector_t c;
    crowdsec_decision_stats_t st;
    const char *err;

    CHECK(run(p, "{\"new\":[{\"scope\":\"Ip\",\"value\":\"1.2.3.4\","
              "\"duration\":\"1h0m0s\",\"type\":\"ban\"}],\"deleted\":null}",
              &c, &st, &err), "simple new: %s", err ? err : "");
    CHECK(st.added == 1 && st.removed == 0, "one added");
    CHECK(c.n == 1 && c.added[0] == 1, "callback saw one add");
    /* key layout: spread byte, family, prefix, network */
    CHECK(c.keylen[0] == 7 && c.key[0][1] == 4 && c.key[0][2] == 32,
          "v4 /32 key");
    CHECK(c.dur[0] == APR_TIME_C(3600) * APR_USEC_PER_SEC, "duration");

    /* a range keeps its prefix and masks its host bits */
    CHECK(run(p, "{\"new\":[{\"scope\":\"Range\",\"value\":\"10.0.0.77/24\","
              "\"duration\":\"1h\"}]}", &c, &st, &err), "range: %s",
              err ? err : "");
    CHECK(st.added == 1, "range added");
    CHECK(c.key[0][2] == 24 && c.key[0][3 + 3] == 0, "range masked to /24");

    /* both keys absent is a legal no-op heartbeat */
    CHECK(run(p, "{}", &c, &st, &err), "empty object: %s", err ? err : "");
    CHECK(st.added == 0 && st.removed == 0 && c.n == 0, "no-op");
    CHECK(run(p, "{\"new\":null,\"deleted\":null}", &c, &st, &err),
          "explicit nulls");
    CHECK(run(p, "{\"new\":[],\"deleted\":[]}", &c, &st, &err),
          "empty arrays");
}

static void test_stream_deleted(apr_pool_t *p)
{
    collector_t c;
    crowdsec_decision_stats_t st;
    const char *err;

    /* A deletion carries an elapsed duration. It must still be applied, or
     * unbanning would never work.
     */
    CHECK(run(p, "{\"deleted\":[{\"scope\":\"Ip\",\"value\":\"1.2.3.4\","
              "\"duration\":\"-1h0m0s\"}]}", &c, &st, &err),
              "deletion: %s", err ? err : "");
    CHECK(st.removed == 1 && st.skipped_expired == 0,
          "negative duration does not block a deletion");
    CHECK(c.n == 1 && c.added[0] == 0, "callback saw a removal");

    /* A deletion needs no duration field at all. */
    CHECK(run(p, "{\"deleted\":[{\"scope\":\"Ip\",\"value\":\"1.2.3.4\"}]}",
              &c, &st, &err), "deletion without duration");
    CHECK(st.removed == 1, "applied");

    /* Deletions are walked first, so a value in both lists ends up present. */
    CHECK(run(p, "{\"new\":[{\"scope\":\"Ip\",\"value\":\"9.9.9.9\","
              "\"duration\":\"1h\"}],"
              "\"deleted\":[{\"scope\":\"Ip\",\"value\":\"9.9.9.9\"}]}",
              &c, &st, &err), "both lists");
    CHECK(c.n == 2 && c.added[0] == 0 && c.added[1] == 1,
          "removal applied before the add");
}

static void test_stream_rejects(apr_pool_t *p)
{
    collector_t c;
    crowdsec_decision_stats_t st;
    const char *err;

    /* An expired new decision is dropped rather than stored. */
    CHECK(run(p, "{\"new\":[{\"scope\":\"Ip\",\"value\":\"1.2.3.4\","
              "\"duration\":\"-5s\"}]}", &c, &st, &err), "expired new");
    CHECK(st.added == 0 && st.skipped_expired == 1, "expired is skipped");

    /* Scopes we cannot evaluate are counted, not guessed at. */
    CHECK(run(p, "{\"new\":[{\"scope\":\"Country\",\"value\":\"FR\","
              "\"duration\":\"1h\"},{\"scope\":\"AS\",\"value\":\"1234\","
              "\"duration\":\"1h\"}]}", &c, &st, &err), "unsupported scopes");
    CHECK(st.added == 0 && st.skipped_scope == 2, "two scopes skipped");
    CHECK(c.n == 0, "nothing reached the cache");

    /* A value that does not parse must never become a key. */
    CHECK(run(p, "{\"new\":[{\"scope\":\"Ip\",\"value\":\"10.0.0.256\","
              "\"duration\":\"1h\"},{\"scope\":\"Ip\","
              "\"value\":\"1.2.3.4/33\",\"duration\":\"1h\"},"
              "{\"scope\":\"Ip\",\"value\":\"\",\"duration\":\"1h\"}]}",
              &c, &st, &err), "bad values");
    CHECK(st.malformed == 3 && st.added == 0, "three malformed");
    CHECK(c.n == 0, "none reached the cache");

    /* Wrong types where strings are required. */
    CHECK(run(p, "{\"new\":[{\"scope\":1,\"value\":\"1.2.3.4\","
              "\"duration\":\"1h\"},{\"scope\":\"Ip\",\"value\":2,"
              "\"duration\":\"1h\"},{\"scope\":\"Ip\",\"value\":\"1.2.3.4\","
              "\"duration\":3}]}", &c, &st, &err), "wrong types");
    CHECK(st.added == 0, "nothing added from wrong types");
    CHECK(st.malformed + st.skipped_scope == 3, "all three rejected");

    /* An unparseable duration is malformed, not treated as forever. */
    CHECK(run(p, "{\"new\":[{\"scope\":\"Ip\",\"value\":\"1.2.3.4\","
              "\"duration\":\"forever\"}]}", &c, &st, &err), "bad duration");
    CHECK(st.added == 0 && st.malformed == 1, "bad duration rejected");

    /* Scope is matched case-insensitively. */
    CHECK(run(p, "{\"new\":[{\"scope\":\"ip\",\"value\":\"1.2.3.4\","
              "\"duration\":\"1h\"},{\"scope\":\"RANGE\","
              "\"value\":\"10.0.0.0/8\",\"duration\":\"1h\"}]}",
              &c, &st, &err), "scope case");
    CHECK(st.added == 2, "lowercase and uppercase scopes both accepted");

    /* An array item that is not an object. */
    CHECK(run(p, "{\"new\":[1,\"x\",null,[]]}", &c, &st, &err),
          "non-object items");
    CHECK(st.malformed == 4 && st.added == 0, "all four malformed");
}

static void test_stream_malformed_doc(apr_pool_t *p)
{
    collector_t c;
    crowdsec_decision_stats_t st;
    const char *err;

    CHECK(!run(p, "", &c, &st, &err), "empty body rejected");
    CHECK(err != NULL, "empty body sets err");
    CHECK(!run(p, "{", &c, &st, &err), "truncated rejected");
    CHECK(!run(p, "not json", &c, &st, &err), "garbage rejected");
    CHECK(!run(p, "[]", &c, &st, &err), "array root rejected");
    CHECK(!run(p, "null", &c, &st, &err), "null root rejected");
    CHECK(!run(p, "{\"new\":{}}", &c, &st, &err), "object for new rejected");
    CHECK(!run(p, "{\"new\":\"x\"}", &c, &st, &err), "string for new rejected");

    /* Unterminated input is malformed for ordinary reasons. */
    {
        char trunc[4096];
        apr_size_t i;

        for (i = 0; i < sizeof(trunc) - 1; i++) {
            trunc[i] = '[';
        }
        trunc[sizeof(trunc) - 1] = '\0';
        CHECK(!run(p, trunc, &c, &st, &err), "unterminated nesting rejected");
    }
}

/* YYJSON_READER_DEPTH_LIMIT is 0 (off) upstream, so it has to be set at
 * compile time. This checks it actually took effect, using *valid* JSON that
 * is merely too deep - unterminated input would be rejected anyway and would
 * prove nothing.
 */
static void test_depth_limit(apr_pool_t *p)
{
    char deep[512];
    apr_size_t half = 32;       /* depth 32, well past the limit of 8 */
    apr_size_t i;
    int any;
    const char *err;

    for (i = 0; i < half; i++) {
        deep[i] = '[';
        deep[half * 2 - 1 - i] = ']';
    }
    deep[half * 2] = '\0';

    /* Valid JSON: an array nested 32 deep. Without the depth limit this parses
     * happily and reports a non-empty array, i.e. "banned".
     */
    CHECK(!crowdsec_decisions_any(deep, strlen(deep), p, &any, &err),
          "nesting past the depth limit is refused");

    /* Shallow nesting still works, so the limit is not rejecting everything. */
    CHECK(crowdsec_decisions_any("[[1]]", 5, p, &any, &err) && any,
          "nesting within the limit still parses");
}

static void test_abort(apr_pool_t *p)
{
    collector_t c;
    crowdsec_decision_stats_t st;
    const char *err;

    /* A storage failure mid-batch must abort the parse, not be ignored. */
    {
        static const char two[] =
            "{\"new\":[{\"scope\":\"Ip\",\"value\":\"1.2.3.4\","
            "\"duration\":\"1h\"},{\"scope\":\"Ip\",\"value\":\"5.6.7.8\","
            "\"duration\":\"1h\"}]}";

        memset(&c, 0, sizeof(c));
        c.rv = APR_EGENERAL;
        err = NULL;
        CHECK(!crowdsec_stream_parse(two, strlen(two), p, collect, &c, &st,
                                     &err), "callback failure aborts");
    }
    CHECK(c.n == 1, "stopped at the first failure");
}

static void test_decisions_any(apr_pool_t *p)
{
    int any;
    const char *err;

    CHECK(crowdsec_decisions_any("null", sizeof("null") - 1, p, &any, &err) && !any,
          "null means none");
    CHECK(crowdsec_decisions_any("[]", sizeof("[]") - 1, p, &any, &err) && !any,
          "empty array means none");
    {
        static const char one[] = "[{\"value\":\"1.2.3.4\"}]";

        CHECK(crowdsec_decisions_any(one, strlen(one), p, &any, &err) && any,
              "non-empty means banned");
    }
    /* The old code did strcmp(body, "null"), so these were indistinguishable
     * from a ban.
     */
    CHECK(crowdsec_decisions_any("  null  ", sizeof("  null  ") - 1, p, &any, &err) && !any,
          "whitespace around null still means none");
    CHECK(!crowdsec_decisions_any("{}", sizeof("{}") - 1, p, &any, &err),
          "object root rejected");
    CHECK(!crowdsec_decisions_any("", 0, p, &any, &err), "empty rejected");
    CHECK(!crowdsec_decisions_any("nul", sizeof("nul") - 1, p, &any, &err),
          "truncated null rejected");
}

/* ------------------------------------------------------------ appsec */

static int av(apr_pool_t *p, const char *json, crowdsec_appsec_verdict_t *out,
              const char **err)
{
    return crowdsec_appsec_parse(json, strlen(json), p, out, err);
}

static void test_appsec_basic(apr_pool_t *p)
{
    crowdsec_appsec_verdict_t v;
    const char *err;

    CHECK(av(p, "{\"action\":\"allow\",\"http_status\":200}", &v, &err),
          "allow: %s", err ? err : "");
    CHECK(v.rem == CROWDSEC_REM_ALLOW && v.http_status == 200, "allow fields");

    CHECK(av(p, "{\"action\":\"ban\",\"http_status\":403}", &v, &err), "ban");
    CHECK(v.rem == CROWDSEC_REM_BAN && v.http_status == 403, "ban fields");

    /* A 200 can still say captcha when default_pass_action is set, which is
     * why the body is parsed on 200 as well as 403.
     */
    CHECK(av(p, "{\"action\":\"captcha\",\"http_status\":200}", &v, &err),
          "captcha on a 200");
    CHECK(v.rem == CROWDSEC_REM_CAPTCHA, "captcha maps to captcha");

    /* An action invented by an administrator is legal and must not read as
     * allow.
     */
    CHECK(av(p, "{\"action\":\"shenanigans\",\"http_status\":403}", &v, &err),
          "unknown action parses");
    CHECK(v.rem == CROWDSEC_REM_UNKNOWN, "unknown action is not allow");
    CHECK(v.action && !strcmp(v.action, "shenanigans"),
          "the raw action survives for logging");
}

static void test_appsec_challenge(apr_pool_t *p)
{
    crowdsec_appsec_verdict_t v;
    const char *err;

    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":200,"
              "\"user_body_content\":\"<html>hi</html>\","
              "\"user_cookies\":[\"a=1; Path=/\",\"b=2; Path=/\"],"
              "\"user_headers\":{\"Content-Security-Policy\":[\"default-src 'self'\"],"
              "\"X-Thing\":\"v\"}}", &v, &err), "challenge: %s",
              err ? err : "");
    CHECK(v.rem == CROWDSEC_REM_CHALLENGE, "challenge action");
    CHECK(v.body_len == 15 && v.body && !memcmp(v.body, "<html>hi</html>", 15),
          "body copied with its length");
    CHECK(v.ncookies == 2, "two cookies");
    CHECK(v.cookies[0] && !strcmp(v.cookies[0], "a=1; Path=/"), "cookie 0");
    CHECK(v.nheaders == 2, "two headers from one string and one array");

    /* 307 with a Location is how a granted challenge cookie is delivered, so
     * the status must never be assumed to be 200.
     */
    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":307,"
              "\"user_body_content\":\"x\","
              "\"user_headers\":{\"Location\":\"/somewhere\"}}", &v, &err),
              "307 challenge");
    CHECK(v.http_status == 307, "307 preserved");

    /* An empty body is the caller's cue to fail closed; the parse itself
     * succeeds so the caller can tell why.
     */
    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":200}", &v, &err),
          "challenge with no body parses");
    CHECK(v.body_len == 0, "no body reported");
}

static void test_appsec_injection(apr_pool_t *p)
{
    crowdsec_appsec_verdict_t v;
    const char *err;

    /* The whole point of validating engine-supplied headers: a CR or LF would
     * end our header and begin one of someone else's choosing.
     */
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_headers\":{\"X\":\"a\\r\\nEvil: 1\"}}", &v, &err),
               "CRLF in a header value is refused");
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_cookies\":[\"a=1\\r\\nEvil: 1\"]}", &v, &err),
               "CRLF in a cookie is refused");
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_headers\":{\"X\\r\\nY\":\"v\"}}", &v, &err),
               "CRLF in a header name is refused");
    /* An escaped NUL makes the reported length disagree with strlen. */
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_headers\":{\"X\":\"a\\u0000b\"}}", &v, &err),
               "embedded NUL in a header value is refused");

    /* Framing headers are dropped rather than rejected: the engine may send a
     * Content-Type it believes in, and we set ours from Apache instead.
     */
    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":200,"
              "\"user_body_content\":\"x\","
              "\"user_headers\":{\"Content-Length\":\"99\","
              "\"Transfer-Encoding\":\"chunked\",\"Content-Type\":\"text/x\","
              "\"Server\":\"nginx\",\"X-Keep\":\"yes\"}}", &v, &err),
              "framing headers dropped: %s", err ? err : "");
    CHECK(v.nheaders == 1 && !strcmp(v.headers[0].name, "X-Keep"),
          "only the safe header survived");
    /* Content-Type is extracted rather than dropped: the engine picks a
     * different one per challenge asset, and losing it would leave the browser
     * sniffing a script as html.
     */
    CHECK(v.content_type && !strcmp(v.content_type, "text/x"),
          "content-type extracted separately");

    /* user_headers is map[string][]string, so this is the form the engine
     * really sends; a bare string is accepted too.
     */
    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":200,"
              "\"user_body_content\":\"x\","
              "\"user_headers\":{\"Content-Type\":[\"application/javascript\"]}}",
              &v, &err), "js content-type as an array: %s", err ? err : "");
    CHECK(v.content_type
          && !strcmp(v.content_type, "application/javascript"),
          "array content-type preserved");
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_headers\":{\"Content-Type\":[\"a/b\",\"c/d\"]}}",
               &v, &err), "two content types refused");

    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":200,"
              "\"user_body_content\":\"x\","
              "\"user_headers\":{\"Content-Type\":\"application/javascript\"}}",
              &v, &err), "js content-type");
    CHECK(v.content_type
          && !strcmp(v.content_type, "application/javascript"),
          "javascript content-type preserved");
    CHECK(v.nheaders == 0, "content-type is not also in the header list");
}

static void test_appsec_bounds(apr_pool_t *p)
{
    crowdsec_appsec_verdict_t v;
    const char *err;
    char big[8192];
    char *json;
    apr_size_t i;

    CHECK(!av(p, "{\"http_status\":200}", &v, &err), "no action refused");
    CHECK(!av(p, "{\"action\":\"ban\"}", &v, &err), "no http_status refused");
    CHECK(!av(p, "{\"action\":\"ban\",\"http_status\":99}", &v, &err),
          "status below 100 refused");
    CHECK(!av(p, "{\"action\":\"ban\",\"http_status\":600}", &v, &err),
          "status above 599 refused");
    CHECK(!av(p, "{\"action\":\"ban\",\"http_status\":\"403\"}", &v, &err),
          "status as a string refused");
    CHECK(!av(p, "{\"action\":1,\"http_status\":403}", &v, &err),
          "action as a number refused");
    CHECK(!av(p, "[]", &v, &err), "array root refused");
    CHECK(!av(p, "", &v, &err), "empty refused");
    CHECK(!av(p, "{", &v, &err), "truncated refused");

    /* An over-long header value must be refused, not truncated. */
    for (i = 0; i < sizeof(big) - 1; i++) {
        big[i] = 'a';
    }
    big[sizeof(big) - 1] = '\0';
    json = apr_psprintf(p, "{\"action\":\"challenge\",\"http_status\":200,"
                        "\"user_body_content\":\"x\","
                        "\"user_headers\":{\"X\":\"%s\"}}", big);
    CHECK(!av(p, json, &v, &err), "over-long header value refused");

    /* Too many cookies. */
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\",\"user_cookies\":"
               "[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"]}",
               &v, &err), "too many cookies refused");

    /* Wrong types inside the collections. */
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\",\"user_cookies\":[1]}",
               &v, &err), "numeric cookie refused");
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_headers\":{\"X\":1}}", &v, &err),
               "numeric header value refused");
    CHECK(!av(p, "{\"action\":\"challenge\",\"http_status\":200,"
               "\"user_body_content\":\"x\","
               "\"user_headers\":[]}", &v, &err),
               "array for user_headers refused");

    /* A body containing a NUL is legal: it is written by length. */
    CHECK(av(p, "{\"action\":\"challenge\",\"http_status\":200,"
              "\"user_body_content\":\"a\\u0000b\"}", &v, &err),
              "NUL in the body is data, not an injection");
    CHECK(v.body_len == 3, "body length counts the NUL");
}

int main(void)
{
    apr_pool_t *p;

    if (apr_initialize() != APR_SUCCESS) {
        printf("Bail out! apr_initialize\n");
        return 1;
    }
    apr_pool_create(&p, NULL);

    test_stream_basic(p);
    test_stream_deleted(p);
    test_stream_rejects(p);
    test_stream_malformed_doc(p);
    test_depth_limit(p);
    test_abort(p);
    test_decisions_any(p);
    test_appsec_basic(p);
    test_appsec_challenge(p);
    test_appsec_injection(p);
    test_appsec_bounds(p);

    apr_terminate();

    if (failures) {
        printf("FAILED: %d\n", failures);
        return 1;
    }
    printf("ok - all verdict tests passed\n");
    return 0;
}
