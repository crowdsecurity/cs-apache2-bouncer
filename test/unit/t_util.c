/* Unit tests for the pure helpers. Links apr only, no httpd, so it runs
 * anywhere. The ap_scan_* conformance check lives in tests/t_scan.c, which is
 * built against httpd.
 */
#include <stdio.h>
#include <string.h>

#include "apr_general.h"

#include "crowdsec_util.h"

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

static void test_hdr_name(void)
{
    struct { const char *in; int want; } t[] = {
        { "Content-Type", 1 }, { "X-Crowdsec-Appsec-Ip", 1 },
        { "a", 1 }, { "", 1 },
        /* the injection cases this exists for */
        { "X\rY", 0 }, { "X\nY", 0 }, { "X\r\nY", 0 },
        { "X Y", 0 },            /* SP is not a tchar */
        { "X:Y", 0 }, { "X\tY", 0 },
        { "!#$%&'*+-.^_`|~", 1 },  /* every permitted special */
        { "X(Y", 0 }, { "X@Y", 0 }, { "X,Y", 0 }, { "X\"Y", 0 },
        { "X/Y", 0 }, { "X[Y", 0 }, { "X{Y", 0 }, { "X?Y", 0 },
        { "X\x7f" "Y", 0 },      /* DEL is a ctrl */
        { "X\x80" "Y", 0 },      /* obs-text is not a tchar */
    };
    unsigned i;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        CHECK(crowdsec_hdr_name_ok(t[i].in) == t[i].want,
              "hdr_name_ok(%s)", t[i].in);
    }
    CHECK(crowdsec_hdr_name_ok(NULL) == 0, "hdr_name_ok(NULL)");
}

static void test_hdr_value(void)
{
    struct { const char *in; int want; } t[] = {
        { "text/html", 1 }, { "", 1 },
        { "a b\tc", 1 },                 /* SP and HT are allowed */
        { "caf\xc3\xa9", 1 },            /* obs-text */
        { "x\x80\xff" "y", 1 },
        { "a\rb", 0 }, { "a\nb", 0 }, { "a\r\nb", 0 },
        { "a\x7f" "b", 0 },              /* DEL */
        { "a\x01" "b", 0 },
        { "a\x0b" "b", 0 },              /* VT is a ctrl, unlike HT */
    };
    unsigned i;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        CHECK(crowdsec_hdr_value_ok(t[i].in) == t[i].want,
              "hdr_value_ok(%s)", t[i].in);
    }
    CHECK(crowdsec_hdr_value_ok(NULL) == 0, "hdr_value_ok(NULL)");
}

static void test_target(void)
{
    struct { const char *in; int want; } t[] = {
        { "/", 1 }, { "/a?b=c", 1 }, { "/%2e%2e%2f", 1 }, { "", 1 },
        { "/a b", 0 },                   /* SP terminates a request target */
        { "/a\tb", 0 },                  /* HT is not vchar */
        { "/a\rb", 0 }, { "/a\nb", 0 },
        { "/\x80", 1 },                  /* obs-text is permitted */
        { "/a\x7f", 0 },
    };
    unsigned i;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        CHECK(crowdsec_target_ok(t[i].in) == t[i].want,
              "target_ok(%s)", t[i].in);
    }
}

static void test_version(void)
{
    CHECK(crowdsec_http_version_hdr(1000) &&
          !strcmp(crowdsec_http_version_hdr(1000), "10"), "1000");
    CHECK(crowdsec_http_version_hdr(1001) &&
          !strcmp(crowdsec_http_version_hdr(1001), "11"), "1001");
    CHECK(crowdsec_http_version_hdr(2000) &&
          !strcmp(crowdsec_http_version_hdr(2000), "20"), "2000");
    CHECK(crowdsec_http_version_hdr(3000) &&
          !strcmp(crowdsec_http_version_hdr(3000), "30"), "3000");
    /* HTTP/0.9, and the case that makes arithmetic wrong: 1010 would render
     * as "110" if we did major*10+minor.
     */
    CHECK(crowdsec_http_version_hdr(9) == NULL, "0.9 omitted");
    CHECK(crowdsec_http_version_hdr(1010) == NULL, "1010 omitted");
    CHECK(crowdsec_http_version_hdr(0) == NULL, "0 omitted");
    CHECK(crowdsec_http_version_hdr(-1) == NULL, "negative omitted");
}

static void test_size(void)
{
    apr_off_t v;

    struct { const char *in; int ok; apr_off_t want; } t[] = {
        { "0", 1, 0 }, { "1", 1, 1 }, { "1024", 1, 1024 },
        { "1k", 1, 1024 }, { "1K", 1, 1024 },
        { "1m", 1, 1048576 }, { "1M", 1, 1048576 },
        { "64m", 1, 67108864 },          /* exactly the ceiling */
        { "1g", 0, 0 },                  /* over the ceiling */
        { "65m", 0, 0 },
        { "", 0, 0 }, { "k", 0, 0 }, { "-1", 0, 0 }, { "-0", 0, 0 },
        { " 1", 0, 0 },                  /* no leading space */
        { "+1", 0, 0 },
        { "1x", 0, 0 }, { "1kk", 0, 0 }, { "1k2", 0, 0 },
        { "abc", 0, 0 },
        /* would overflow a 64-bit multiply if checked the naive way */
        { "9223372036854775807", 0, 0 },
        { "99999999999999999999", 0, 0 },
    };
    unsigned i;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        v = -1;
        CHECK(crowdsec_parse_size(t[i].in, &v) == t[i].ok,
              "parse_size(%s) ok", t[i].in);
        if (t[i].ok) {
            CHECK(v == t[i].want, "parse_size(%s) = %" APR_OFF_T_FMT,
                  t[i].in, v);
        }
    }
    CHECK(crowdsec_parse_size("1", NULL) == 0, "parse_size NULL out");
    CHECK(crowdsec_parse_size(NULL, &v) == 0, "parse_size NULL in");
}

static void test_body_take(void)
{
    apr_size_t take;

    CHECK(crowdsec_body_take(0, 100, 1000, &take) && take == 100, "room");
    CHECK(crowdsec_body_take(950, 100, 1000, &take) && take == 50, "partial");
    CHECK(!crowdsec_body_take(1000, 100, 1000, &take) && take == 0, "at cap");
    CHECK(!crowdsec_body_take(1001, 100, 1000, &take) && take == 0, "over cap");
    CHECK(!crowdsec_body_take(0, 100, 0, &take) && take == 0, "zero cap");
    CHECK(!crowdsec_body_take(-1, 100, 1000, &take), "negative used");
    CHECK(!crowdsec_body_take(0, 100, -1, &take), "negative cap");
    CHECK(!crowdsec_body_take(0, 0, 1000, &take) && take == 0, "zero chunk");
    /* The reason this helper exists: used+chunk overflows, cap-used does not */
    CHECK(crowdsec_body_take(APR_INT64_C(0x7ffffffffffffff0), 100,
                             APR_INT64_C(0x7ffffffffffffff8), &take)
          && take == 8, "no overflow near max");
}

static void test_cidr(void)
{
    crowdsec_net_t n;

    /* v4 host */
    CHECK(crowdsec_cidr_parse("1.2.3.4", &n), "v4 host parses");
    CHECK(n.family == 4 && n.plen == 32, "v4 host defaults to /32");
    CHECK(n.addr[0] == 1 && n.addr[3] == 4, "v4 host bytes");

    /* v4 network, host bits must be cleared */
    CHECK(crowdsec_cidr_parse("10.1.2.3/24", &n), "v4 cidr parses");
    CHECK(n.plen == 24 && n.addr[0] == 10 && n.addr[1] == 1
          && n.addr[2] == 2 && n.addr[3] == 0, "v4 /24 masked");

    CHECK(crowdsec_cidr_parse("10.1.2.3/0", &n) && n.plen == 0
          && n.addr[0] == 0 && n.addr[3] == 0, "v4 /0 masked to zero");

    /* non-byte-aligned prefix */
    CHECK(crowdsec_cidr_parse("192.168.1.130/25", &n) && n.addr[3] == 128,
          "v4 /25 keeps the top bit of the last octet");
    CHECK(crowdsec_cidr_parse("10.0.0.255/31", &n) && n.addr[3] == 254,
          "v4 /31");

    /* v6 */
    CHECK(crowdsec_cidr_parse("::1", &n) && n.family == 6 && n.plen == 128,
          "v6 host defaults to /128");
    CHECK(crowdsec_cidr_parse("2001:db8::1/32", &n) && n.plen == 32
          && n.addr[0] == 0x20 && n.addr[1] == 0x01
          && n.addr[2] == 0x0d && n.addr[3] == 0xb8
          && n.addr[4] == 0 && n.addr[15] == 0, "v6 /32 masked");

    /* two spellings of one network must land on one key */
    {
        crowdsec_net_t a, b;
        unsigned char ka[CROWDSEC_KEY_MAX], kb[CROWDSEC_KEY_MAX];
        apr_size_t la, lb;

        CHECK(crowdsec_cidr_parse("10.0.0.0/24", &a), "a");
        CHECK(crowdsec_cidr_parse("10.0.0.77/24", &b), "b");
        la = crowdsec_key_encode(&a, ka, sizeof(ka));
        lb = crowdsec_key_encode(&b, kb, sizeof(kb));
        CHECK(la == lb && la > 0 && !memcmp(ka, kb, la),
              "10.0.0.0/24 and 10.0.0.77/24 encode identically");
    }

    /* prefix length out of range for the family -- must never alias */
    CHECK(!crowdsec_cidr_parse("1.2.3.4/33", &n), "v4 /33 rejected");
    CHECK(!crowdsec_cidr_parse("::1/129", &n), "v6 /129 rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3.4/-1", &n), "negative plen rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3.4/", &n), "empty plen rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3.4/024", &n), "leading-zero plen rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3.4/2x", &n), "junk plen rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3.4/1/2", &n), "double slash rejected");

    /* malformed addresses */
    CHECK(!crowdsec_cidr_parse("10.0.0.256", &n), "octet > 255 rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3.4.5", &n), "five octets rejected");
    CHECK(!crowdsec_cidr_parse("1.2.3", &n), "three octets rejected");
    CHECK(!crowdsec_cidr_parse("", &n), "empty rejected");
    CHECK(!crowdsec_cidr_parse("/24", &n), "no address rejected");
    CHECK(!crowdsec_cidr_parse("not-an-ip", &n), "garbage rejected");
    CHECK(!crowdsec_cidr_parse("2001:db8:::1", &n), "bad v6 rejected");
    CHECK(!crowdsec_cidr_parse(NULL, &n), "NULL rejected");
    {
        /* longer than any address, must not run off the stack buffer */
        char big[200];
        memset(big, '1', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        CHECK(!crowdsec_cidr_parse(big, &n), "overlong input rejected");
    }
}

static void test_key_encode(void)
{
    crowdsec_net_t n;
    unsigned char buf[CROWDSEC_KEY_MAX];
    apr_size_t len;

    CHECK(crowdsec_cidr_parse("1.2.3.4", &n), "parse");
    len = crowdsec_key_encode(&n, buf, sizeof(buf));
    CHECK(len == 6, "v4 key is 6 bytes");
    /* shmcb rejects keys under 4 bytes; the shortest we can emit is 6 */
    CHECK(len >= 4, "v4 key clears the shmcb minimum");
    CHECK(buf[0] == 4 && buf[1] == 32, "v4 key header");

    CHECK(crowdsec_cidr_parse("::1", &n), "parse v6");
    len = crowdsec_key_encode(&n, buf, sizeof(buf));
    CHECK(len == 18, "v6 key is 18 bytes");
    CHECK(len <= CROWDSEC_KEY_MAX, "v6 key fits CROWDSEC_KEY_MAX");
    CHECK(buf[0] == 6 && buf[1] == 128, "v6 key header");

    /* families must not collide even with identical trailing bytes */
    {
        crowdsec_net_t a, b;
        unsigned char ka[CROWDSEC_KEY_MAX], kb[CROWDSEC_KEY_MAX];
        apr_size_t la, lb;

        CHECK(crowdsec_cidr_parse("0.0.0.0/0", &a), "v4 any");
        CHECK(crowdsec_cidr_parse("::/0", &b), "v6 any");
        la = crowdsec_key_encode(&a, ka, sizeof(ka));
        lb = crowdsec_key_encode(&b, kb, sizeof(kb));
        CHECK(!(la == lb && !memcmp(ka, kb, la)), "v4 and v6 keys differ");
    }

    CHECK(crowdsec_key_encode(&n, buf, 4) == 0, "short buffer refused");
    CHECK(crowdsec_key_encode(NULL, buf, sizeof(buf)) == 0, "NULL net");
    CHECK(crowdsec_key_encode(&n, NULL, sizeof(buf)) == 0, "NULL buf");
}

static void test_rem(void)
{
    CHECK(crowdsec_action_to_rem("allow") == CROWDSEC_REM_ALLOW, "allow");
    CHECK(crowdsec_action_to_rem("ban") == CROWDSEC_REM_BAN, "ban");
    CHECK(crowdsec_action_to_rem("captcha") == CROWDSEC_REM_CAPTCHA, "captcha");
    CHECK(crowdsec_action_to_rem("challenge") == CROWDSEC_REM_CHALLENGE, "chal");
    /* admin-defined actions are legal and must not be mistaken for allow */
    CHECK(crowdsec_action_to_rem("log") == CROWDSEC_REM_UNKNOWN, "log");
    CHECK(crowdsec_action_to_rem("") == CROWDSEC_REM_UNKNOWN, "empty");
    CHECK(crowdsec_action_to_rem("ALLOW") == CROWDSEC_REM_UNKNOWN, "case");
    CHECK(crowdsec_action_to_rem("allow ") == CROWDSEC_REM_UNKNOWN, "trailing");
    CHECK(crowdsec_action_to_rem(NULL) == CROWDSEC_REM_UNKNOWN, "NULL");

    /* severity order is the merge policy */
    CHECK(crowdsec_rem_merge(CROWDSEC_REM_ALLOW, CROWDSEC_REM_BAN)
          == CROWDSEC_REM_BAN, "allow+ban");
    CHECK(crowdsec_rem_merge(CROWDSEC_REM_BAN, CROWDSEC_REM_ALLOW)
          == CROWDSEC_REM_BAN, "ban+allow commutes");
    CHECK(crowdsec_rem_merge(CROWDSEC_REM_CAPTCHA, CROWDSEC_REM_CHALLENGE)
          == CROWDSEC_REM_CHALLENGE, "challenge beats captcha");
    CHECK(crowdsec_rem_merge(CROWDSEC_REM_CHALLENGE, CROWDSEC_REM_BAN)
          == CROWDSEC_REM_BAN, "ban beats challenge");
    CHECK(crowdsec_rem_merge(CROWDSEC_REM_ALLOW, CROWDSEC_REM_UNKNOWN)
          == CROWDSEC_REM_UNKNOWN, "unknown beats allow");
}

int main(void)
{
    if (apr_initialize() != APR_SUCCESS) {
        printf("Bail out! apr_initialize failed\n");
        return 1;
    }
    test_hdr_name();
    test_hdr_value();
    test_target();
    test_version();
    test_size();
    test_body_take();
    test_cidr();
    test_key_encode();
    test_rem();
    apr_terminate();

    if (failures) {
        printf("FAILED: %d\n", failures);
        return 1;
    }
    printf("ok - all util tests passed\n");
    return 0;
}
