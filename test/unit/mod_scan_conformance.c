/* Test-only module: asserts crowdsec_util's byte tables agree with Apache's
 * own ap_scan_* for every single-byte input plus a multi-byte corpus.
 *
 * ap_scan_* live in the httpd binary rather than a shared library, so this
 * cannot be a standalone test binary - it has to run inside the server.
 * test/bats/scan-conformance.bats loads it and greps the result.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "crowdsec_util.h"

module AP_MODULE_DECLARE_DATA scan_conformance_module;

static int cmp(server_rec *s, const char *what, const char *in, int len,
               int ours, int theirs)
{
    if (ours == theirs) {
        return 0;
    }
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                 "SCANCONF MISMATCH %s len=%d byte0=0x%02x ours=%d theirs=%d",
                 what, len, (unsigned char) in[0], ours, theirs);
    return 1;
}

static int check(server_rec *s, const char *in, int len)
{
    int bad = 0;

    bad += cmp(s, "token", in, len, crowdsec_hdr_name_ok(in),
               *ap_scan_http_token(in) == '\0');
    bad += cmp(s, "field", in, len, crowdsec_hdr_value_ok(in),
               *ap_scan_http_field_content(in) == '\0');
    bad += cmp(s, "vchar", in, len, crowdsec_target_ok(in),
               *ap_scan_vchar_obstext(in) == '\0');

    return bad;
}

static int conf_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *s)
{
    static const char *corpus[] = {
        "", "a", "Content-Type", "text/html; charset=utf-8",
        "/a?b=c", "/%2e%2e%2f", "caf\xc3\xa9", "a b\tc",
        "a\r\nb", "x\x7f" "y", "\x80\xff", "!#$%&'*+-.^_`|~",
        "a\rb", "a\nb", "a\x0b" "b", "  ", "\t", " ",
        NULL
    };
    char one[2];
    int c, bad = 0, i;

    /* every single byte, 0x01..0xff; 0x00 would just be the empty string */
    one[1] = '\0';
    for (c = 1; c <= 0xff; c++) {
        one[0] = (char) c;
        bad += check(s, one, 1);
    }
    for (i = 0; corpus[i]; i++) {
        bad += check(s, corpus[i], (int) strlen(corpus[i]));
    }

    if (bad) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SCANCONF FAIL %d mismatches", bad);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "SCANCONF PASS");
    }

    return OK;
}

static void conf_hooks(apr_pool_t *p)
{
    ap_hook_post_config(conf_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(scan_conformance) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, conf_hooks
};
