#include <string.h>

#include "apr.h"
#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "apr_strings.h"

#include "crowdsec_util.h"

/*
 * Apache's scanners live in libhttpd, which a standalone test binary cannot
 * link, so they are reproduced here as tables. tests/t_util.c asserts byte-for
 * -byte agreement with the real ap_scan_* for all 256 single-byte inputs, so
 * these stay honest rather than merely looking right.
 */

/* RFC7230 3.2.6 tchar. */
static const unsigned char tbl_token[256] = {
    ['!'] = 1, ['#'] = 1, ['$'] = 1, ['%'] = 1, ['&'] = 1, ['\''] = 1,
    ['*'] = 1, ['+'] = 1, ['-'] = 1, ['.'] = 1, ['^'] = 1, ['_'] = 1,
    ['`'] = 1, ['|'] = 1, ['~'] = 1,
    ['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1, ['5'] = 1,
    ['6'] = 1, ['7'] = 1, ['8'] = 1, ['9'] = 1,
    ['A'] = 1, ['B'] = 1, ['C'] = 1, ['D'] = 1, ['E'] = 1, ['F'] = 1,
    ['G'] = 1, ['H'] = 1, ['I'] = 1, ['J'] = 1, ['K'] = 1, ['L'] = 1,
    ['M'] = 1, ['N'] = 1, ['O'] = 1, ['P'] = 1, ['Q'] = 1, ['R'] = 1,
    ['S'] = 1, ['T'] = 1, ['U'] = 1, ['V'] = 1, ['W'] = 1, ['X'] = 1,
    ['Y'] = 1, ['Z'] = 1,
    ['a'] = 1, ['b'] = 1, ['c'] = 1, ['d'] = 1, ['e'] = 1, ['f'] = 1,
    ['g'] = 1, ['h'] = 1, ['i'] = 1, ['j'] = 1, ['k'] = 1, ['l'] = 1,
    ['m'] = 1, ['n'] = 1, ['o'] = 1, ['p'] = 1, ['q'] = 1, ['r'] = 1,
    ['s'] = 1, ['t'] = 1, ['u'] = 1, ['v'] = 1, ['w'] = 1, ['x'] = 1,
    ['y'] = 1, ['z'] = 1
};

static int tbl_ready;
static unsigned char tbl_field[256];   /* VCHAR + obs-text + HT + SP */
static unsigned char tbl_vchar[256];   /* VCHAR + obs-text          */

static void tbl_init(void)
{
    int c;

    for (c = 0x21; c <= 0x7e; c++) {    /* VCHAR */
        tbl_field[c] = 1;
        tbl_vchar[c] = 1;
    }
    for (c = 0x80; c <= 0xff; c++) {    /* obs-text */
        tbl_field[c] = 1;
        tbl_vchar[c] = 1;
    }
    tbl_field['\t'] = 1;
    tbl_field[' '] = 1;

    tbl_ready = 1;
}

/* Racing here is harmless: every writer computes the same bytes, and the
 * values only ever go 0 -> 1. Avoids needing a mutex or a child_init hook for
 * something this small.
 */
static void tbl_need(void)
{
    if (!tbl_ready) {
        tbl_init();
    }
}

static int scan_all(const char *s, const unsigned char *tbl)
{
    const unsigned char *p = (const unsigned char *) s;

    if (!s) {
        return 0;
    }
    while (*p) {
        if (!tbl[*p]) {
            return 0;
        }
        p++;
    }
    return 1;
}

int crowdsec_hdr_name_ok(const char *s)
{
    return scan_all(s, tbl_token);
}

int crowdsec_hdr_value_ok(const char *s)
{
    tbl_need();
    return scan_all(s, tbl_field);
}

int crowdsec_target_ok(const char *s)
{
    tbl_need();
    return scan_all(s, tbl_vchar);
}

const char *crowdsec_http_version_hdr(int proto_num)
{
    /* A switch, not arithmetic: HTTP_VERSION packs as 1000*major+minor, so
     * major*10+minor would render 1010 (a hypothetical HTTP/1.10) as "110".
     * The header is specified as exactly two digits, so anything without a
     * two-digit spelling is omitted instead of mangled.
     */
    switch (proto_num) {
    case 1000:
        return "10";
    case 1001:
        return "11";
    case 2000:
        return "20";
    case 3000:
        return "30";
    default:
        return NULL;
    }
}

int crowdsec_parse_size(const char *s, apr_off_t *out)
{
    apr_off_t v, mul = 1;
    char *end;

    if (!s || !*s || !out) {
        return 0;
    }
    /* apr_strtoff happily accepts leading whitespace and a sign; neither
     * belongs in a size, and "-0" would otherwise sneak past the v < 0 test.
     */
    if (*s < '0' || *s > '9') {
        return 0;
    }
    if (apr_strtoff(&v, s, &end, 10) != APR_SUCCESS || v < 0) {
        return 0;
    }

    switch (*end) {
    case 'k':
    case 'K':
        mul = 1024;
        end++;
        break;
    case 'm':
    case 'M':
        mul = 1024 * 1024;
        end++;
        break;
    case 'g':
    case 'G':
        mul = 1024 * 1024 * 1024;
        end++;
        break;
    case '\0':
        break;
    default:
        return 0;
    }
    if (*end) {
        return 0;
    }

    /* Divide rather than multiply, so the check cannot itself overflow. */
    if (v > CROWDSEC_SIZE_CEILING / mul) {
        return 0;
    }
    *out = v * mul;

    return 1;
}

int crowdsec_body_take(apr_off_t used, apr_size_t chunk, apr_off_t cap,
                       apr_size_t *take)
{
    apr_off_t room;

    if (!take) {
        return 0;
    }
    *take = 0;

    if (used < 0 || cap < 0 || used >= cap) {
        return 0;
    }
    /* Never used + chunk: that is the overflow. */
    room = cap - used;
    *take = ((apr_off_t) chunk > room) ? (apr_size_t) room : chunk;

    return *take > 0;
}

static int parse_plen(const char *s, int max, int *out)
{
    int v = 0;
    int digits = 0;

    if (!*s) {
        return 0;
    }
    /* Reject a leading zero outright, so one prefix length has exactly one
     * spelling and "/024" cannot quietly become "/24".
     */
    if (s[0] == '0' && s[1] != '\0') {
        return 0;
    }
    for (; *s; s++) {
        if (*s < '0' || *s > '9') {
            return 0;
        }
        /* Three digits is enough for 128 and keeps v from running away. */
        if (++digits > 3) {
            return 0;
        }
        v = v * 10 + (*s - '0');
    }
    if (v > max) {
        return 0;
    }
    *out = v;

    return 1;
}

int crowdsec_cidr_parse(const char *s, crowdsec_net_t *out)
{
    char buf[46 + 1];           /* longest INET6_ADDRSTRLEN plus NUL */
    const char *slash;
    apr_size_t alen;
    crowdsec_net_t n;
    int max;

    if (!s || !out) {
        return 0;
    }
    memset(&n, 0, sizeof(n));

    slash = strchr(s, '/');
    alen = slash ? (apr_size_t) (slash - s) : strlen(s);
    if (alen == 0 || alen >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, s, alen);
    buf[alen] = '\0';

    /* A ':' anywhere means v6. POSIX inet_pton is strict about the rest -- it
     * is what rejects "1.2.3.4.5", "10.0.0.256" and leading zeros, so one
     * network cannot arrive under two spellings.
     */
    if (strchr(buf, ':')) {
        n.family = 6;
        max = 128;
        if (inet_pton(AF_INET6, buf, n.addr) != 1) {
            return 0;
        }
    }
    else {
        n.family = 4;
        max = 32;
        if (inet_pton(AF_INET, buf, n.addr) != 1) {
            return 0;
        }
    }

    if (slash) {
        if (!parse_plen(slash + 1, max, &n.plen)) {
            return 0;
        }
    }
    else {
        n.plen = max;
    }

    /* Hand back the network, not whatever host bits came in, so two spellings
     * of the same network produce one key.
     */
    crowdsec_ip_mask(&n, n.plen, out);

    return 1;
}

void crowdsec_ip_mask(const crowdsec_net_t *in, int plen, crowdsec_net_t *out)
{
    int width, full, rem, i;

    if (!in || !out) {
        return;
    }
    width = (in->family == 6) ? 16 : 4;

    if (plen < 0) {
        plen = 0;
    }
    if (plen > width * 8) {
        plen = width * 8;
    }

    memset(out, 0, sizeof(*out));
    out->family = in->family;
    out->plen = plen;

    full = plen / 8;
    rem = plen % 8;
    memcpy(out->addr, in->addr, (apr_size_t) full);
    if (rem) {
        out->addr[full] = in->addr[full] & (unsigned char) (0xff << (8 - rem));
    }
    for (i = full + (rem ? 1 : 0); i < width; i++) {
        out->addr[i] = 0;
    }
}

apr_size_t crowdsec_key_encode(const crowdsec_net_t *n, unsigned char *buf,
                               apr_size_t buflen)
{
    apr_size_t width, len;

    if (!n || !buf) {
        return 0;
    }
    width = (n->family == 6) ? 16 : 4;
    len = 2 + width;            /* family, plen, network */

    if (buflen < len) {
        return 0;
    }
    buf[0] = (unsigned char) n->family;
    buf[1] = (unsigned char) n->plen;
    memcpy(buf + 2, n->addr, width);

    return len;
}

crowdsec_rem_t crowdsec_rem_merge(crowdsec_rem_t a, crowdsec_rem_t b)
{
    return (a > b) ? a : b;
}

crowdsec_rem_t crowdsec_action_to_rem(const char *action)
{
    if (!action) {
        return CROWDSEC_REM_UNKNOWN;
    }
    if (!strcmp(action, "allow")) {
        return CROWDSEC_REM_ALLOW;
    }
    if (!strcmp(action, "ban")) {
        return CROWDSEC_REM_BAN;
    }
    if (!strcmp(action, "captcha")) {
        return CROWDSEC_REM_CAPTCHA;
    }
    if (!strcmp(action, "challenge")) {
        return CROWDSEC_REM_CHALLENGE;
    }
    /* default_remediation and SetAction accept arbitrary strings, so an
     * unknown action is expected, not a protocol error.
     */
    return CROWDSEC_REM_UNKNOWN;
}
