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

/* must be last: see the file for why */
#include "crowdsec_poison.h"

/*
 * Apache's scanners live in libhttpd, which a standalone test binary cannot
 * link, so they are reproduced here. test/unit/mod_scan_conformance.c asserts
 * byte-for-byte agreement with the real ap_scan_* for all 256 single-byte
 * inputs, so these stay honest rather than merely looking right.
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

/* Unlike tchar, these two are contiguous ranges, so they are predicates rather
 * than tables. A table would have to be built at runtime, and publishing it
 * from one thread without a barrier is a data race: another thread can see the
 * ready flag before the bytes, read an all-zero table, and reject a valid
 * header.
 */
static int is_vchar_obstext(unsigned char c)
{
    return (c >= 0x21 && c <= 0x7e) || c >= 0x80;
}

static int is_field_content(unsigned char c)
{
    return is_vchar_obstext(c) || c == '\t' || c == ' ';
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

static int scan_all_pred(const char *s, int (*ok)(unsigned char))
{
    const unsigned char *p = (const unsigned char *) s;

    if (!s) {
        return 0;
    }
    while (*p) {
        if (!ok(*p)) {
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
    return scan_all_pred(s, is_field_content);
}

int crowdsec_target_ok(const char *s)
{
    return scan_all_pred(s, is_vchar_obstext);
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
    /* Never used + chunk: that is the overflow. The comparison is unsigned
     * because chunk is, and a value above the signed maximum would cast to a
     * negative apr_off_t, compare below room, and hand back the whole chunk -
     * defeating the cap this function exists to enforce.
     */
    room = cap - used;
    *take = ((apr_uint64_t) chunk > (apr_uint64_t) room)
        ? (apr_size_t) room : chunk;

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
    apr_size_t width, len, i;
    unsigned int h = 2166136261u;

    if (!n || !buf) {
        return 0;
    }
    width = (n->family == 6) ? 16 : 4;
    len = 3 + width;            /* spread, family, plen, network */

    if (buflen < len) {
        return 0;
    }
    buf[1] = (unsigned char) n->family;
    buf[2] = (unsigned char) n->plen;
    memcpy(buf + 3, n->addr, width);

    /* FNV-1a over the meaningful bytes. Derived from them, so a lookup
     * recomputes the same leading byte.
     */
    for (i = 1; i < len; i++) {
        h = (h ^ buf[i]) * 16777619u;
    }
    /* The whole byte range is available: mod_socache_shmcb picks a subcache
     * with first_byte & (subcache_num - 1), so reserving a single value never
     * isolated anything anyway, and the control state no longer lives here.
     */
    buf[0] = (unsigned char) (h & 0xffu);

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

/* Go's unit table, longest first so "ms" is not read as "m" followed by junk.
 * "µs" appears as both U+00B5 and U+03BC in Go's own output.
 */
static const struct
{
    const char *unit;
    apr_size_t len;
    apr_interval_time_t usec;
} duration_units[] = {
    { "ns", 2, 0 },             /* below our resolution; contributes nothing */
    { "us", 2, 1 },
    { "\xc2\xb5s", 3, 1 },      /* U+00B5 MICRO SIGN */
    { "\xce\xbcs", 3, 1 },      /* U+03BC GREEK SMALL LETTER MU */
    { "ms", 2, 1000 },
    { "s", 1, APR_USEC_PER_SEC },
    { "m", 1, APR_TIME_C(60) * APR_USEC_PER_SEC },
    { "h", 1, APR_TIME_C(3600) * APR_USEC_PER_SEC }
};

int crowdsec_parse_duration(const char *s, apr_interval_time_t *out)
{
    apr_interval_time_t total = 0;
    int negative = 0;
    int groups = 0;

    if (!s || !out) {
        return 0;
    }
    if (*s == '-') {
        negative = 1;
        s++;
    }
    else if (*s == '+') {
        s++;
    }
    /* Go spells a zero duration "0s", but bare "0" shows up in hand-written
     * config, so accept it.
     */
    if (!strcmp(s, "0")) {
        *out = 0;
        return 1;
    }
    if (!*s) {
        return 0;
    }

    while (*s) {
        apr_interval_time_t whole = 0, scaled;
        apr_interval_time_t frac_num = 0, frac_den = 1;
        int digits = 0;
        unsigned u;

        for (; *s >= '0' && *s <= '9'; s++) {
            if (whole <= CROWDSEC_DURATION_MAX) {
                whole = whole * 10 + (*s - '0');
            }
            /* Past the clamp the magnitude no longer matters, but keep
             * consuming digits so the syntax check still sees the whole token.
             */
            digits++;
        }
        if (*s == '.') {
            s++;
            for (; *s >= '0' && *s <= '9'; s++) {
                /* Keep at most 6 fractional digits: more cannot affect a
                 * microsecond result.
                 */
                if (frac_den < 1000000) {
                    frac_num = frac_num * 10 + (*s - '0');
                    frac_den *= 10;
                }
                digits++;
            }
        }
        if (!digits) {
            return 0;
        }

        for (u = 0; u < sizeof(duration_units) / sizeof(duration_units[0]);
             u++) {
            if (!strncmp(s, duration_units[u].unit, duration_units[u].len)) {
                break;
            }
        }
        if (u == sizeof(duration_units) / sizeof(duration_units[0])) {
            return 0;           /* missing or unknown unit */
        }
        s += duration_units[u].len;

        if (duration_units[u].usec == 0) {
            groups++;           /* ns: valid, but rounds away */
            continue;
        }
        /* Saturate rather than fail. Rejecting an absurd duration would make
         * the caller drop the decision, and dropping a ban fails open; an
         * over-long ban is merely treated as permanent, which it effectively
         * is. Genuine syntax errors are still rejected above.
         */
        if (whole > CROWDSEC_DURATION_MAX / duration_units[u].usec) {
            total = CROWDSEC_DURATION_MAX;
            groups++;
            continue;
        }
        scaled = whole * duration_units[u].usec;
        if (frac_den > 1) {
            scaled += (frac_num * duration_units[u].usec) / frac_den;
        }
        if (total > CROWDSEC_DURATION_MAX - scaled) {
            total = CROWDSEC_DURATION_MAX;
        }
        else {
            total += scaled;
        }
        groups++;
    }

    if (!groups) {
        return 0;
    }
    if (total > CROWDSEC_DURATION_MAX) {
        total = CROWDSEC_DURATION_MAX;
    }
    *out = negative ? -total : total;

    return 1;
}
