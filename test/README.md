# Functional tests

Each test starts a throwaway Apache instance and a stub LAPI on free ports, both
under a temp dir that is removed on success. Set `HARNESS_KEEP=1` to keep the
tree (config, error log) for inspection after a failure.

Build the module first — the harness loads `.libs/mod_crowdsec.so`:

```
apxs -c mod_crowdsec.c
```

Then run a file, or the whole directory:

```
bats test/bats/
```

`bats` is not packaged on all distros. If it is not on `PATH`, point at a
checkout — the crowdsec engine repo vendors one as a submodule:

```
/path/to/crowdsec/test/lib/bats-core/bin/bats test/bats/
```

Requires `apache2` plus, in `/usr/lib/apache2/modules`, `mod_mpm_prefork`,
`mod_mpm_event`, `mod_authz_core`, `mod_dir` and `mod_socache_shmcb`;
`mod_proxy`, `mod_proxy_http` and `mod_rewrite` for the gating tests; and
`mod_alias`, `mod_headers`, `mod_auth_basic`, `mod_authn_core`,
`mod_authn_file` and `mod_authz_user` for the regression tests. All ship in the
`apache2` package. `python3` runs the stub API and the port probing.

## What is covered

| file | what it exercises |
|---|---|
| `blocked-http-code.bats` | the unset-default bug: a banned address must be blocked without `CrowdsecBlockedHTTPCode` |
| `scan-conformance.bats` | the header sanitiser tables against Apache's own `ap_scan_*` |
| `http-client.bats` | the libcurl layer: response ceiling, timeouts, closed port, handle reuse, `http_proxy` immunity |
| `live-mode.bats` | per-request queries, the shared verdict cache, and every `CrowdsecFallback` value |
| `stream-mode.bats` | background polling, ranges, deletion, expiry, the unprimed window |
| `limits.bats` | cache too small, 100000 decisions, IPv6, many prefix lengths, malformed input, leader takeover |
| `appsec.bats` | what is forwarded for inspection, each verdict, failure handling |
| `challenge.bats` | relaying the interstitial, cookies, headers, the internal endpoints, failing closed |
| `appsec-body.bats` | body inspection and replay, the limit, drop vs bypass, chunked, gzip, LimitRequestBody |
| `gating.bats` | which requests reach the lookup: reverse proxy, internal redirects, vhosts inheriting the cache |
| `regressions.bats` | the issues 0.1 left open: basic auth, redirects, ProxyPreserveHost, the user agent |

Both MPMs are covered; `HARNESS_MPM=event` switches, and tests needing several
child processes use `mpm_many_children` so the directives are spelled correctly
for whichever MPM is active.

```
HARNESS_MPM=event bats test/bats/
```

Set `HARNESS_LOGLEVEL` to raise Apache's log level, e.g.
`HARNESS_LOGLEVEL="info socache_shmcb:trace5"` when investigating the cache.

Set `MODULE` to test a build other than `.libs/mod_crowdsec.so`. That is how a
regression gets confirmed: a test in `regressions.bats` that passes against the
version which had the bug is testing nothing, so replay it against that build
and watch it fail first.

```
git archive v0.1 | tar -x -C /tmp/v01
(cd /tmp/v01 && apxs2 -c -o mod_crowdsec.la mod_crowdsec.c)
MODULE=/tmp/v01/.libs/mod_crowdsec.so bats test/bats/regressions.bats
```

0.1 has no `CrowdsecMode` and no `CrowdsecLocalCacheTimeout`, so Apache rejects
the config `regr_conf` writes; drop those two lines to replay a case against
it.

## Testing against a real engine

The stubs implement the protocol as documented, which is not the same as
implementing it as the engine really behaves. Point the module at a real
crowdsec instead:

```
cscli bouncers add apache-test -o raw        # the key
cscli decisions add --ip 127.0.0.1 --duration 10m
cscli decisions add --range 127.0.0.0/24 --duration 10m
```

A run against a live engine holding 145000 real decisions confirmed the stream
protocol, range matching, deletion within one poll, and the 16MB sizing figure
above.

For AppSec, point `CrowdsecAppsecURL` at a real appsec datasource. With the
`crowdsecurity/appsec-bot-challenge` collection installed, a plain `curl` to a
challenged path gets the real interstitial — around 318KB — and
`/crowdsec-internal/challenge/pow-worker.js` and `fpscanner.js` are served from
the engine. Two things cannot be checked without a browser that can compute the
proof of work: the cookie the engine mints on a successful submission, and the
request that follows it. Those are covered against the stub, where a solve can
be simulated.

## Unit tests

`test/unit/t_util.c` covers the pure helpers in `crowdsec_util.c` and links only
apr, so it runs without a server:

```
gcc -Wall -Wextra -Werror -g -fsanitize=address,undefined \
    $(pkg-config --cflags apr-1) -I. test/unit/t_util.c crowdsec_util.c \
    $(pkg-config --libs apr-1) -o t_util && ./t_util
```

`test/unit/mod_scan_conformance.c` is a test-only Apache module. The header
sanitisers are reimplemented locally because Apache's `ap_scan_*` live in
the httpd binary rather than a shared library, so they cannot be linked from a
standalone test. This module runs inside the server and asserts the
reimplementations agree with the real functions for every byte; `test/bats/scan-conformance.bats` drives
it. Build it with:

```
apxs -c -I. -o test/unit/mod_scan_conformance.la \
    test/unit/mod_scan_conformance.c crowdsec_util.c
```

Both will move under `make check` when the build changes land.

## Fuzzing

The JSON parsers and the header sanitisers have libFuzzer targets under
`fuzz/`, with post-conditions rather than bare crash checks. They need clang
and are not part of `make check` or CI. See `fuzz/README.md`.
