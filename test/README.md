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

Requires `apache2` plus `mod_mpm_prefork`, `mod_mpm_event`, `mod_authz_core`,
`mod_dir` and `mod_socache_shmcb` in `/usr/lib/apache2/modules`, and `python3`
for the stub API and port probing.

## What is covered

| file | what it exercises |
|---|---|
| `blocked-http-code.bats` | the unset-default bug: a banned address must be blocked without `CrowdsecBlockedHTTPCode` |
| `scan-conformance.bats` | the header sanitiser tables against Apache's own `ap_scan_*` |
| `http-client.bats` | the libcurl layer: response ceiling, timeouts, closed port, handle reuse, `http_proxy` immunity |
| `live-mode.bats` | per-request queries, the shared verdict cache, and every `CrowdsecFallback` value |
| `stream-mode.bats` | background polling, ranges, deletion, expiry, the unprimed window |
| `limits.bats` | cache too small, 100000 decisions, IPv6, many prefix lengths, malformed input, leader takeover |

Both MPMs are covered; `HARNESS_MPM=event` switches, and tests needing several
child processes use `mpm_many_children` so the directives are spelled correctly
for whichever MPM is active.

```
HARNESS_MPM=event bats test/bats/
```

Set `HARNESS_LOGLEVEL` to raise Apache's log level, e.g.
`HARNESS_LOGLEVEL="info socache_shmcb:trace5"` when investigating the cache.

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
