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

Requires `apache2` plus `mod_mpm_prefork`, `mod_authz_core`, `mod_dir`,
`mod_proxy`, `mod_proxy_http` and `mod_socache_shmcb` in
`/usr/lib/apache2/modules`, and `python3` for the stub LAPI and port probing.

## Unit tests

`test/unit/t_util.c` covers the pure helpers in `crowdsec_util.c` and links only
apr, so it runs without a server:

```
gcc -Wall -Wextra -Werror -g -fsanitize=address,undefined \
    $(pkg-config --cflags apr-1) -I. test/unit/t_util.c crowdsec_util.c \
    $(pkg-config --libs apr-1) -o t_util && ./t_util
```

`test/unit/mod_scan_conformance.c` is a test-only Apache module. The header
sanitisers are reimplemented as byte tables because Apache's `ap_scan_*` live in
the httpd binary rather than a shared library, so they cannot be linked from a
standalone test. This module runs inside the server and asserts the tables agree
with the real functions for every byte; `test/bats/scan-conformance.bats` drives
it. Build it with:

```
apxs -c -I. -o test/unit/mod_scan_conformance.la \
    test/unit/mod_scan_conformance.c crowdsec_util.c
```

Both will move under `make check` when the build changes land.
