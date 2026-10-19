# yyjson's compile-time options. The depth limit matters: upstream defaults it
# to 0, which compiles the check out entirely, so untrusted input would have no
# nesting bound at all. Our deepest schema is three levels.
YYJSON_DEFS = -DYYJSON_READER_DEPTH_LIMIT=8 \
              -DYYJSON_DISABLE_WRITER=1 \
              -DYYJSON_DISABLE_INCR_READER=1 \
              -DYYJSON_DISABLE_NON_STANDARD=1 \
              -DYYJSON_DISABLE_FILE=1 \
              -DYYJSON_DISABLE_UTILS=1

CROWDSEC_HDRS = crowdsec_internal.h crowdsec_config.h crowdsec_util.h \
                crowdsec_http.h crowdsec_lapi.h crowdsec_store.h crowdsec_verdict.h \
                crowdsec_appsec.h \
                crowdsec_poison.h

CROWDSEC_SRC = mod_crowdsec.c crowdsec_config.c crowdsec_util.c crowdsec_http.c \
               crowdsec_lapi.c crowdsec_poller.c crowdsec_verdict.c crowdsec_appsec.c

CROWDSEC_INC = -I@srcdir@ -I@srcdir@/vendor/yyjson

# yyjson is handed to apxs as a prebuilt object, because -Wc applies to every
# source and we want -Werror on ours only.
APXS_ARGS = -c -o @srcdir@/mod_crowdsec.la \
            $(CROWDSEC_INC) $(YYJSON_DEFS) \
            -Wc,"$(CFLAGS) $(AM_CFLAGS) $(curl_CFLAGS) $(CROWDSEC_WARN_CFLAGS)" \
            -Wl,"$(LDFLAGS) $(AM_LDFLAGS) $(curl_LIBS)" \
            @srcdir@/vendor/yyjson/yyjson.lo \
            $(CROWDSEC_SRC:%=@srcdir@/%)

EXTRA_DIST = $(CROWDSEC_SRC) $(CROWDSEC_HDRS) \
             vendor/yyjson/yyjson.c vendor/yyjson/yyjson.h \
             vendor/yyjson/LICENSE vendor/yyjson/VERSION \
             test/README.md test/lib/harness.sh \
             test/lib/stub_endpoint.py test/lib/stub_lapi.py \
             test/lib/stub_appsec.py test/lib/memo_probe.py \
             test/unit/t_util.c test/unit/t_verdict.c test/unit/t_http.c \
             test/unit/mod_scan_conformance.c \
             test/bats/appsec.bats test/bats/appsec-body.bats \
             test/bats/blocked-http-code.bats test/bats/challenge.bats \
             test/bats/connect.bats test/bats/gating.bats \
             test/bats/http-client.bats test/bats/limits.bats \
             test/bats/live-mode.bats test/bats/scan-conformance.bats \
             test/bats/stream-mode.bats \
             fuzz/README.md \
             scripts/version.sh scripts/_bouncer.sh \
             config/crowdsec-apache2-bouncer.conf \
             config/mod_crowdsec.load.in config/mod_crowdsec.conf.in \
             config/10-crowdsec.conf.in config/crowdsec-include.conf.in

@srcdir@/vendor/yyjson/yyjson.lo: @srcdir@/vendor/yyjson/yyjson.c \
                                  @srcdir@/vendor/yyjson/yyjson.h
	$(APXS_LIBTOOL) --mode=compile --tag=disable-static $(CC) \
	    $(CFLAGS) $(YYJSON_DEFS) -w \
	    -c -o $@ @srcdir@/vendor/yyjson/yyjson.c
	touch @srcdir@/vendor/yyjson/yyjson.slo

all-local: @srcdir@/vendor/yyjson/yyjson.lo
	$(APXS) $(APXS_ARGS)

install-exec-local: @srcdir@/vendor/yyjson/yyjson.lo
	if test -z "$${LIBEXECDIR}"; then LIBEXECDIR=`$(APXS) -q LIBEXECDIR`; fi;\
	\
	mkdir -p $(DESTDIR)$${LIBEXECDIR}; \
	\
	$(APXS) -S LIBEXECDIR=$(DESTDIR)$${LIBEXECDIR} -i $(APXS_ARGS)

# The bouncer's own files, independent of which apache layout is in use. Kept
# separate from install-apache-snippets because the Debian package takes this
# half only: there dh_apache2 owns the .so and the mods-available pair, and it
# is what emits the apache2-api dependency.
install-bouncer-data:
	$(MKDIR_P) $(DESTDIR)@CROWDSEC_CONFDIR@
# 0600 because this file holds the API key. scripts/_bouncer.sh writes it with
# a plain redirect under umask 177, which preserves whatever mode the file
# already has rather than imposing one - so the packaging has to create it
# with the right mode in the first place.
	$(INSTALL) -m 0600 $(srcdir)/config/crowdsec-apache2-bouncer.conf \
	    $(DESTDIR)@CROWDSEC_CONFDIR@/crowdsec-apache2-bouncer.conf
	$(MKDIR_P) $(DESTDIR)@BOUNCER_LIBDIR@
	$(INSTALL) -m 0600 $(srcdir)/scripts/_bouncer.sh \
	    $(DESTDIR)@BOUNCER_LIBDIR@/_bouncer.sh

# These come from config.status, so they are in the build tree and take no
# $(srcdir).
install-apache-snippets:
if LAYOUT_DEBIAN
	$(MKDIR_P) $(DESTDIR)@APACHE_CONFROOT@/mods-available
	$(INSTALL_DATA) config/mod_crowdsec.load config/mod_crowdsec.conf \
	    $(DESTDIR)@APACHE_CONFROOT@/mods-available/
endif
if LAYOUT_EL
	$(MKDIR_P) $(DESTDIR)@APACHE_CONFROOT@/conf.modules.d
	$(INSTALL_DATA) config/10-crowdsec.conf \
	    $(DESTDIR)@APACHE_CONFROOT@/conf.modules.d/10-crowdsec.conf
	$(MKDIR_P) $(DESTDIR)@APACHE_CONFROOT@/conf.d
	$(INSTALL_DATA) config/crowdsec-include.conf \
	    $(DESTDIR)@APACHE_CONFROOT@/conf.d/crowdsec.conf
endif

install-data-local: install-bouncer-data install-apache-snippets
.PHONY: install-bouncer-data install-apache-snippets

clean-local:
	rm -f @srcdir@/vendor/yyjson/yyjson.lo \
	      @srcdir@/vendor/yyjson/yyjson.slo
	rm -rf @srcdir@/vendor/yyjson/.libs

# --- version ---------------------------------------------------------------
# configure.ac is the source of truth. debian/changelog is the one copy that
# is not derived from it - the release pipeline regenerates it with dch, so
# this only catches local and CI builds, which is where it would be noticed.
check-version:
	@v=`$(srcdir)/scripts/version.sh`; \
	if test -f $(srcdir)/debian/changelog && \
	   command -v dpkg-parsechangelog >/dev/null 2>&1; then \
	    d=`dpkg-parsechangelog -l$(srcdir)/debian/changelog -S Version \
	       | sed 's/-[^-]*$$//'`; \
	    if test "$$v" != "$$d"; then \
	        echo "version mismatch: configure.ac $$v, debian/changelog $$d" >&2; \
	        exit 1; \
	    fi; \
	    echo "version $$v, matching debian/changelog"; \
	else \
	    echo "version $$v (no debian/changelog to check against)"; \
	fi
.PHONY: check-version

check-local: check-version

# --- tests -----------------------------------------------------------------
# Unit tests link apr directly and need no server.

# --- fuzzing -------------------------------------------------------------
# Not in check_PROGRAMS: these never terminate on their own, and they need
# clang. "make fuzz" builds them; fuzz/README.md has the invocations.
FUZZ_TARGETS = fuzz/fuzz_verdict fuzz/fuzz_stream fuzz/fuzz_hdr

if FUZZING
noinst_PROGRAMS = $(FUZZ_TARGETS)

fuzz_fuzz_verdict_SOURCES = fuzz/fuzz_verdict.c crowdsec_verdict.c \
                            crowdsec_util.c vendor/yyjson/yyjson.c
fuzz_fuzz_verdict_CPPFLAGS = $(AM_CPPFLAGS) $(YYJSON_DEFS)
fuzz_fuzz_verdict_CFLAGS = $(FUZZ_CFLAGS)
fuzz_fuzz_verdict_LDFLAGS = $(FUZZ_CFLAGS)
fuzz_fuzz_verdict_LDADD = $(apr_LIBS)

fuzz_fuzz_stream_SOURCES = fuzz/fuzz_stream.c crowdsec_verdict.c \
                           crowdsec_util.c vendor/yyjson/yyjson.c
fuzz_fuzz_stream_CPPFLAGS = $(AM_CPPFLAGS) $(YYJSON_DEFS)
fuzz_fuzz_stream_CFLAGS = $(FUZZ_CFLAGS)
fuzz_fuzz_stream_LDFLAGS = $(FUZZ_CFLAGS)
fuzz_fuzz_stream_LDADD = $(apr_LIBS)

fuzz_fuzz_hdr_SOURCES = fuzz/fuzz_hdr.c crowdsec_util.c
fuzz_fuzz_hdr_CPPFLAGS = $(AM_CPPFLAGS)
fuzz_fuzz_hdr_CFLAGS = $(FUZZ_CFLAGS)
fuzz_fuzz_hdr_LDFLAGS = $(FUZZ_CFLAGS)
fuzz_fuzz_hdr_LDADD = $(apr_LIBS)

fuzz: $(FUZZ_TARGETS)
else
fuzz:
	@echo "configure with --enable-fuzzing CC=clang first" >&2; exit 1
endif
.PHONY: fuzz

check_PROGRAMS = test/unit/t_util test/unit/t_verdict test/unit/t_http
TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CROWDSEC_INC) $(apr_CFLAGS) $(apu_CFLAGS)

test_unit_t_util_SOURCES = test/unit/t_util.c crowdsec_util.c
test_unit_t_util_LDADD = $(apr_LIBS)

test_unit_t_verdict_SOURCES = test/unit/t_verdict.c crowdsec_verdict.c \
                              crowdsec_util.c vendor/yyjson/yyjson.c
test_unit_t_verdict_CPPFLAGS = $(AM_CPPFLAGS) $(YYJSON_DEFS)
test_unit_t_verdict_LDADD = $(apr_LIBS)

test_unit_t_http_SOURCES = test/unit/t_http.c crowdsec_http.c crowdsec_util.c
test_unit_t_http_CPPFLAGS = $(AM_CPPFLAGS) $(curl_CFLAGS)
test_unit_t_http_LDADD = $(apr_LIBS) $(apu_LIBS) $(curl_LIBS)

# --- CI helper -------------------------------------------------------------
# The static-analysis job analyses each source on its own rather than through
# apxs, so it needs the warning flags, the source list and the yyjson defines -
# all already spelled out once above or in configure.ac. Emitted as KEY=value
# so the job can append it straight to $$GITHUB_ENV, rather than keeping a
# second copy of each that silently drifts.
print-analyzer-vars:
	@echo 'ANALYZE_WARN=$(CROWDSEC_WARN_CFLAGS)'
	@echo 'ANALYZE_SRC=$(CROWDSEC_SRC)'
	@echo 'ANALYZE_DEFS=$(YYJSON_DEFS)'
.PHONY: print-analyzer-vars
