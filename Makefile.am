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
                crowdsec_http.h crowdsec_lapi.h crowdsec_verdict.h crowdsec_poison.h

CROWDSEC_SRC = mod_crowdsec.c crowdsec_util.c crowdsec_http.c \
               crowdsec_lapi.c crowdsec_verdict.c

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
             test/README.md test/lib/harness.sh test/lib/stub_endpoint.py \
             test/unit/t_util.c test/unit/t_verdict.c test/unit/t_http.c \
             test/unit/mod_scan_conformance.c \
             mod_crowdsec.spec

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

clean-local:
	rm -f @srcdir@/vendor/yyjson/yyjson.lo \
	      @srcdir@/vendor/yyjson/yyjson.slo
	rm -rf @srcdir@/vendor/yyjson/.libs

# --- tests -----------------------------------------------------------------
# Unit tests link apr directly and need no server.

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
