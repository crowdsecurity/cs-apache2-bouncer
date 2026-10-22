#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([crowdsec-apache2-bouncer], [1.0.0], [support@crowdsec.net],
        [crowdsec-apache2-bouncer],
        [https://github.com/crowdsecurity/cs-apache2-bouncer])
AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects])
AC_CONFIG_FILES([Makefile crowdsec_version.h
                 config/crowdsec.load
                 config/crowdsec.conf
                 config/10-crowdsec.conf
                 config/crowdsec-include.conf])
AC_CONFIG_SRCDIR([mod_crowdsec.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_ARG_WITH(apxs,
    [  --with-apxs=PATH        path to Apache apxs],
    [
        if test "$withval" = "yes"; then
            AC_CHECK_PROGS(APXS, apxs /usr/sbin/apxs, reject)
        else
            APXS=$withval
            AC_SUBST(APXS)
        fi
    ],
    [
        AC_CHECK_PROGS(APXS, apxs /usr/sbin/apxs, reject)
    ])
if test "$APXS" = "reject"; then
  AC_MSG_ERROR([Could not find apxs on the path.])
fi

# Make sure the Apache include files are found
AM_CPPFLAGS="$AM_CPPFLAGS -I`$APXS -q INCLUDEDIR`"
AM_CFLAGS="$AM_CFLAGS -I`$APXS -q INCLUDEDIR`"

# Checks for libraries.
PKG_CHECK_MODULES(apr, apr-1 >= 1.3)
PKG_CHECK_MODULES(apu, apr-util-1 >= 1.3)

# libcurl is how we talk to the local API and to the AppSec component. 7.40 is
# the floor for CURLOPT_UNIX_SOCKET_PATH; CURLOPT_PROTOCOLS_STR needs 7.85 and
# is used conditionally, falling back to the deprecated bitmask below that.
PKG_CHECK_MODULES(curl, libcurl >= 7.40,, [
  AC_PATH_PROG([CURL_CONFIG], [curl-config], [no])
  AS_IF([test "x$CURL_CONFIG" = xno],
        [AC_MSG_ERROR([libcurl development files not found. Install libcurl4-openssl-dev or libcurl-devel.])],
        [curl_CFLAGS=`$CURL_CONFIG --cflags`
         curl_LIBS=`$CURL_CONFIG --libs`
         AC_SUBST(curl_CFLAGS)
         AC_SUBST(curl_LIBS)])
])

# apxs builds every source with the same flags, so yyjson is compiled on its
# own in order to keep -Werror off vendored code. This is the libtool apxs
# itself uses; it expands to two words, so do not quote it in the Makefile.
AC_SUBST([APXS_LIBTOOL], [`$APXS -q LIBTOOL`])

# Everything that differs between an apache2 and an httpd install comes from
# apxs rather than from a hardcoded path, so one source tree can produce the
# Debian and the EL layout. TARGET is literally "apache2" on Debian-family and
# "httpd" on EL, which is also the service and binary name.
AC_SUBST([APXS_LIBEXECDIR], [`$APXS -q LIBEXECDIR`])
AC_SUBST([APXS_SYSCONFDIR], [`$APXS -q SYSCONFDIR`])
AC_SUBST([APXS_TARGET], [`$APXS -q TARGET`])

AC_ARG_WITH([crowdsec-confdir],
  [AS_HELP_STRING([--with-crowdsec-confdir=DIR],
                  [where the bouncer config lives @<:@/etc/crowdsec/bouncers@:>@])],
  [crowdsec_confdir=$withval], [crowdsec_confdir=/etc/crowdsec/bouncers])
AC_SUBST([CROWDSEC_CONFDIR], [$crowdsec_confdir])

# /usr/lib and not $libdir or %{_libdir}: this holds an architecture-
# independent shell snippet, and every other crowdsec bouncer puts its copy in
# /usr/lib/<package>, including on 64-bit EL where _libdir is /usr/lib64. The
# maintainer scripts source it by that literal path.
AC_SUBST([BOUNCER_LIBDIR], [/usr/lib/crowdsec-apache2-bouncer])

# Which enablement convention to install: Debian has mods-available and
# a2enmod, EL has conf.modules.d and no equivalent. "none" installs neither,
# for a build that only wants the module itself.
AS_CASE([$APXS_TARGET],
  [apache2], [apache_layout=debian],
  [httpd],   [apache_layout=el],
             [apache_layout=none])
AC_ARG_WITH([apache-layout],
  [AS_HELP_STRING([--with-apache-layout=debian|el|none],
                  [module enablement convention @<:@auto from apxs -q TARGET@:>@])],
  [apache_layout=$withval])
AS_CASE([$apache_layout],
  [debian|el|none], [],
  [AC_MSG_ERROR([--with-apache-layout must be debian, el or none])])
AM_CONDITIONAL([LAYOUT_DEBIAN], [test "x$apache_layout" = xdebian])
AM_CONDITIONAL([LAYOUT_EL], [test "x$apache_layout" = xel])

# Where the enablement directories live, which is NOT apxs's SYSCONFDIR on EL:
# there it is /etc/httpd/conf, while conf.d and conf.modules.d are its
# siblings under /etc/httpd. On Debian SYSCONFDIR is /etc/apache2 and
# mods-available is directly below it.
AS_CASE([$apache_layout],
  [el], [apache_confroot=`AS_DIRNAME(["$APXS_SYSCONFDIR"])`],
        [apache_confroot=$APXS_SYSCONFDIR])
AC_ARG_WITH([apache-confroot],
  [AS_HELP_STRING([--with-apache-confroot=DIR],
                  [directory holding mods-available or conf.modules.d @<:@auto@:>@])],
  [apache_confroot=$withval])
AC_SUBST([APACHE_CONFROOT], [$apache_confroot])

# -Wno-unused-parameter and -Wno-missing-field-initializers are not laxity:
# Apache fixes the signature of every hook and directive handler, and
# STANDARD20_MODULE_STUFF leaves the module struct partly uninitialised, so
# -Wextra fires on its API rather than on our code.
AC_SUBST([CROWDSEC_WARN_CFLAGS],
         ["-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wformat=2 -Wshadow -Wvla"])
AC_ARG_ENABLE([werror],
  [AS_HELP_STRING([--enable-werror], [treat warnings in our own sources as errors])],
  [AS_IF([test "x$enableval" = xyes],
         [CROWDSEC_WARN_CFLAGS="$CROWDSEC_WARN_CFLAGS -Werror"])])

# Fuzzing is a developer tool, not part of make check: libFuzzer needs clang,
# and the targets run for as long as you let them. See fuzz/README.md.
AC_ARG_ENABLE([fuzzing],
  [AS_HELP_STRING([--enable-fuzzing],
                  [build the fuzz targets (requires clang and libFuzzer)])],
  [AS_IF([test "x$enableval" = xyes], [enable_fuzzing=yes])],
  [enable_fuzzing=no])
AM_CONDITIONAL([FUZZING], [test "x$enable_fuzzing" = xyes])
AS_IF([test "x$enable_fuzzing" = xyes], [
  AC_MSG_CHECKING([whether $CC accepts -fsanitize=fuzzer])
  save_cflags="$CFLAGS"
  CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_MSG_ERROR([--enable-fuzzing needs a compiler with libFuzzer; try CC=clang])])
  CFLAGS="$save_cflags"
  FUZZ_CFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all"
  FUZZ_CFLAGS="$FUZZ_CFLAGS -fsanitize-address-use-after-scope -g"
])
AC_SUBST(FUZZ_CFLAGS)

CFLAGS="$CFLAGS $apr_CFLAGS $apu_CFLAGS"
CPPFLAGS="$CPPFLAGS $apr_CPPFLAGS $apu_CPPFLAGS"
LDFLAGS="$LDFLAGS $apr_LIBS $apu_LIBS"

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.

AC_SUBST(PACKAGE_VERSION)
AC_OUTPUT

AC_MSG_NOTICE([apache target:  $APXS_TARGET (layout $apache_layout)])
AC_MSG_NOTICE([module dir:     $APXS_LIBEXECDIR])
AC_MSG_NOTICE([apache confdir: $APACHE_CONFROOT (apxs sysconfdir $APXS_SYSCONFDIR)])
AC_MSG_NOTICE([bouncer config: $CROWDSEC_CONFDIR])
