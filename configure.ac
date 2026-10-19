#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([crowdsec-apache2-bouncer], [1.0.0], [support@crowdsec.net],
        [crowdsec-apache2-bouncer],
        [https://github.com/crowdsecurity/cs-apache2-bouncer])
AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects])
AC_CONFIG_FILES([Makefile crowdsec_version.h])
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

AC_ARG_WITH(install,
    [  --with-install=PATH     path to install],
    [
        if test "$withval" = "yes"; then
            AC_CHECK_PROGS(INSTALL, install /usr/sbin/install, reject)
        else
            APXS=$withval
            AC_SUBST(INSTALL)
        fi
    ],
    [
        AC_CHECK_PROGS(INSTALL, install /usr/sbin/install, reject)
    ])
if test "$INSTALL" = "reject"; then
  AC_MSG_ERROR([Could not find install on the path.])
fi

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
