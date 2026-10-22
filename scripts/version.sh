#!/bin/sh
# Prints the version from configure.ac's AC_INIT, which is the one place it is
# declared.
#
# Not "autoconf --trace": the rpm spec and the release workflow both need the
# version before configure has necessarily been generated, and on hosts that
# have no autoconf at all.
set -eu

ac="$(dirname "$0")/../configure.ac"

version=$(sed -n \
    's/^AC_INIT(\[\{0,1\}[^],]*\]\{0,1\}, *\[\{0,1\}\([0-9][^] ,]*\).*/\1/p' \
    "$ac")

if [ -z "$version" ]; then
    echo "version.sh: no version found in $ac" >&2
    exit 1
fi

printf '%s\n' "$version"
