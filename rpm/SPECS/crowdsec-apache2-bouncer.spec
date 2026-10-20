Name:      crowdsec-apache2-bouncer
Version:   %(echo $VERSION)
Release:   %(echo $PACKAGE_NUMBER)%{?dist}
Summary:   CrowdSec bouncer for the Apache 2 HTTP server

License:   MIT
URL:       https://crowdsec.net
Source0:   https://github.com/crowdsecurity/cs-apache2-bouncer/archive/v%(echo $VERSION).tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# configure is not committed and the build tarball is the git checkout rather
# than a make dist, so %build has to autoreconf first.
BuildRequires: gcc, make, autoconf, automake, libtool, pkgconfig
BuildRequires: httpd-devel
BuildRequires: apr-devel, apr-util-devel
BuildRequires: libcurl-devel
BuildRequires: gettext
# Not optional: EL's apr libtool passes RPM's hardening specs unconditionally,
# so without this apxs dies on "cannot read spec file
# /usr/lib/rpm/redhat/redhat-hardened-cc1". rpm-build pulls it in, which is
# why a pipeline build gets away without it and a plain make does not.
BuildRequires: redhat-rpm-config

# httpd-mmn is the module ABI pin. The macro comes from macros.httpd in
# httpd-devel and expands to 20120211x8664; the provider differs by release -
# httpd itself on EL8, httpd-core on EL9+, where the binary and modules moved
# out of the httpd meta-package. httpd-filesystem owns conf.d and
# conf.modules.d.
Requires: httpd
Requires: httpd-filesystem
Requires: httpd-mmn = %{_httpd_mmn}
# envsubst, used by the scriptlets to write the API key into the config.
Requires: gettext

# EL7-era httpd is 2.4.6, below the 2.4.16 this module needs. The pipeline
# gates these out by release, but fail here too rather than ship something
# that installs and then refuses to load.
%if 0%{?rhel} && 0%{?rhel} < 8
%{error:%{name} requires httpd 2.4.16 or later; EL7 is not a supported target}
%endif
%if 0%{?amzn} == 2
%{error:%{name} requires httpd 2.4.16 or later; Amazon Linux 2 is not supported}
%endif

# Fallbacks in case macros.httpd is not loaded: an undefined macro would
# otherwise end up verbatim in Requires, and the package would be
# uninstallable at the user's end rather than failing here.
%{!?_httpd_moddir:     %global _httpd_moddir     %{_libdir}/httpd/modules}
%{!?_httpd_confdir:    %global _httpd_confdir    %{_sysconfdir}/httpd/conf.d}
%{!?_httpd_modconfdir: %global _httpd_modconfdir %{_sysconfdir}/httpd/conf.modules.d}

# House convention, and it avoids an unpackaged-debuginfo failure. The
# trade-off for a C module is that the .so ships unstripped with no
# -debuginfo subpackage.
%define debug_package %{nil}
%define version_number %(echo $VERSION)

%description
mod_crowdsec asks a CrowdSec local API for a verdict on each client and then
blocks, challenges or allows the request. Decisions are taken either per
request or from the decision stream, polled in the background into a shared
cache so that no request waits on the API.

Requests can also be forwarded to the CrowdSec AppSec component for WAF
inspection and bot detection, including serving the challenge interstitial.

%prep
%setup -q -T -b 0 -n %{name}-%{version_number}

%build
autoreconf -fi
# The module path and the httpd layout come from apxs, which httpd-devel
# provides. confroot is passed explicitly because apxs reports
# /etc/httpd/conf as its SYSCONFDIR, while conf.d and conf.modules.d are its
# siblings - so rpm's own macro is the better source of truth here.
%configure --enable-werror --with-apache-confroot=%{_sysconfdir}/httpd
%make_build

%install
rm -rf %{buildroot}
%make_install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_httpd_moddir}/mod_crowdsec.so
%attr(0600,root,root) /usr/lib/%{name}/_bouncer.sh
%config(noreplace) %{_httpd_modconfdir}/10-crowdsec.conf
%config(noreplace) %{_httpd_confdir}/crowdsec.conf
%config(noreplace) %attr(0600,root,root) /etc/crowdsec/bouncers/%{name}.conf
%license LICENSE
%doc README.md

%post
# $1 is 1 on first install, 2 or more on upgrade.
START=1
if ! (
    # Sourced inside a subshell on purpose: _bouncer.sh turns on "set -eu",
    # and the config test below has to be allowed to fail so that it can be
    # reported rather than abort the scriptlet.
    . /usr/lib/%{name}/_bouncer.sh
    rc=0
    if [ "$1" = "1" ] && need_api_key; then
        set_api_key || rc=1
    fi
    set_local_port
    exit "$rc"
); then
    START=0
fi

if [ "$START" -eq 0 ]; then
    echo "no api key was generated; run 'cscli bouncers add <bouncer_name>' on your LAPI server and put the key in /etc/crowdsec/bouncers/%{name}.conf" >&2
fi

# Test before reloading: a bad Crowdsec directive must not take httpd down
# during a package install.
if /usr/sbin/apachectl configtest >/dev/null 2>&1; then
    if [ -d /run/systemd/system ]; then
        systemctl try-reload-or-restart httpd >/dev/null 2>&1 || :
    fi
else
    echo "httpd configuration test failed, so httpd was not reloaded. Run 'apachectl configtest' to see why." >&2
fi

%preun
# $1 is 0 on uninstall and 1 or more when an upgrade removes the old package.
# Unlike dpkg's remove, an rpm erase takes the config with it (or leaves it as
# .rpmsave), so there is no retained config left holding a key the API no
# longer knows.
if [ "$1" = "0" ]; then
    ( . /usr/lib/%{name}/_bouncer.sh; delete_bouncer ) || :
fi

%postun
# The .so and the conf.modules.d snippet are both gone by now, so httpd has no
# dangling LoadModule - a modified snippet is kept as .rpmsave, which does not
# match the conf.modules.d/*.conf glob. Reload so the module stops being used.
if [ "$1" = "0" ] && [ -d /run/systemd/system ]; then
    if systemctl is-active --quiet httpd; then
        /usr/sbin/apachectl configtest >/dev/null 2>&1 && \
            systemctl try-reload-or-restart httpd >/dev/null 2>&1 || :
    fi
fi

%changelog
* Mon Oct 20 2026 Crowdsec Team <support@crowdsec.net>
- initial packaging
