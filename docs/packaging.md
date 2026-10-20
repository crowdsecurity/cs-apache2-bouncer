# Packaging and release

## What this repo produces

`.github/workflows/packages.yml` builds and install-tests one package per
target, in a container, on a host runner:

| format | targets | arch |
|---|---|---|
| deb | Debian bullseye, bookworm, trixie; Ubuntu 22.04, 24.04 | amd64 on every push, + arm64 on a tag |
| rpm | AlmaLinux 8, 9, 10; Rocky 9 | same |

Each job builds the package, asserts the bouncer config is 0600 inside the
package, installs it, and runs `test/pkg/smoke.sh` against the distro's own
httpd. The deb jobs also run `lintian --fail-on error`; the rpm jobs assert no
unexpanded rpm macro reached `Requires`.

Alma and Rocky both build because the packagecloud `el/N` repositories serve
RHEL, Alma and Rocky from one artifact — building on two of them is a check
that the artifact really is interchangeable, not extra coverage for its own
sake.

### Why containers on a host runner, not a `container:` job

A job-level `container:` needs a node runtime inside the image for
`actions/checkout`, which the EL images do not reliably have. Running
`docker run` from a host runner also keeps the invocation identical to what a
developer runs locally.

### Local equivalent

```sh
docker run --rm -v "$PWD:/src:ro" -w /src debian:bookworm sh -c '
  apt-get update && apt-get install -y build-essential debhelper devscripts \
    apache2 apache2-dev libcurl4-openssl-dev autoconf automake libtool \
    pkg-config gettext-base python3 curl &&
  mkdir -p /b && cp -a /src /b/pkg && cd /b/pkg &&
  dpkg-buildpackage -us -uc -b &&
  apt-get install -y /b/*.deb && /b/pkg/test/pkg/smoke.sh'
```

Three traps when writing tests like this by hand:

- **Build each package under its own parent directory.** `dpkg-buildpackage`
  drops its output next to the source tree, so building an old and a new
  package in sibling directories puts both `.deb`s in the same place and
  `ls | head -1` sorts `0.1` before `1.0.0`.
- **Give the two packages genuinely different versions** when testing an
  upgrade. `mv_conffile … 1.0.0~` is skipped if the installed version is not
  older, so an upgrade test with both sides at `1.0.0` silently exercises
  nothing.
- **`debian:bullseye` needs its apt sources repointed** to
  `archive.debian.org` with `Acquire::Check-Valid-Until "false"`; it is EOL
  and the stock image's lists 404.

## Releasing

1. Bump the version in `configure.ac` and `debian/changelog`; `make
   check-version` asserts they agree.
2. Tag `vX.Y.Z`, or `vX.Y.Z~rcN` for a prerelease per the house
   tilde-versioning rule.
3. `.github/workflows/release.yml` checks the tag against `configure.ac`,
   builds every target for both architectures, and attaches the packages to a
   GitHub release. A `~rc` tag is published as a prerelease.
4. Publishing the GitHub release fires the webhook that starts this product's
   AWS CodePipeline, defined in `crowdsecurity/packaging`. That pipeline signs
   the packages and pushes them to packagecloud:
   `crowdsec/crowdsec-apache` for a release, `crowdsec/crowdsec-apache-testing`
   for a prerelease.

Nothing in this repo pushes to packagecloud, deliberately.

## Changes still needed in crowdsecurity/packaging

The apache2 lane predates the rpm work and only ships debs. Paths below are
relative to the `crowdsecurity/packaging` checkout.

### 1. `terraform/apache2bouncer/main.tf`

- `disable_rpm = true` → `false`. This gates the `build_rpm`, `sign_rpms`,
  `update_repository_rpm` and `update_archive_rpm` actions.
- `scripts.rpms = ""` →
  `"codepipeline/build_packages/build_rpms/scripts/generic.sh"`. That becomes
  `SCRIPT_NAME` for the rpm build.
- `DISTRIBUTION_LIST`: add `trixie`; drop `bionic buster focal oracular`, all
  EOL and all below the `debhelper-compat (= 13)` this package now needs
  (bionic ships debhelper 11, buster 12).
- **New** `RPM_RELEASEVER_LIST = "el8 el9 el10"`. It has to be a new variable:
  `DISTRIBUTION_LIST` holds deb codenames and is in scope in the rpm stage too,
  so reusing it would gate every rpm out.
- **New** `RPM_ADDITIONAL_DEPENDENCIES = "httpd-devel apr-devel apr-util-devel
  libcurl-devel autoconf automake libtool gcc make gettext pkgconfig
  redhat-rpm-config"`. The existing `ADDITIONAL_DEPENDENCIES` is apt syntax and
  is read only by the deb script. `redhat-rpm-config` is not optional: EL's apr
  libtool passes RPM's hardening specs unconditionally, so without it apxs
  fails on `cannot read spec file /usr/lib/rpm/redhat/redhat-hardened-cc1`.

### 2. `codepipeline/includes/rpms/deps.sh`

- Add an `el10` branch. CentOS Stream 10 maps to `RELEASEVER=el10`, which
  matches none of the existing blocks, so an EL10 build currently installs no
  `rpm-build` at all.
- Consume `RPM_ADDITIONAL_DEPENDENCIES` at the end of `deps()`.
- Do not `dnf install curl` unconditionally: EL9 ships `curl-minimal`, which
  already provides `/usr/bin/curl` and which the full `curl` package conflicts
  with, so the install fails outright there.

### 3. `codepipeline/build_packages/build_rpms/matrix.yml`

Add the distro gate the rpm lane has never had, around the two `rpmbuild`
calls:

```sh
if [ -z "${RPM_RELEASEVER_LIST}" ] ||
   echo "${RPM_RELEASEVER_LIST}" | grep -qw "${RELEASEVER}"; then
   rpmbuild -bs SPECS/${PACKAGE_NAME}.spec
   rpmbuild -bb SPECS/${PACKAGE_NAME}.spec
else
   mkdir -p RPMS SRPMS
fi
```

Empty or unset preserves today's behaviour for every other product. The
`mkdir` keeps `post_build` from failing on a missing directory. Use `grep -qw`,
not `grep -q`.

### 4. `codepipeline/build_packages/build_rpms/buildspec.yml`

Add `centos_stream10` and `centos_stream10_arm64` entries, which needs the ECR
image first (see 6). Leave `oraclelinux7` and `amzn2` alone: their httpd is
2.4.6, below this module's 2.4.16 floor. The `RPM_RELEASEVER_LIST` gate keeps
us off them, and the spec's own `%if 0%{?rhel} < 8` / `%if 0%{?amzn} == 2`
errors are the second line of defence.

### 5. `codepipeline/update_repository/update_rpm/buildspec.yml`

- **Add the missing `APACHE_BOUNCER` branch.** It hardcodes
  `REPO="crowdsec"`/`crowdsec-testing`/`crowdsec-dev`, so enabling the rpm lane
  as-is would push apache rpms into the shared repository alongside the engine.
  Mirror `update_deb/script.sh`: `crowdsec-apache` when `PRERELEASE=false`,
  `crowdsec-apache-testing` when true. `APACHE_BOUNCER` is already in scope.
- **Gate the `rpm_any/rpm_any` push on `STATIC = true`.** It is currently
  ungated. For a module pinned to `httpd-mmn` an el9 build must never be
  offered to el8. While there: that block's `sed 's/-el9-/-any-/'` never
  matches an rpm filename, because the dist tag is `.el9.` and not `-el9-`, so
  the el9 rpm is pushed verbatim today. Fix or delete it.
- Note that the `ol/$DISTRO_VERSION` push will start carrying the apache module
  too. That is wanted — Oracle 8 and 9 are EL — and OL7 never gets one because
  of the gate.

### 6. `codepipeline/update_repository/update_deb/script.sh`

This is the change that makes the per-distro builds actually reach users, and
the riskiest item here.

- Add `DISTRO_MAP[trixie]=debian`.
- The fan-out loop finds `*.deb -path '*bookworm*'` and pushes that one build
  to all eleven distro targets, **ungated**. For a non-static package the other
  seven per-distro builds are simply discarded, and a noble user installs a
  bookworm-built `.so`. Replace it with a per-distro push keyed on
  `cut -d/ -f2` — the field the `.dsc` loop already relies on, since the zip
  layout is `<distribution>/<arch>/` — keeping the existing fan-out for
  `STATIC` / `NON_BINARY_PACKAGE`.

⚠️ That last change alters behaviour for **every** non-static product on the
lane. Gate it on `APACHE_BOUNCER` first, and generalise later after auditing
which other pipelines set neither flag.

### 7. ECR images

Per `consensus-docs/docs/Packaging/add_platform.md`, push to
`675752266593.dkr.ecr.eu-west-1.amazonaws.com/codebuild/`:

- `debian:trixie` (multiarch, so one tag covers both architectures)
- `centos:centos_stream10` and `centos:centos_stream10_arm64`

Then add the matching build-list entries in `build_debs_nonstatic/buildspec.yml`
and `build_rpms/buildspec.yml`.
