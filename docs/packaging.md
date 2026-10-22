# Packaging and release

## What this repo produces

`.github/workflows/packages.yml` builds and install-tests one package per
target, in a container, on a host runner. It is tiered, because the full
matrix is a lot of wall clock for what actually differs between most of these
targets:

| when | deb targets | rpm targets | arch | jobs |
|---|---|---|---|---|
| push, PR | bookworm, noble | el9 | amd64 | 3 |
| manual run with `full_packages` | all five | all four | amd64 | 9 |
| `v*` tag | all five | all four | amd64 + arm64 | 18 |

The quick subset keeps the axes the deb packaging actually varies on —
bookworm is non-t64 and noble is t64 — plus the EL release closest to what
most people run. What the other targets are each there for:

| target | why |
|---|---|
| bullseye | oldest deb; libcurl 7.74, so the pre-7.85 `setopt` path |
| trixie | t64 names, newest debhelper |
| jammy | libcurl 7.81, also pre-7.85 |
| el8 | apr 1.6, python 3.6, httpd 2.4.37, full `curl` |
| el10 | newest EL |
| rocky9 | cross-check that the `el9` artifact is interchangeable |

The target list lives once, in the `targets` job, and the quick subset is a
list of names filtered out of it — so adding a target cannot leave the two
tiers disagreeing. That job also expands the cross product with the
architectures and resolves the runner, emitting one object per job.

Do not be tempted to simplify that back into a second matrix dimension with
`include` supplying the runner. A GitHub Actions `include` entry whose keys
match no existing combination does not extend anything — it adds a
combination of its own. With the quick tier's single architecture, an
`{arch: arm64, runner: ...}` entry therefore created an extra job carrying a
runner but **no target**, which failed with `docker: invalid reference
format` because the image name was empty.

**Run the full matrix before tagging.** The quick subset will not catch a
regression specific to bullseye, trixie, jammy, el8 or el10; those are proven
by the manual run or by the release build itself.

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

### Prereleases, for testing packages

Tag `vX.Y.Z-rcN`. The package version becomes `X.Y.Z~rcN`, and the GitHub
release is drafted and marked as a prerelease, for you to write up and publish.

The `-rc` → `~rc` rewrite is not cosmetic and it is not optional:

- git refuses a `~` in a ref name, so the **tag** has to use `-rc`;
- dpkg and rpm both sort `~` below nothing, so the **package version** has to
  use `~rc` or the prerelease outranks the release it precedes. Measured:
  `dpkg --compare-versions 1.0.0-rc1 lt 1.0.0-1` is **false**, while
  `1.0.0~rc1 lt 1.0.0` is true.

This is the same rewrite `codepipeline/fetch_sources/placeholder/buildspec.yml`
performs, so a package built here is versioned identically to one the pipeline
would build from the same tag.

Verified on bookworm and EL9, installing each in turn:

```
1.0.0~rc1  ->  1.0.0~rc2  ->  1.0.0
```

apt and dnf both treat those as successive upgrades, which is the whole point:
you can hand a tester rc1, then rc2, and they upgrade rather than having to
purge in between.

One thing that does **not** change: the version the module reports to the
local API, which comes from `configure.ac` and so stays `1.0.0` for every rc
of 1.0.0. `cscli bouncers list` will show `crowdsec-apache2-bouncer/1.0.0` for
an rc build. The release pipeline behaves the same way — it never touches
`configure.ac` — so this is consistent rather than a quirk of CI, but it does
mean the engine cannot distinguish rc1 from the final release.

`make check-version` compares only the upstream part of the changelog version,
stripping a trailing `-revision` and any `~suffix`. It has to: `dh_auto_test`
runs `make check` *after* `dch` has stamped the tag into the changelog, so a
gate comparing the full string fails every prerelease build.

### Steps

1. Bump the version in `configure.ac` and `debian/changelog`; `make
   check-version` asserts the upstream parts agree.
2. Tag `vX.Y.Z`, or `vX.Y.Z-rcN` for a prerelease.
3. `.github/workflows/release.yml` derives the package version from the tag,
   checks its upstream part against `configure.ac`, builds every target for
   both architectures, and attaches the packages to a **draft** GitHub
   release.
4. Write the changelog on that draft - the release editor's "Generate release
   notes" button seeds one - and publish it.

The workflow deliberately stops at a draft. Publishing is the step that fires
the packagecloud webhook, so it stays a human decision taken once the packages
are attached and the notes are right; and because the workflow passes no
`body`, a re-run never overwrites what was written by hand.

### What a release contains

One asset per target and architecture. The deb filenames carry the codename
because `dpkg-buildpackage` does not put anything distro-specific in them -
all five builds are otherwise called
`crowdsec-apache2-bouncer_1.0.0_amd64.deb`, and as release assets they would
overwrite one another:

```
crowdsec-apache2-bouncer_1.0.0_bullseye_amd64.deb      (and _arm64)
crowdsec-apache2-bouncer_1.0.0_bookworm_amd64.deb
crowdsec-apache2-bouncer_1.0.0_trixie_amd64.deb
crowdsec-apache2-bouncer_1.0.0_jammy_amd64.deb
crowdsec-apache2-bouncer_1.0.0_noble_amd64.deb
crowdsec-apache2-bouncer-1.0.0-1.el8.x86_64.rpm        (and aarch64)
crowdsec-apache2-bouncer-1.0.0-1.el9.x86_64.rpm
crowdsec-apache2-bouncer-1.0.0-1.el10.x86_64.rpm
crowdsec-apache2-bouncer-1.0.0-1.el*.src.rpm
```

The rpm names already include the dist tag, so they need no renaming - but
Alma 9 and Rocky 9 produce the *same* `.el9` name, which is why Rocky is
marked `publish: false` in the matrix: it is a cross-check that the artifact
really is interchangeable, not a second thing to ship. Debug symbols are not
shipped for either format.

Renaming the file is safe: dpkg and rpm both read the package's own metadata,
not its filename, so `apt install ./crowdsec-apache2-bouncer_1.0.0_noble_amd64.deb`
behaves exactly as before.

## Distribution

**Today the GitHub release is the distribution channel.** Users download the
asset for their distro and install it with `apt install ./...deb` or
`dnf install ./...rpm`.

Nothing in this repo pushes to packagecloud, and it should stay that way:
publishing a GitHub release fires the webhook that starts this product's AWS
CodePipeline, which signs and pushes to `crowdsec/crowdsec-apache` (release)
or `crowdsec/crowdsec-apache-testing` (prerelease). The webhook handler is
`packaging/src/webhook/webhook.py` in `crowdsecurity/terraform-infra`; it acts
on the `prereleased` and `released` actions only, and the repository branch it
feeds is the `APACHE_BOUNCER` gate in
`crowdsecurity/packaging:codepipeline/update_repository/update_deb/script.sh`.

That webhook is **currently disabled** on this repository (hook `526124629`,
set `active=false` on 2026-10-22) so that release testing cannot reach
packagecloud. Re-enable it only once the lane below is fixed:

```sh
gh api -X PATCH repos/crowdsecurity/cs-apache2-bouncer/hooks/526124629 -F active=true
```

Nothing in `terraform-infra` declares a `github_repository_webhook`, so a
`terraform apply` will neither revert nor restore that state.

That lane is **not ready for these packages yet**, which is why releases are
the channel for now. Two hard blockers and one correctness bug, detailed
below: rpms are never built (`disable_rpm = true`), rpms would be pushed to
the shared `crowdsec` repository next to the engine (`update_rpm` has no
`APACHE_BOUNCER` branch), and the deb publish step ships one bookworm build to
every distro target.

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
