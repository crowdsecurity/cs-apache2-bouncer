# Apache2 CrowdSec Bouncer

Module for the [Apache HTTP Web Server](https://httpd.apache.org) that filters
unwanted web traffic. It checks each request against CrowdSec decisions,
optionally forwards it to the AppSec component for WAF inspection, and can
serve the bot-detection challenge.

See also the [public documentation](https://doc.crowdsec.net/u/bouncers/apache_bouncer).

## Features

- **Decision enforcement**, in two modes:
  - `stream` — the decision set is polled in the background into a shared
    cache. No API round trip on the request path.
  - `live` — the API is queried per request, with a short-lived in-process
    cache per address.
- **Web Application Firewall (AppSec)** — full request is forwarded to
  the AppSec/WAF component inline; the verdict decides the request.
- **Bot detection** — serves the challenge interstitial, its assets and its
  submit endpoint, and relays the resulting cookie.
- IPv4 and IPv6, single addresses and ranges.
- Unix socket or TCP for AppSec.

Remediations supported: `ban`, `allow`, `challenge`. There is no captcha
support; see [Known limits](#known-limits).

## Requirements

- Apache 2.4.16 or later
- `mod_socache_shmcb` (stream mode)
- libcurl 7.40 or later
- A CrowdSec local API, and the AppSec component if you want WAF or bot
  detection

## Install

From the package:

```sh
apt install ./crowdsec-apache2-bouncer_*.deb
```

The package registers a bouncer, writes the key into
`/etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf`, and enables the module.

From source:

```sh
autoreconf -fi
./configure --with-apxs=/usr/bin/apxs2
make && sudo make install
```

Register a bouncer by hand if needed:

```sh
sudo cscli bouncers add apache
```

## Quick start

### Stream mode (recommended)

Server scope, in `/etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf`:

```apache
CrowdsecURL    http://127.0.0.1:8080
CrowdsecAPIKey <key from cscli bouncers add>

CrowdsecMode            stream
CrowdsecUpdateFrequency 10s
CrowdsecCache           shmcb:crowdsec(16777216)
CrowdsecFallback        allow
```

Then enable it where you want it:

```apache
<Location />
    Crowdsec On
</Location>
```

`CrowdsecCache` is mandatory in stream mode and must be large enough to hold
every decision — see the sizing note under [`CrowdsecCache`](#decision-source).

### Live mode

No cache required:

```apache
CrowdsecURL    http://127.0.0.1:8080
CrowdsecAPIKey <key>
CrowdsecMode   live
```

### AppSec (WAF)

Add the endpoint at server scope and turn it on per scope:

```apache
CrowdsecAppsecURL http://127.0.0.1:7422

<Location />
    Crowdsec       On
    CrowdsecAppsec On
</Location>
```

`CrowdsecAppsecPath` must match the `path` of the engine's appsec datasource.
A 404 from AppSec usually means it does not.

### Bot detection

Bot detection is AppSec with the challenge collections installed on the engine.
No extra directive: enable `CrowdsecAppsec` and install the collection.

```sh
sudo cscli collections install crowdsecurity/appsec-bot-challenge
sudo systemctl reload crowdsec
```

The challenge serves its own assets from `CrowdsecAppsecInternalPath`
(`/crowdsec-internal/challenge/` by default). Those paths are always sent to
AppSec, including where `Crowdsec` is otherwise `Off`, because a challenged
visitor cannot complete without them.

### Behind a reverse proxy

The module uses the address Apache reports, so configure `mod_remoteip`
properly:

```apache
RemoteIPHeader        X-Forwarded-For
RemoteIPInternalProxy 10.0.0.0/8
```

With `RemoteIPHeader` set and **no** trusted-proxy list, any client can choose
the address being policed. Set `CrowdsecTrustUseragentIP Off` to pin to the
real TCP peer instead.

## Status

```apache
<Location /crowdsec-status>
    SetHandler crowdsec-status
    Crowdsec   Off
    Require    ip 127.0.0.1
</Location>
```

Reports `mode`, `url`, `cache`, and in stream mode `primed`, `pulls`,
`stored`, `retained` and `last_pull_age_ms`.

`stored` is what the last full pull wrote. `retained` estimates how many
survived, extrapolated from a sample of up to 32 keys re-read after the pull,
so treat it as an indicator rather than a count. `retained` below `stored`
means the cache is evicting decisions and needs to be larger; the error log
says so too.

## Logging

The module sets these in `subprocess_env`, usable in `LogFormat`:

| Variable | Values |
|---|---|
| `CROWDSEC_STATUS` | `allow`, `ban`, `challenge`, or why it could not decide |
| `CROWDSEC_SOURCE` | `memo`, `cache`, `live`, `unprimed` |
| `CROWDSEC_APPSEC_STATUS` | the verdict action, `body-bypass`, `parse-fail`, `http-<code>`, or a transport error |

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b %{CROWDSEC_STATUS}e %{CROWDSEC_APPSEC_STATUS}e" crowdsec
```

For the stream poller's own messages:

```apache
LogLevel info crowdsec_module:info
```

## Configuration directives

Scope column: **S** = server/vhost only, **S+D** = also valid in
`<Directory>`, `<Location>` and `.htaccess`-equivalent scopes.

### Decision source

| Directive | Scope | Default | Description |
|---|---|---|---|
| `CrowdsecURL` | S | — | Base URL of the local API, e.g. `http://localhost:8080`. |
| `CrowdsecAPIKey` | S | — | Bouncer key from `cscli bouncers add`. |
| `CrowdsecMode` | S | `live` | `live` or `stream`. `stream` requires `CrowdsecCache`. |
| `CrowdsecUpdateFrequency` | S | `10s` | Decision stream poll interval. |
| `CrowdsecCache` | S | — | Shared decision cache, e.g. `shmcb:crowdsec(16777216)`. Required by stream mode. Budget ~128 bytes per decision: 100,000 decisions need at least 6 MB, 1,000,000 fit in 128 MB. Undersized, decisions are evicted and those clients go unblocked; the error log reports it after each pull. |
| `CrowdsecCacheTimeout` | S | `60s` | How long one address's verdict is held in the **shared** cache. Live mode only: it is what stops every child querying the API for the same client. |
| `CrowdsecLocalCacheTimeout` | S | `2s` | How long one address's verdict is held **within a single Apache child**, in front of the shared cache. Added to `CrowdsecUpdateFrequency` in the time a new decision takes to apply, so keep it small. Capped at `CrowdsecCacheTimeout`. |
| `CrowdsecConnectTimeout` | S | `1s` | Connection timeout to the local API. |
| `CrowdsecTimeout` | S | `5s` | Total budget for one API request. A stream pull gets a multiple of this. |

### Enforcement

| Directive | Scope | Default | Description |
|---|---|---|---|
| `Crowdsec` | S+D | `Off` | Check requests in this scope. |
| `CrowdsecBlockedHTTPCode` | S+D | `429` | Status for a blocked client: `429`, `403` or `500`. |
| `CrowdsecLocation` | S+D | — | Redirect a blocked client here instead. Supports expressions, e.g. `/blocked?ip=%{REMOTE_ADDR}`. |
| `CrowdsecFallback` | S+D | `fail` | When CrowdSec cannot be consulted, including before the stream has loaded: `fail` (500), `block`, or `allow`. |
| `CrowdsecRemediationFallback` | S+D | `ban` | What an AppSec remediation this module cannot serve (captcha, or a custom one) becomes: `ban` or `allow`. Does not apply to local API decisions. |
| `CrowdsecTrustUseragentIP` | S+D | `On` | Trust the address reported by modules such as `mod_remoteip`. `Off` uses the connection's real peer. |

### AppSec

| Directive | Scope | Default | Description |
|---|---|---|---|
| `CrowdsecAppsecURL` | S | — | AppSec address: `http://127.0.0.1:7422` or `unix:/run/crowdsec/appsec.sock`. Unset disables AppSec. |
| `CrowdsecAppsecPath` | S | `/` | Path AppSec listens on. Must match the datasource's `path`. |
| `CrowdsecAppsec` | S+D | `Off` | Send requests in this scope for inspection. |
| `CrowdsecAppsecAlwaysSend` | S+D | `Off` | Inspect even when the client is already blocked. |
| `CrowdsecAppsecFailureAction` | S+D | `passthrough` | When AppSec cannot be consulted: `passthrough` or `deny`. |
| `CrowdsecAppsecConnectTimeout` | S | `200ms` | Connection timeout to AppSec. |
| `CrowdsecAppsecTimeout` | S | `1s` | Total budget for one AppSec request, excluding time reading the client body. |
| `CrowdsecAppsecBodyLimit` | S+D | `1m` | How much request body to forward. `0` forwards none, leaving the WAF blind to anything in a body. Buffered per in-flight request, so the worst case is this × `MaxRequestWorkers`. |
| `CrowdsecAppsecBodyLimitAction` | S+D | `drop` | A body over the limit: `drop` blocks it, `bypass` lets it through **uninspected**. |
| `CrowdsecAppsecInternalPath` | S | `/crowdsec-internal/challenge/` | Prefix the challenge serves its assets and submissions from. |

## Known limits

**A gzipped request body is inspected compressed.** The body is captured before
Apache inflates it, so AppSec sees the compressed bytes and rules matching body
content will not fire. The origin still receives correct plaintext. Shared with
the other bouncers.

**`CrowdsecAppsecBodyLimitAction bypass` is a WAF bypass.** Anyone can pad a
request body past the limit to skip inspection. Use `drop` unless you have a
specific reason.

**No captcha.** An AppSec `captcha` remediation is resolved through
`CrowdsecRemediationFallback`, which defaults to `ban`.

**Stream decisions are enforced as a ban.** The decision stream carries no
interstitial, so a `challenge` or `captcha` decision from the local API becomes
a ban rather than being served.

**A new decision is not instant**, and the delay differs by mode.

In `stream` mode the worst case is `CrowdsecUpdateFrequency` +
`CrowdsecLocalCacheTimeout` — **12s** with the defaults. A request arriving just
before the poller picks the decision up misses the shared store and caches an
allow in that child's memo, and is served from it until the memo expires. It is
per child: others block as soon as the pull lands.

In `live` mode the worst case is `CrowdsecCacheTimeout` +
`CrowdsecLocalCacheTimeout` — **62s** with the defaults, because the shared
entry and the memo seeded from it expire independently.

`CrowdsecLocalCacheTimeout` is the knob for propagation speed; it costs only
extra shared-cache reads. `CrowdsecCacheTimeout` governs API traffic in live
mode, so lowering that one makes every child query the API more often.

**One child pays for the stream pull.** The child holding the polling lease
allocates roughly 4.6× the stream body size while applying it, and keeps that
as a high-water mark. Measured: a 27 MB body (≈185,000 entries) takes the
polling child from 24 MB to 149 MB resident. Other children are unaffected.
Budget for it on memory-constrained hosts with large blocklists.

**AppSec throughput is bound by the engine.** Inspection adds a round trip plus
rule evaluation. Measured on 2 vCPU with 202 rules loaded: 0.65 ms mean per
inspection, capping throughput around 1,500 req/s, of which the module accounts
for ~3%. Tune the rule set, not the bouncer.

**The challenge interstitial is ~327 KB per unsolved visitor.** On a public
site this is a bandwidth consideration before it is a CPU one.

**An internal redirect is inspected headers-only.** A request reaching a
protected scope through `mod_rewrite` or `ErrorDocument` has already had its
body consumed, so only its headers and URI go to AppSec. The decision lookup
still applies in full.

**`CrowdsecLocation` and `CrowdsecAppsecInternalPath` are untested.** They work
as described but have no automated coverage.
