/* Every directive this module accepts, and the per-directory and per-server
 * structures they fill in. Nothing here runs on the request path.
 */
/*
 * MIT License
 *
 * Copyright (c) 2024 Graham Leggett
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "crowdsec_config.h"

#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_mpm.h"

#include "apr_strings.h"

#include "crowdsec_appsec.h"
#include "crowdsec_http.h"
#include "crowdsec_lapi.h"
#include "crowdsec_util.h"

/* must be last: see the file for why */
#include "crowdsec_poison.h"
/* ------------------------------------------------------------ config */

void *create_crowdsec_dir_config(apr_pool_t *p, char *d)
{
    /* Defaults are deliberately not seeded here: a value set in the creator is
     * indistinguishable from one an administrator wrote, which breaks the
     * *_set merge for child scopes. Each is resolved at the point of use.
     */
    return apr_pcalloc(p, sizeof(crowdsec_config_rec));
}

#define MERGE(field)                                                    \
    new->field = (add->field##_set == 0) ? base->field : add->field;    \
    new->field##_set = add->field##_set || base->field##_set

void *merge_crowdsec_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    crowdsec_config_rec *new = apr_pcalloc(p, sizeof(crowdsec_config_rec));
    crowdsec_config_rec *add = addv;
    crowdsec_config_rec *base = basev;

    MERGE(enable);
    MERGE(fallback);
    MERGE(location);
    MERGE(blockedhttpcode);
    MERGE(remediation_fallback);
    MERGE(trust_useragent_ip);
    MERGE(appsec_enable);
    MERGE(appsec_always_send);
    MERGE(appsec_failure_action);
    MERGE(appsec_body_limit);
    MERGE(appsec_body_limit_action);

    return new;
}

void *create_crowdsec_server_config(apr_pool_t *p, server_rec *s)
{
    crowdsec_server_rec *conf = apr_pcalloc(p, sizeof(crowdsec_server_rec));

    conf->cache_timeout = CROWDSEC_CACHE_TIMEOUT_DEFAULT;
    conf->update_frequency = CROWDSEC_UPDATE_FREQ_DEFAULT;
    conf->connect_timeout = CROWDSEC_CONNECT_TIMEOUT_DEFAULT;
    conf->timeout = CROWDSEC_TIMEOUT_DEFAULT;
    conf->mode = CROWDSEC_MODE_LIVE;
    conf->appsec_path = CROWDSEC_APPSEC_PATH_DEFAULT;
    conf->appsec_internal_path = CROWDSEC_APPSEC_INTERNAL_DEFAULT;
    conf->appsec_connect_timeout = CROWDSEC_APPSEC_CONNECT_TIMEOUT_DEFAULT;
    conf->appsec_timeout = CROWDSEC_APPSEC_TIMEOUT_DEFAULT;

    return conf;
}

void *merge_crowdsec_server_config(apr_pool_t *p, void *basev,
                                          void *addv)
{
    crowdsec_server_rec *new = apr_pcalloc(p, sizeof(crowdsec_server_rec));
    crowdsec_server_rec *add = addv;
    crowdsec_server_rec *base = basev;

    MERGE(url);
    MERGE(key);
    MERGE(mode);
    MERGE(update_frequency);
    MERGE(connect_timeout);
    MERGE(timeout);
    MERGE(cache_timeout);
    MERGE(appsec_path);
    MERGE(appsec_connect_timeout);
    MERGE(appsec_timeout);
    MERGE(appsec_internal_path);

    /* appsec_socket is derived from appsec_url, so they move together. */
    new->appsec_url = (add->appsec_url_set == 0)
        ? base->appsec_url : add->appsec_url;
    new->appsec_socket = (add->appsec_url_set == 0)
        ? base->appsec_socket : add->appsec_socket;
    new->appsec_url_set = add->appsec_url_set || base->appsec_url_set;

    /* provider and instance travel together. */
    new->cache_provider = (add->cache_provider_set == 0)
        ? base->cache_provider : add->cache_provider;
    new->cache_instance = (add->cache_provider_set == 0)
        ? base->cache_instance : add->cache_instance;
    new->cache_provider_set = add->cache_provider_set
        || base->cache_provider_set;

    return new;
}

/* ------------------------------------------------------- directives */

static const char *set_crowdsec(cmd_parms *cmd, void *dconf, int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->enable = flag;
    conf->enable_set = 1;

    return NULL;
}

static const char *set_crowdsec_trust_useragent_ip(cmd_parms *cmd, void *dconf,
                                                   int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->trust_useragent_ip = flag;
    conf->trust_useragent_ip_set = 1;

    return NULL;
}

static const char *set_crowdsec_fallback(cmd_parms *cmd, void *dconf,
                                         const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(arg, "fail")) {
        conf->fallback = CROWDSEC_FAIL;
    }
    else if (!strcmp(arg, "block")) {
        conf->fallback = CROWDSEC_BLOCK;
    }
    else if (!strcmp(arg, "allow")) {
        conf->fallback = CROWDSEC_ALLOW;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecFallback '%s'. Valid "
                            "values are fail, block and allow.", arg);
    }
    conf->fallback_set = 1;

    return NULL;
}

static const char *set_crowdsec_remediation_fallback(cmd_parms *cmd,
                                                     void *dconf,
                                                     const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(arg, "ban")) {
        conf->remediation_fallback = CROWDSEC_REM_BAN;
    }
    else if (!strcmp(arg, "allow")) {
        conf->remediation_fallback = CROWDSEC_REM_ALLOW;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecRemediationFallback "
                            "'%s'. Valid values are ban and allow.", arg);
    }
    conf->remediation_fallback_set = 1;

    return NULL;
}

static const char *set_crowdsec_blockedhttpcode(cmd_parms *cmd, void *dconf,
                                                const char *arg)
{
    crowdsec_config_rec *conf = dconf;
    apr_off_t code;

    /* Not atoi: it cannot tell "0" from "banana", and zero is OK here, which
     * Apache spells as "allow".
     */
    if (!crowdsec_parse_size(arg, &code)) {
        return apr_psprintf(cmd->pool, "CrowdsecBlockedHTTPCode '%s' is not a "
                            "number.", arg);
    }
    switch (code) {
    case HTTP_TOO_MANY_REQUESTS:
    case HTTP_FORBIDDEN:
    case HTTP_INTERNAL_SERVER_ERROR:
        conf->blockedhttpcode = (http_code) code;
        break;
    default:
        return apr_psprintf(cmd->pool, "Unknown CrowdsecBlockedHTTPCode '%s'. "
                            "Valid values are 403, 500 and 429.", arg);
    }
    conf->blockedhttpcode_set = 1;

    return NULL;
}

static const char *set_crowdsec_location(cmd_parms *cmd, void *dconf,
                                         const char *arg)
{
    crowdsec_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->location = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
                                       &expr_err, NULL);
    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in CrowdsecLocation: ",
                           expr_err, NULL);
    }
    conf->location_set = 1;

    return NULL;
}

static const char *set_crowdsec_url(cmd_parms *cmd, void *dconf,
                                    const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    apr_size_t len;

    if (!*arg) {
        return "CrowdsecURL must not be empty.";
    }
    /* The URL is concatenated with the endpoint path, so a trailing slash
     * would produce a double slash and a 404 that looks like a bad key.
     */
    len = strlen(arg);
    while (len > 1 && arg[len - 1] == '/') {
        len--;
    }
    sconf->url = apr_pstrmemdup(cmd->pool, arg, len);
    sconf->url_set = 1;

    return NULL;
}

static const char *set_crowdsec_api_key(cmd_parms *cmd, void *dconf,
                                        const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);

    /* Caught here rather than per request: the key goes into a header, and a
     * stray newline in a config file would otherwise inject one.
     */
    if (!crowdsec_hdr_value_ok(arg) || !*arg) {
        return "CrowdsecAPIKey is empty or contains characters that cannot "
            "appear in an HTTP header.";
    }
    sconf->key = arg;
    sconf->key_set = 1;

    return NULL;
}

static const char *set_crowdsec_mode(cmd_parms *cmd, void *dconf,
                                     const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);

    if (!strcmp(arg, "live")) {
        sconf->mode = CROWDSEC_MODE_LIVE;
    }
    else if (!strcmp(arg, "stream")) {
        sconf->mode = CROWDSEC_MODE_STREAM;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecMode '%s'. Valid "
                            "values are live and stream.", arg);
    }
    sconf->mode_set = 1;

    return NULL;
}

static const char *parse_interval(cmd_parms *cmd, const char *arg,
                                 const char *name, apr_interval_time_t max,
                                 apr_interval_time_t *out)
{
    apr_interval_time_t t;

    if (ap_timeout_parameter_parse(arg, &t, "s") != APR_SUCCESS) {
        return apr_psprintf(cmd->pool, "%s '%s' is not a valid duration. Use "
                            "e.g. 200ms, 5s or 2min.", name, arg);
    }
    if (t <= 0) {
        return apr_psprintf(cmd->pool, "%s must be greater than zero.", name);
    }
    if (t > max) {
        return apr_psprintf(cmd->pool, "%s is too large.", name);
    }
    *out = t;

    return NULL;
}

static const char *set_crowdsec_update_frequency(cmd_parms *cmd, void *dconf,
                                                 const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecUpdateFrequency",
                                     apr_time_from_sec(3600),
                                     &sconf->update_frequency);

    if (err) {
        return err;
    }
    sconf->update_frequency_set = 1;

    return NULL;
}

static const char *set_crowdsec_connect_timeout(cmd_parms *cmd, void *dconf,
                                                const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecConnectTimeout",
                                     apr_time_from_sec(60),
                                     &sconf->connect_timeout);

    if (err) {
        return err;
    }
    sconf->connect_timeout_set = 1;

    return NULL;
}

static const char *set_crowdsec_timeout(cmd_parms *cmd, void *dconf,
                                        const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecTimeout",
                                     apr_time_from_sec(300),
                                     &sconf->timeout);

    if (err) {
        return err;
    }
    sconf->timeout_set = 1;

    return NULL;
}

static const char *set_crowdsec_cache(cmd_parms *cmd, void *dconf,
                                      const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *errmsg, *name, *args = ap_strchr_c(arg, ':');

    if (args) {
        name = apr_pstrmemdup(cmd->temp_pool, arg, args - arg);
        args++;
    }
    else {
        name = arg;
    }

    sconf->cache_provider =
        ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, name,
                           AP_SOCACHE_PROVIDER_VERSION);
    if (!sconf->cache_provider) {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecCache provider '%s'. "
                            "Maybe you need to load mod_socache_%s?", name,
                            name);
    }
    errmsg = sconf->cache_provider->create(&sconf->cache_instance, args,
                                           cmd->temp_pool, cmd->pool);
    if (errmsg) {
        return apr_psprintf(cmd->pool, "CrowdsecCache: %s", errmsg);
    }
    sconf->cache_provider_set = 1;
    /* This server_rec created the instance, so it is the one that initialises
     * and destroys it. merge_crowdsec_server_config deliberately does not
     * propagate this bit.
     */
    sconf->cache_owned = 1;

    return NULL;
}

static const char *set_crowdsec_cache_timeout(cmd_parms *cmd, void *dconf,
                                              const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecCacheTimeout",
                                     apr_time_from_sec(86400),
                                     &sconf->cache_timeout);

    if (err) {
        return err;
    }
    sconf->cache_timeout_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec(cmd_parms *cmd, void *dconf, int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->appsec_enable = flag;
    conf->appsec_enable_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_always_send(cmd_parms *cmd, void *dconf,
                                                   int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->appsec_always_send = flag;
    conf->appsec_always_send_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_failure_action(cmd_parms *cmd,
                                                      void *dconf,
                                                      const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(arg, "passthrough")) {
        conf->appsec_failure_action = CROWDSEC_APPSEC_PASSTHROUGH;
    }
    else if (!strcmp(arg, "deny")) {
        conf->appsec_failure_action = CROWDSEC_APPSEC_DENY;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown CrowdsecAppsecFailureAction "
                            "'%s'. Valid values are passthrough and deny.",
                            arg);
    }
    conf->appsec_failure_action_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_body_limit(cmd_parms *cmd, void *dconf,
                                                  const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!crowdsec_parse_size(arg, &conf->appsec_body_limit)) {
        return apr_psprintf(cmd->pool, "CrowdsecAppsecBodyLimit '%s' is not a "
                            "valid size. Use e.g. 1m, 512k or a byte count.",
                            arg);
    }
    conf->appsec_body_limit_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_body_limit_action(cmd_parms *cmd,
                                                         void *dconf,
                                                         const char *arg)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(arg, "drop")) {
        conf->appsec_body_limit_action = CROWDSEC_CAP_DROP;
    }
    else if (!strcmp(arg, "bypass")) {
        conf->appsec_body_limit_action = CROWDSEC_CAP_BYPASS;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown "
                            "CrowdsecAppsecBodyLimitAction '%s'. Valid values "
                            "are drop and bypass.", arg);
    }
    conf->appsec_body_limit_action_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_url(cmd_parms *cmd, void *dconf,
                                           const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    apr_size_t len;

    if (!*arg) {
        return "CrowdsecAppsecURL must not be empty.";
    }

    /* unix:/path/to.sock addresses the socket the engine's listen_socket
     * creates. libcurl still needs a URL for the request line, so a
     * placeholder host is used and the socket carries the connection.
     */
    if (!strncmp(arg, "unix:", 5)) {
        if (!arg[5]) {
            return "CrowdsecAppsecURL unix: needs a socket path.";
        }
        sconf->appsec_socket = apr_pstrdup(cmd->pool, arg + 5);
        sconf->appsec_url = "http://localhost";
    }
    else {
        if (strncmp(arg, "http://", 7) && strncmp(arg, "https://", 8)) {
            return "CrowdsecAppsecURL must begin with http://, https:// or "
                "unix:.";
        }
        /* A trailing slash here plus the leading one in CrowdsecAppsecPath
         * would make a double slash, which the engine answers with 404.
         */
        len = strlen(arg);
        while (len > 1 && arg[len - 1] == '/') {
            len--;
        }
        sconf->appsec_url = apr_pstrmemdup(cmd->pool, arg, len);
        /* Drop any socket a previous unix: form in this scope derived, or
         * libcurl keeps connecting to it and ignores this URL entirely.
         */
        sconf->appsec_socket = NULL;
    }
    sconf->appsec_url_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_path(cmd_parms *cmd, void *dconf,
                                            const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);

    if (arg[0] != '/') {
        return "CrowdsecAppsecPath must begin with a slash.";
    }
    if (!crowdsec_target_ok(arg)) {
        return "CrowdsecAppsecPath contains characters that cannot appear in "
            "a request target.";
    }
    sconf->appsec_path = arg;
    sconf->appsec_path_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_internal_path(cmd_parms *cmd,
                                                     void *dconf,
                                                     const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    apr_size_t len = strlen(arg);

    if (arg[0] != '/' || len < 2) {
        return "CrowdsecAppsecInternalPath must be an absolute path.";
    }
    if (arg[len - 1] != '/') {
        return "CrowdsecAppsecInternalPath must end with a slash.";
    }
    if (!crowdsec_target_ok(arg)) {
        return "CrowdsecAppsecInternalPath contains characters that cannot "
            "appear in a request target.";
    }
    sconf->appsec_internal_path = arg;
    sconf->appsec_internal_path_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_connect_timeout(cmd_parms *cmd,
                                                       void *dconf,
                                                       const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecAppsecConnectTimeout",
                                     apr_time_from_sec(60),
                                     &sconf->appsec_connect_timeout);

    if (err) {
        return err;
    }
    sconf->appsec_connect_timeout_set = 1;

    return NULL;
}

static const char *set_crowdsec_appsec_timeout(cmd_parms *cmd, void *dconf,
                                               const char *arg)
{
    crowdsec_server_rec *sconf =
        ap_get_module_config(cmd->server->module_config, &crowdsec_module);
    const char *err = parse_interval(cmd, arg, "CrowdsecAppsecTimeout",
                                     apr_time_from_sec(60),
                                     &sconf->appsec_timeout);

    if (err) {
        return err;
    }
    sconf->appsec_timeout_set = 1;

    return NULL;
}

const command_rec crowdsec_cmds[] = {
    AP_INIT_FLAG("Crowdsec", set_crowdsec, NULL, RSRC_CONF | ACCESS_CONF,
                 "Check requests in this scope against crowdsec. Default off."),
    AP_INIT_TAKE1("CrowdsecFallback", set_crowdsec_fallback, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "What to do when crowdsec cannot be consulted, including "
                  "before the decision stream has loaded: fail (500), block, "
                  "or allow. Default fail."),
    AP_INIT_TAKE1("CrowdsecBlockedHTTPCode", set_crowdsec_blockedhttpcode,
                  NULL, RSRC_CONF | ACCESS_CONF,
                  "Status returned to a blocked client: 429, 403 or 500. "
                  "Default 429."),
    AP_INIT_TAKE1("CrowdsecRemediationFallback",
                  set_crowdsec_remediation_fallback, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "What an AppSec remediation this component cannot serve "
                  "(captcha, or one defined by the administrator) becomes: ban "
                  "or allow. Default ban. Does not apply to local API "
                  "decisions, which are always enforced as a ban."),
    AP_INIT_TAKE1("CrowdsecLocation", set_crowdsec_location, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "URL or path to redirect a blocked client to. Supports "
                  "expressions, e.g. /blocked?ip=%{REMOTE_ADDR}."),
    AP_INIT_FLAG("CrowdsecTrustUseragentIP",
                 set_crowdsec_trust_useragent_ip, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Trust the client address reported by modules such as "
                 "mod_remoteip. Default on. Turn off to use the connection's "
                 "real peer instead, when no trusted-proxy list is in place."),
    AP_INIT_TAKE1("CrowdsecURL", set_crowdsec_url, NULL, RSRC_CONF,
                  "Base URL of the crowdsec local API, e.g. "
                  "http://localhost:8080."),
    AP_INIT_TAKE1("CrowdsecAPIKey", set_crowdsec_api_key, NULL, RSRC_CONF,
                  "API key for this bouncer, from cscli bouncers add."),
    AP_INIT_TAKE1("CrowdsecMode", set_crowdsec_mode, NULL, RSRC_CONF,
                  "live queries the API per request; stream polls the decision "
                  "stream in the background and needs CrowdsecCache. "
                  "Default live."),
    AP_INIT_TAKE1("CrowdsecUpdateFrequency", set_crowdsec_update_frequency,
                  NULL, RSRC_CONF,
                  "How often to poll the decision stream. Default 10s."),
    AP_INIT_TAKE1("CrowdsecConnectTimeout", set_crowdsec_connect_timeout, NULL,
                  RSRC_CONF,
                  "How long to wait for a connection to the API. Default 1s."),
    AP_INIT_TAKE1("CrowdsecTimeout", set_crowdsec_timeout, NULL, RSRC_CONF,
                  "Total budget for one API request. Default 5s. A stream pull "
                  "is allowed a multiple of this."),
    AP_INIT_TAKE1("CrowdsecCache", set_crowdsec_cache, NULL, RSRC_CONF,
                  "Shared cache for decisions, e.g. shmcb or "
                  "shmcb:crowdsec(16777216). Required by stream mode, where it "
                  "must hold every decision. Measured: 100000 decisions need "
                  "at least 6MB and 1000000 fit in 128MB, so budget about 128 "
                  "bytes per decision for headroom. Too small and decisions "
                  "are silently evicted, leaving those clients unblocked; the "
                  "error log reports it after each pull."),
    AP_INIT_TAKE1("CrowdsecCacheTimeout", set_crowdsec_cache_timeout, NULL,
                  RSRC_CONF,
                  "How long one address's verdict is remembered in-process. "
                  "Default 60s."),
    AP_INIT_TAKE1("CrowdsecAppsecURL", set_crowdsec_appsec_url, NULL,
                  RSRC_CONF,
                  "Address of the AppSec component, e.g. "
                  "http://127.0.0.1:7422 or unix:/run/crowdsec/appsec.sock. "
                  "Unset disables AppSec."),
    AP_INIT_TAKE1("CrowdsecAppsecPath", set_crowdsec_appsec_path, NULL,
                  RSRC_CONF,
                  "Path the AppSec component listens on, matching the "
                  "datasource's path setting. Default /. A 404 from AppSec "
                  "usually means this does not match."),
    AP_INIT_TAKE1("CrowdsecAppsecInternalPath",
                  set_crowdsec_appsec_internal_path, NULL, RSRC_CONF,
                  "Prefix the bot-detection challenge serves its own assets "
                  "and submissions from. Default "
                  "/crowdsec-internal/challenge/. These are always sent to "
                  "AppSec and never to the origin, even where Crowdsec is "
                  "otherwise off, because a challenged visitor cannot "
                  "complete without them."),
    AP_INIT_TAKE1("CrowdsecAppsecConnectTimeout",
                  set_crowdsec_appsec_connect_timeout, NULL, RSRC_CONF,
                  "How long to wait for a connection to AppSec. Default "
                  "200ms."),
    AP_INIT_TAKE1("CrowdsecAppsecTimeout", set_crowdsec_appsec_timeout, NULL,
                  RSRC_CONF,
                  "Total budget for one AppSec request, excluding the time "
                  "spent reading the client's body. Default 1s."),
    AP_INIT_FLAG("CrowdsecAppsec", set_crowdsec_appsec, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Send requests in this scope to AppSec for inspection. "
                 "Default off."),
    AP_INIT_FLAG("CrowdsecAppsecAlwaysSend",
                 set_crowdsec_appsec_always_send, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Inspect even when the client is already blocked. Default "
                 "off, since nothing is gained by inspecting a request that "
                 "will be refused anyway."),
    AP_INIT_TAKE1("CrowdsecAppsecFailureAction",
                  set_crowdsec_appsec_failure_action, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "What to do when AppSec cannot be consulted: passthrough or "
                  "deny. Default passthrough. This is an availability choice, "
                  "not a security one - an attacker who can degrade AppSec "
                  "gains a window with no inspection."),
    AP_INIT_TAKE1("CrowdsecAppsecBodyLimit", set_crowdsec_appsec_body_limit,
                  NULL, RSRC_CONF | ACCESS_CONF,
                  "How much request body to forward for inspection. Default "
                  "1m; 0 forwards none, leaving the WAF blind to anything "
                  "carried in a body. The limit is buffered per request in "
                  "flight, so the worst case is this times MaxRequestWorkers."),
    AP_INIT_TAKE1("CrowdsecAppsecBodyLimitAction",
                  set_crowdsec_appsec_body_limit_action, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "What to do with a body over the limit: drop (default) "
                  "blocks the request; bypass lets it through UNINSPECTED, "
                  "which is a WAF bypass anyone can trigger by padding a "
                  "request body."),
    {NULL}
};
