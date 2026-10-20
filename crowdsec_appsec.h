/* The AppSec (WAF) path: forwarding a request for inspection, capturing and
 * replaying its body, and serving a bot-detection challenge.
 */
#ifndef CROWDSEC_APPSEC_H
#define CROWDSEC_APPSEC_H

#include "crowdsec_config.h"
#include "crowdsec_verdict.h"

typedef enum
{
    CROWDSEC_APPSEC_OK = 0,     /* the engine answered; verdict is filled in */
    CROWDSEC_APPSEC_FAIL,       /* unreachable, unauthorised, or unparseable */
    CROWDSEC_APPSEC_DROP,       /* body over the cap with the drop action */
    CROWDSEC_APPSEC_BADREQ      /* the request itself is unforwardable */
} crowdsec_appsec_res_t;

/* Per-request state, kept in r->request_config. Never in a config struct:
 * those are shared between threads and live for the life of the server.
 */
typedef struct
{
    request_rec *r;             /* identity check for the replay filter */
    char *body;
    apr_size_t body_len;        /* captured, and all of it is replayed */
    apr_size_t inspect_len;     /* offered for inspection: body_len or the cap */
    apr_size_t replay_off;
    apr_status_t read_rv;       /* why the body read failed, if it did */
    unsigned int truncated:1;   /* more body remains on the wire */
    unsigned int filter_installed:1;
    crowdsec_appsec_verdict_t verdict;
} crowdsec_req_rec;

void crowdsec_appsec_register(apr_pool_t *p);

/* True for anything under the prefix the challenge serves itself from.
 * Matched on the decoded path so a traversal cannot dodge it.
 */
int crowdsec_is_challenge_path(const char *uri, const char *prefix);

/* Forwards the request for inspection. Reads the body when the configuration
 * asks for it, which is why it needs the per-request state.
 */
crowdsec_appsec_res_t crowdsec_appsec_check(request_rec *r,
                                            crowdsec_server_rec *sconf,
                                            crowdsec_config_rec *conf,
                                            crowdsec_req_rec *st,
                                            const char *ip);

/* Emits a challenge response and returns DONE, or an HTTP status on failure.
 * Must be the last thing the hook does.
 */
int crowdsec_appsec_serve(request_rec *r, const crowdsec_appsec_verdict_t *v);

/* Puts the captured body back for the real handler. Only on the allow path. */
void crowdsec_appsec_replay(request_rec *r, crowdsec_req_rec *st);

/* For an internal redirect: re-installs the replay filter against a body an
 * earlier request in the chain already captured. Returns the new per-request
 * state, or NULL if no ancestor had a body. See the comment in the body.
 */
crowdsec_req_rec *crowdsec_appsec_inherit_body(request_rec *r);

#endif /* CROWDSEC_APPSEC_H */
