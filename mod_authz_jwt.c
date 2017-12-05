/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This module is triggered by an
 *
 *          AuthGroupFile standard /path/to/file
 *
 * and the presense of a
 *
 *         require group <list-of-groups>
 *
 * In an applicable limit/directory block for that method.
 *
 * If there are no AuthGroupFile directives valid for
 * the request; we DECLINED.
 *
 * If the AuthGroupFile is defined; but somehow not
 * accessible: we SERVER_ERROR (was DECLINED).
 *
 * If there are no 'require ' directives defined for
 * this request then we DECLINED (was OK).
 *
 * If there are no 'require ' directives valid for
 * this request method then we DECLINED. (was OK)
 *
 * If there are any 'require group' blocks and we
 * are not in any group - we HTTP_UNAUTHORIZE
 *
 */

#ifndef HAVE_CONFIG_H
#  include "config.h"
#  undef PACKAGE_NAME
#  undef PACKAGE_STRING
#  undef PACKAGE_TARNAME
#  undef PACKAGE_VERSION
#endif

#include "apr_lib.h" /* apr_isspace */
#include "apr_strings.h"
#include "apr_time.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "mod_auth.h"

#include <jwt.h>


typedef struct {
    const char *jwt_key;
    const char *jwt_alg;
    unsigned int jwt_exp;
} authz_jwt_config_rec;

static const char *jwt_alg_str(jwt_alg_t alg)
{
    switch (alg) {
        case JWT_ALG_NONE:
            return "none";
        case JWT_ALG_HS256:
            return "HS256";
        case JWT_ALG_HS384:
            return "HS384";
        case JWT_ALG_HS512:
            return "HS512";
        case JWT_ALG_RS256:
            return "RS256";
        case JWT_ALG_RS384:
            return "RS384";
        case JWT_ALG_RS512:
            return "RS512";
        case JWT_ALG_ES256:
            return "ES256";
        case JWT_ALG_ES384:
            return "ES384";
        case JWT_ALG_ES512:
            return "ES512";
        default:
            return NULL;
	}
}
static void *create_authz_jwt_dir_config(apr_pool_t *p, char *d)
{
    authz_jwt_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->jwt_exp = 1;
    conf->jwt_alg = NULL;
    conf->jwt_key = NULL;

    return conf;
}

static void *merge_auth_jwt_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    authz_jwt_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    authz_jwt_config_rec *base = basev;
    authz_jwt_config_rec *overrides = overridesv;

    newconf->jwt_key =
            overrides->jwt_key ? overrides->jwt_key : base->jwt_key;

    newconf->jwt_alg =
            overrides->jwt_alg ? overrides->jwt_alg : base->jwt_alg;

    newconf->jwt_exp = overrides->jwt_exp;

    return newconf;
}

static const char *set_jwt_key(cmd_parms *cmd, void *config, const char *jwt_key)
{
    authz_jwt_config_rec *conf = (authz_jwt_config_rec *)config;

    conf->jwt_key = jwt_key;

    return NULL;
}

static const char *set_jwt_alg(cmd_parms *cmd, void *config, const char *jwt_alg)
{
    authz_jwt_config_rec *conf = (authz_jwt_config_rec *)config;

    conf->jwt_alg = jwt_alg;

    return NULL;
}

static const char *set_jwt_exp(cmd_parms *cmd, void *config, const char *jwt_exp)
{
    authz_jwt_config_rec *conf = (authz_jwt_config_rec *)config;

    if (0 == strcasecmp(jwt_exp, "on")) {
        conf->jwt_exp = 1;
    } else if (0 == strcasecmp(jwt_exp, "off")) {
        conf->jwt_exp = 0;
    } else {
        return apr_pstrcat(cmd->pool,
                           cmd->cmd->name, " must be On or Off",
                           NULL);
    }
    return NULL;
}

static const command_rec authz_jwt_cmds[] =
{
        AP_INIT_TAKE1("AuthJwtKey", set_jwt_key, NULL, OR_AUTHCFG, "Key to decode JWT token"),
        AP_INIT_TAKE1("AuthJwtAlg", set_jwt_alg, NULL, OR_AUTHCFG, "(Optional) algorithm in token"),
        AP_INIT_TAKE1("AuthJwtExp", set_jwt_exp, NULL, OR_AUTHCFG, "Enable exp time validation"),
        {NULL}
};

module AP_MODULE_DECLARE_DATA authz_jwt_module;

static authz_status jwt_check_authorization(request_rec *r,
                                                  const char *require_args,
                                                  const void *parsed_require_args)
{
    authz_jwt_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_jwt_module);
    int res;
    jwt_t* jwt;
    const char *auth_line, *auth_scheme;

    /* We need at least a key in the configuration to decode the token */
    if (!(conf->jwt_key)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01664) "JWT : No key in the configuration");
        return AUTHZ_DENIED;
    }

    /* Get the appropriate header */
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                             ? "Proxy-Authorization"
                                             : "Authorization");

    if (!auth_line) {
        return AUTHZ_DENIED;
    }

    auth_scheme = ap_getword(r->pool, &auth_line, ' ');
    if (strcasecmp(auth_scheme, "JWT") && strcasecmp(auth_scheme, "Bearer")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01614) "JWT : wrong authentication scheme: %s", r->uri);
        return AUTHZ_DENIED;
    }

    /* Skip leading spaces. */
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }

    /* Decode JWT token */
    res = jwt_decode(&jwt, auth_line, conf->jwt_key, strlen(conf->jwt_key));
    if (res) {
        jwt_free(jwt);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01664) "JWT : unable to decode token");
        return AUTHZ_DENIED;
    }

    /* Verify algorithm if alg check enabled */
    if (conf->jwt_alg && strcasecmp(jwt_alg_str(jwt_get_alg(jwt)), conf->jwt_alg)) {
        jwt_free(jwt);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01664) "JWT : algorithm does not match the expecting one");
        return AUTHZ_DENIED;
    }

    /* Verify expiration date if exp check enabled */
    if (conf->jwt_exp && jwt_get_grant_int(jwt, "exp") < apr_time_sec(r->request_time)) {
        jwt_free(jwt);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01664) "JWT : token has expired");
        return AUTHZ_DENIED;
    }

    jwt_free(jwt);

    return AUTHZ_GRANTED;
}

static const authz_provider authz_jwt_provider =
{
    &jwt_check_authorization,
    NULL,
};


static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-jwt-token",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_jwt_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_jwt) =
{
        STANDARD20_MODULE_STUFF,
        create_authz_jwt_dir_config, /* dir config creater */
        merge_auth_jwt_dir_config,   /* dir merger -- default is to override */
        NULL,                        /* server config */
        NULL,                        /* merge server config */
        authz_jwt_cmds,              /* command apr_table_t */
        register_hooks               /* register hooks */
};
