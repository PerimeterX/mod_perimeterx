#include "px_enforcer.h"
#include <apr_strings.h>
#include <http_log.h>
#include <util_cookies.h>

#include "px_payload.h"
#include "px_json.h"
#include "px_utils.h"
#include "px_client.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *PX_PAYLOAD_COOKIE_V1_PREFIX = "_px";
static const char *PX_PAYLOAD_COOKIE_V3_PREFIX = "_px3";
static const char *CAPTCHA_COOKIE = "_pxCaptcha";

static const char *NO_TOKEN = "1";
static const char *MOBILE_SDK_CONNECTION_ERROR = "2";
static const char *MOBILE_SDK_PINNING_ERROR = "3";

static const char* FILE_EXT_WHITELIST[] = {
    ".css", ".bmp", ".tif", ".ttf", ".docx", ".woff2", ".js", ".pict", ".tiff", ".eot", ".xlsx", ".jpg", ".csv",
    ".eps", ".woff", ".xls", ".jpeg", ".doc", ".ejs", ".otf", ".pptx", ".gif", ".pdf", ".swf", ".svg", ".ps",
    ".ico", ".pls", ".midi", ".svgz", ".class", ".png", ".ppt", ".mid", "webp", ".jar"
};

static const char *LOGGER_DEBUG_FORMAT = "[PerimeterX - DEBUG][%s] - %s";
static const char *LOGGER_ERROR_FORMAT = "[PerimeterX - ERROR][%s] - %s";

static action_t parseBlockAction(const char* act) {
    if (act && act[0] == 'j') {
        return ACTION_CHALLENGE;
    }
    return (act && act[0] == 'b') ? ACTION_BLOCK : ACTION_CAPTCHA;
}

static void set_call_reason(request_context *ctx, validation_result_t vr) {
    switch (vr) {
        case VALIDATION_RESULT_NULL_PAYLOAD:
            ctx->call_reason = CALL_REASON_NO_PAYLOAD;
            break;
        case VALIDATION_RESULT_EXPIRED:
            ctx->call_reason = CALL_REASON_EXPIRED_PAYLOAD;
            break;
        case VALIDATION_RESULT_DECRYPTION_FAILED:
            ctx->call_reason = CALL_REASON_PAYLOAD_DECRYPTION_FAILED;
            break;
        case VALIDATION_RESULT_INVALID:
            ctx->call_reason = CALL_REASON_PAYLOAD_VALIDATION_FAILED;
            break;
        case VALIDATION_RESULT_MOBILE_SDK_CONNECTION_ERROR:
            ctx->call_reason = CALL_REASON_MOBILE_SDK_CONNECTION_ERROR;
            break;
        case VALIDATION_RESULT_MOBILE_SDK_PINNING_ERROR:
            ctx->call_reason = CALL_REASON_MOBILE_SDK_PINNING_ERROR;
            break;
        default:
            ctx->call_reason = CALL_REASON_PAYLOAD_VALIDATION_FAILED;
            break;
    }
}

static bool is_sensitive_route(request_rec *r, px_config *conf) {
    apr_array_header_t *sensitive_routes = conf->sensitive_routes;
    for (int i = 0; i < sensitive_routes->nelts; i++) {
        char *route = APR_ARRAY_IDX(sensitive_routes, i, char*);
        if (strcmp(r->uri, route) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_sensitive_route_prefix(request_rec *r, px_config *conf) {
    apr_array_header_t *sensitive_routes_prefix = conf->sensitive_routes_prefix;
    for (int i = 0; i < sensitive_routes_prefix->nelts; i++) {
        char *prefix = APR_ARRAY_IDX(sensitive_routes_prefix, i, char*);
        if (strncmp(r->uri, prefix, strlen(prefix)) == 0) {
            return true;
        }
    }
    return false;
}

static bool enable_block_for_hostname(request_rec *r, apr_array_header_t *domains_list) {
    // domains list not configured, module will be enabled globally and not per domain
    if (domains_list->nelts == 0) return true;
    const char *req_hostname = r->hostname;
    if (req_hostname == NULL) return true;
    for (int i = 0; i < domains_list->nelts; i++) {
        const char *domain = APR_ARRAY_IDX(domains_list, i, const char*);
        if (strcmp(req_hostname, domain) == 0) {
            return true;
        }
    }
    return false;
}

bool verify_captcha(request_context *ctx, px_config *conf) {
    if (!ctx->px_captcha) {
        return false;
    }

    // preventing reuse of captcha cookie by deleting it
    apr_status_t res = ap_cookie_remove(ctx->r, CAPTCHA_COOKIE, NULL, ctx->r->headers_out, ctx->r->err_headers_out, NULL);
    if (res != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Could not remove _pxCaptcha from request");
    }

    char *payload = create_captcha_payload(ctx, conf);
    if (!payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "verify_captcha: failed to format captcha payload. url: ", ctx->full_url, NULL));
        ctx->pass_reason = PASS_REASON_ERROR;
        return true;
    }

    char *response_str = NULL;
    CURLcode status = post_request(conf->captcha_api_url, payload, conf->captcha_timeout, conf, ctx, &response_str, &ctx->api_rtt);
    free(payload);
    if (status == CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "verify_captcha: server response ", response_str, NULL));
        captcha_response *c = parse_captcha_response(response_str, ctx);
        free(response_str);
        bool passed = (c && c->status == 0);
        if (passed) {
            ctx->pass_reason = PASS_REASON_CAPTCHA;
        }
        return passed;
    }

    if (status == CURLE_OPERATION_TIMEDOUT) {
        ctx->pass_reason = PASS_REASON_CAPTCHA_TIMEOUT;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Captcha response timeout - passing request");
    } else {
        ctx->pass_reason = PASS_REASON_ERROR;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "verify_captcha: failed to perform captcha validation request. url: ", ctx->full_url, NULL));
    }

    return false;
}

bool px_should_verify_request(request_rec *r, px_config *conf) {
    if (!conf->module_enabled) {
        return false;
    }

    if (conf->block_page_url && strcmp(r->uri, conf->block_page_url) == 0) {
        return false;
    }

    const char *file_ending = strrchr(r->uri, '.');
    if (file_ending) {
        const apr_array_header_t *file_exts = conf->custom_file_ext_whitelist;
        if (file_exts->nelts > 0) {
            // using custom file extension whitelist
            for (int i = 0; i < file_exts->nelts; i++) {
                const char *file_ext = APR_ARRAY_IDX(file_exts, i, const char*);
                if (strcmp(file_ending, file_ext) == 0) {
                    return false;
                }
            }
        } else {
            // using default whitelist
            for (int i = 0; i < sizeof(FILE_EXT_WHITELIST)/sizeof(*FILE_EXT_WHITELIST); i++ ) {
                if (strcmp(file_ending, FILE_EXT_WHITELIST[i]) == 0) {
                    return false;
                }
            }
        }
    }

    // checks if request is filtered using PXWhitelistRoutes
    const apr_array_header_t *routes = conf->routes_whitelist;
    for (int i = 0; i < routes->nelts; i++) {
        const char *route = APR_ARRAY_IDX(routes, i, const char*);
        if (strncmp(route, r->parsed_uri.path, strlen(route)) == 0) {
            return false;
        }
    }

    // checks if request is filtered using PXWhitelistUserAgents
    const char *r_useragent = apr_table_get(r->headers_in, "User-Agent");
    if (r_useragent) {
        const apr_array_header_t *useragents = conf->useragents_whitelist;
        for (int i = 0; i < useragents->nelts; i++) {
            const char *useragent = APR_ARRAY_IDX(useragents, i, const char*);
            if (strcmp(useragent, r_useragent) == 0) {
                return false;
            }
        }
    }

    return true;
}

risk_response* risk_api_get(request_context *ctx, px_config *conf) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Evaluating Risk API request, call reason: ", get_call_reason_string(ctx->call_reason), NULL));
    char *risk_payload = create_risk_payload(ctx, conf);
    if (!risk_payload) {
        ctx->pass_reason = PASS_REASON_ERROR;
        return NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "risk payload: ", risk_payload, NULL));

    char *risk_response_str;
    CURLcode status = post_request(conf->risk_api_url, risk_payload, conf->api_timeout_ms, conf, ctx, &risk_response_str, &ctx->api_rtt);
    ctx->made_api_call = true;
    free(risk_payload);
    if (status == CURLE_OK) {
        risk_response *risk_response = parse_risk_response(risk_response_str, ctx);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Risk API response returned successfully, risk score: ", apr_itoa(ctx->r->pool, risk_response->score), NULL));
        free(risk_response_str);
        return risk_response;
    }

    if (status == CURLE_OPERATION_TIMEDOUT) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Risk API timed out");
        ctx->pass_reason = PASS_REASON_S2S_TIMEOUT;
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Unexpected exception in Risk API call.");
        ctx->pass_reason = PASS_REASON_ERROR;
    }

    return NULL;
}

request_context* create_context(request_rec *r, const px_config *conf) {
    request_context *ctx = (request_context*) apr_pcalloc(r->pool, sizeof(request_context));

    ctx->r = r;
    ctx->app_id = conf->app_id;
    ctx->response_application_json = false;

    const char *px_payload1 = NULL;
    const char *px_payload3 = NULL;
    ctx->token_origin = TOKEN_ORIGIN_COOKIE;
    if (conf->enable_token_via_header) {
        int payload_prefix = extract_payload_from_header(r->pool, r->headers_in, &px_payload3, &px_payload1);
        if (payload_prefix > -1) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id , "Mobile SDK token detected");
            ctx->token_origin = TOKEN_ORIGIN_HEADER;
        }
    }
    if (ctx->token_origin == TOKEN_ORIGIN_COOKIE) {
        ap_cookie_read(r, PX_PAYLOAD_COOKIE_V3_PREFIX, &px_payload3, 0);
        ap_cookie_read(r, PX_PAYLOAD_COOKIE_V1_PREFIX, &px_payload1, 0);
    }

    ap_cookie_read(r, CAPTCHA_COOKIE, &ctx->px_captcha, 1);

    ctx->ip = get_request_ip(r, conf);
    if (!ctx->ip) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id , "create_context: request IP is NULL");
    }

    ctx->px_payload1 = apr_pstrdup(r->pool, px_payload1);
    ctx->px_payload3 = apr_pstrdup(r->pool, px_payload3);
    if (px_payload3) {
        ctx->px_payload = px_payload3;
        ctx->px_payload_version = 3;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id , "Cookie V3 found, Evaluating");
    } else if (px_payload1) {
        ctx->px_payload = px_payload1;
        ctx->px_payload_version = 1;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id , "Cookie V1 found, Evaluating");
    }
    ctx->uri = r->unparsed_uri;
    ctx->hostname = r->hostname;
    ctx->http_method = r->method;
    ctx->useragent = apr_table_get(r->headers_in, "User-Agent");
    ctx->action = conf->captcha_enabled ? ACTION_CAPTCHA : ACTION_BLOCK;
    // TODO(barak): full_url is missing the protocol like http:// or https://
    ctx->full_url = apr_pstrcat(r->pool, r->hostname, r->unparsed_uri, NULL);

    // TODO(barak): parse without strtok
    char *saveptr;
    const char *delim = "/";
    char *protocol_cpy = apr_pstrdup(r->pool, r->protocol);
    apr_strtok(protocol_cpy , delim, &saveptr);
    const char *version = apr_strtok(NULL, delim, &saveptr);

    ctx->http_version = version;
    ctx->headers = r->headers_in;
    ctx->block_reason = BLOCK_REASON_NONE;
    ctx->call_reason = CALL_REASON_NONE;
    ctx->pass_reason = PASS_REASON_NONE; // initial value, should always get changed if request passes
    ctx->block_enabled = enable_block_for_hostname(r, conf->enabled_hostnames);

    return ctx;
}

bool px_verify_request(request_context *ctx, px_config *conf) {
    bool request_valid = true;

    risk_response *risk_response;

    if (conf->captcha_enabled && ctx->px_captcha) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Captcha cookie found, evaluating");
        if (verify_captcha(ctx, conf)) {
            // clean users cookie on captcha verification
            apr_status_t res1 = ap_cookie_remove2(ctx->r, PX_PAYLOAD_COOKIE_V1_PREFIX, NULL, ctx->r->headers_out, ctx->r->err_headers_out, NULL);
            if (res1 != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Could not remove _px from request");
            }
            apr_status_t res3 = ap_cookie_remove2(ctx->r, PX_PAYLOAD_COOKIE_V3_PREFIX, NULL, ctx->r->headers_out, ctx->r->err_headers_out, NULL);
            if (res3 != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Could not remove _px3 from request");
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Captcha API response validation status: passed");
            return request_valid;
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Captcha API response validation status: failed");
            ctx->call_reason = CALL_REASON_CAPTCHA_FAILED;
            risk_response = risk_api_get(ctx, conf);
            goto handle_response;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "No Captcha cookie present on the request");
    validation_result_t vr;

    if (ctx->px_payload == NULL || (ctx->token_origin == TOKEN_ORIGIN_HEADER && strcmp(ctx->px_payload, NO_TOKEN) == 0)) {
        vr = VALIDATION_RESULT_NULL_PAYLOAD;
        if (ctx->token_origin == TOKEN_ORIGIN_HEADER) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Mobile special token - no token");
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Cookie is missing");
        }
    } else if (ctx->token_origin == TOKEN_ORIGIN_HEADER && strcmp(ctx->px_payload, MOBILE_SDK_CONNECTION_ERROR) == 0) {
        vr = VALIDATION_RESULT_MOBILE_SDK_CONNECTION_ERROR;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Mobile special token - connection error");
    } else if (ctx->token_origin == TOKEN_ORIGIN_HEADER && strcmp(ctx->px_payload, MOBILE_SDK_PINNING_ERROR) == 0) {
        vr = VALIDATION_RESULT_MOBILE_SDK_PINNING_ERROR;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Mobile special token - pinning issue");
    } else {
        vr = VALIDATION_RESULT_DECRYPTION_FAILED;
        risk_payload *c = decode_payload(ctx->px_payload, conf->payload_key, ctx);
        if (c) {
            ctx->score = c->score;
            ctx->vid = c->vid;
            ctx->uuid = c->uuid;
            ctx->action = parseBlockAction(c->action);
            vr = validate_payload(c, ctx, conf->payload_key);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool,"Cookie decryption failed, value: ", ctx->px_payload, NULL));
            ctx->px_payload_orig = ctx->px_payload;
        }
    }
    switch (vr) {
        case VALIDATION_RESULT_VALID:
            request_valid = ctx->score < conf->blocking_score;
            if (!request_valid) {
                ctx->block_reason = BLOCK_REASON_PAYLOAD;
            } else if (is_sensitive_route_prefix(ctx->r, conf) || is_sensitive_route(ctx->r, conf)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Sensitive route match, sending Risk API. path: ", ctx->uri, NULL));
                ctx->call_reason = CALL_REASON_SENSITIVE_ROUTE;
                risk_response = risk_api_get(ctx, conf);
                goto handle_response;
            } else {
                ctx->pass_reason = PASS_REASON_PAYLOAD;
            }
            break;
        case VALIDATION_RESULT_EXPIRED:
        case VALIDATION_RESULT_DECRYPTION_FAILED:
        case VALIDATION_RESULT_NULL_PAYLOAD:
        case VALIDATION_RESULT_INVALID:
        case VALIDATION_RESULT_MOBILE_SDK_CONNECTION_ERROR:
        case VALIDATION_RESULT_MOBILE_SDK_PINNING_ERROR:
            set_call_reason(ctx, vr);
            risk_response = risk_api_get(ctx, conf);
handle_response:
            if (risk_response) {
                ctx->score = risk_response->score;
                
                if (risk_response->action_data_body){
                    ctx->action_data_body = risk_response->action_data_body;
                }

                if (!ctx->uuid && risk_response->uuid) {
                    ctx->uuid = risk_response->uuid;
                }

                if (risk_response->action) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s] px_verify_request: parsing action (%s)", ctx->app_id, risk_response->action);
                    ctx->action = parseBlockAction(risk_response->action);
                }

                request_valid = ctx->score < conf->blocking_score;
                if (!request_valid) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Risk score is higher or equal to blocking score. score: ", apr_itoa(ctx->r->pool, ctx->score), " blocking score: ",  apr_itoa(ctx->r->pool, conf->blocking_score), NULL));
                    ctx->block_reason = BLOCK_REASON_SERVER;
                } else {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Risk score is lower than blocking score. score: ", apr_itoa(ctx->r->pool, ctx->score), " blocking score: ", apr_itoa(ctx->r->pool, conf->blocking_score), NULL));
                    ctx->pass_reason = PASS_REASON_S2S;
                }
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, LOGGER_ERROR_FORMAT, ctx->app_id, "Unexpected exception while evaluating Risk cookie.");
                return true;
            }
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "px_verify_request: cookie decode failed returning valid result");
            return true;
    }

    return request_valid;
}

#if DEBUG
const char *json_context(request_context *ctx) {
    return context_to_json_string(ctx);
}
#endif
