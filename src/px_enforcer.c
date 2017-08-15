#include "px_enforcer.h"

#include <apr_strings.h>
#include <http_log.h>
#include <util_cookies.h>

#include "px_payload.h"
#include "px_json.h"
#include "px_utils.h"
#include "curl_pool.h"

static const char *PX_PAYLOAD_COOKIE_PREFIX = "_px";
static const char *CAPTCHA_COOKIE = "_pxCaptcha";
static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";

static const char *NO_TOKEN = "1";
static const char *MOBILE_SDK_CONNECTION_ERROR = "2";



static const char* FILE_EXT_WHITELIST[] = {
    ".css", ".bmp", ".tif", ".ttf", ".docx", ".woff2", ".js", ".pict", ".tiff", ".eot", ".xlsx", ".jpg", ".csv",
    ".eps", ".woff", ".xls", ".jpeg", ".doc", ".ejs", ".otf", ".pptx", ".gif", ".pdf", ".swf", ".svg", ".ps",
    ".ico", ".pls", ".midi", ".svgz", ".class", ".png", ".ppt", ".mid", "webp", ".jar"
};

static CURLcode post_request(const char *url, const char *payload, long timeout, px_config *conf, const request_context *ctx, char **response_data, double *request_rtt) {
    CURL *curl = curl_pool_get_wait(conf->curl_pool);
    if (curl == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: post_req_request: could not obtain curl handle", ctx->app_id);
        return CURLE_FAILED_INIT;
    }
    CURLcode status = post_request_helper(curl, url, payload, timeout, conf, ctx->r->server, response_data);
    if (request_rtt) {
        if (CURLE_OK != curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, request_rtt)) {
            *request_rtt = 0;
        }
    }
    curl_pool_put(conf->curl_pool, curl);
    return status;
}

void set_call_reason(request_context *ctx, validation_result_t vr) {
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
    // domains list not configured, module will be enabled globally and not per domainf
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: could not remove _pxCaptcha from request", ctx->app_id);
    }

    char *payload = create_captcha_payload(ctx, conf);
    if (!payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: verify_captcha: failed to format captcha payload. url: (%s)", ctx->app_id, ctx->full_url);
        ctx->pass_reason = PASS_REASON_ERROR;
        return true;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: verify_captcha: request - (%s)", ctx->app_id, payload);
    char *response_str = NULL;
    CURLcode status = post_request(conf->captcha_api_url, payload, conf->captcha_timeout, conf, ctx, &response_str, &ctx->api_rtt);
    free(payload);
    if (status == CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: verify_captcha: server response (%s)", ctx->app_id, response_str);
        captcha_response *c = parse_captcha_response(response_str, ctx);
        free(response_str);
        bool passed = (c && c->status == 0);
        if (passed) {
            ctx->pass_reason = PASS_REASON_CAPTCHA;
        }
        return passed;
    }
    ctx->pass_reason = (status == CURLE_OPERATION_TIMEDOUT) ? PASS_REASON_CAPTCHA_TIMEOUT : PASS_REASON_ERROR;
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: verify_captcha: failed to perform captcha validation request. url: (%s)", ctx->app_id, ctx->full_url);
    return false;
}

static void post_verification(request_context *ctx, px_config *conf, bool request_valid) {
    const char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
    if (strcmp(activity_type, BLOCKED_ACTIVITY_TYPE) == 0 || conf->send_page_activities) {
        char *activity = create_activity(activity_type, conf, ctx);
        if (!activity) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: post_verification: (%s) create activity failed", ctx->app_id, activity_type);
            return;
        }
        if (conf->background_activity_send) {
            apr_queue_push(conf->activity_queue, activity);
        } else {
            post_request(conf->activities_api_url, activity, conf->api_timeout_ms, conf, ctx, NULL, NULL);
            free(activity);
        }
    }
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
    char *risk_payload = create_risk_payload(ctx, conf);
    if (!risk_payload) {
        ctx->pass_reason = PASS_REASON_ERROR;
        return NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: risk payload: %s", ctx->app_id, risk_payload);
    char *risk_response_str;
    CURLcode status = post_request(conf->risk_api_url, risk_payload, conf->api_timeout_ms, conf, ctx, &risk_response_str, &ctx->api_rtt);
    ctx->made_api_call = true;
    free(risk_payload);
    if (status == CURLE_OK) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: risk response: %s", ctx->app_id, risk_response_str);
        risk_response *risk_response = parse_risk_response(risk_response_str, ctx);
        free(risk_response_str);
        return risk_response;
    }
    ctx->pass_reason = (status == CURLE_OPERATION_TIMEDOUT) ? PASS_REASON_S2S_TIMEOUT : PASS_REASON_ERROR;
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: no risk response, status %d", ctx->app_id, status);
    return NULL;
}

request_context* create_context(request_rec *r, const px_config *conf) {
    request_context *ctx = (request_context*) apr_pcalloc(r->pool, sizeof(request_context));

    ctx->r = r;
    ctx->app_id = conf->app_id;
    ctx->captcha_type = CAPTCHA_TYPE_RECAPTCHA;
    ctx->response_application_json = false;

    const char *px_payload = NULL;
    ctx->token_origin = TOKEN_ORIGIN_COOKIE;

    if (conf->enable_token_via_header) {
        int payload_prefix = extract_payload_from_header(r->pool, r->headers_in, &px_payload);
        if (payload_prefix > -1) {
            ctx->token_origin = TOKEN_ORIGIN_HEADER;
        } else {
            ap_cookie_read(r, PX_PAYLOAD_COOKIE_PREFIX, &px_payload, 0);
        }
    } else {
        ap_cookie_read(r, PX_PAYLOAD_COOKIE_PREFIX, &px_payload, 0);
    }


    ap_cookie_read(r, CAPTCHA_COOKIE, &ctx->px_captcha, 1);

    ctx->ip = get_request_ip(r, conf);
    if (!ctx->ip) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: create_context: request IP is NULL", conf->app_id);
    }

    ctx->px_payload = apr_pstrdup(r->pool, px_payload);
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

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: create_context: useragent: (%s), px_payload: (%s), full_url: (%s), hostname: (%s) , http_method: (%s), http_version: (%s), uri: (%s), ip: (%s), block_enabled: (%d)", conf->app_id, ctx->useragent, ctx->px_payload, ctx->full_url, ctx->hostname, ctx->http_method, ctx->http_version, ctx->uri, ctx->ip, ctx->block_enabled);

    return ctx;
}

bool px_verify_request(request_context *ctx, px_config *conf) {
    bool request_valid = true;

    risk_response *risk_response;

    if (conf->captcha_enabled && ctx->px_captcha) {
        if (verify_captcha(ctx, conf)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s] verify_captcha: validation status true", ctx->app_id);
            // clean users cookie on captcha verification
            apr_status_t res = ap_cookie_remove2(ctx->r, PX_PAYLOAD_COOKIE_PREFIX, NULL, ctx->r->headers_out, ctx->r->err_headers_out, NULL);
            if (res != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s] could not remove _px from request", ctx->app_id);
            }
            post_verification(ctx, conf, true);
            return request_valid;
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s] verify_captcha: validation status false, creating risk_api for this request", ctx->app_id);
            ctx->call_reason = CALL_REASON_CAPTCHA_FAILED;
            risk_response = risk_api_get(ctx, conf);
            goto handle_response;
        }
    }

    validation_result_t vr;

    if (ctx->px_payload == NULL || (ctx->token_origin == TOKEN_ORIGIN_HEADER && strcmp(ctx->px_payload, NO_TOKEN) == 0)) {
        vr = VALIDATION_RESULT_NULL_PAYLOAD;
    } else if (ctx->token_origin == TOKEN_ORIGIN_HEADER && strcmp(ctx->px_payload, MOBILE_SDK_CONNECTION_ERROR) == 0) {
        vr = VALIDATION_RESULT_MOBILE_SDK_CONNECTION_ERROR;
    } else {
        risk_payload *c = decode_payload(ctx->px_payload, conf->payload_key, ctx);
        if (c) {
            ctx->score = c->b_val;
            ctx->vid = c->vid;
            ctx->uuid = c->uuid;
            vr = validate_payload(c, ctx, conf->payload_key);
        } else {
            ctx->px_payload_orig = ctx->px_payload;
            vr = VALIDATION_RESULT_DECRYPTION_FAILED;
        }
    }
    switch (vr) {
        case VALIDATION_RESULT_VALID:
            request_valid = ctx->score < conf->blocking_score;
            if (!request_valid) {
                ctx->block_reason = BLOCK_REASON_PAYLOAD;
            } else if (is_sensitive_route_prefix(ctx->r, conf ) || is_sensitive_route(ctx->r, conf)) {
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
            set_call_reason(ctx, vr);
            risk_response = risk_api_get(ctx, conf);
handle_response:
            if (risk_response) {
                ctx->score = risk_response->score;
                if (!ctx->uuid && risk_response->uuid) {
                    ctx->uuid = risk_response->uuid;
                }
                request_valid = ctx->score < conf->blocking_score;
                if (!request_valid) {
                    ctx->block_reason = BLOCK_REASON_SERVER;
                } else {
                    ctx->pass_reason = PASS_REASON_S2S;
                }
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s] px_verify_request: could not complete risk_api request", ctx->app_id);
                return true;
            }
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s] px_verify_request: cookie decode failed returning valid result (%d)", ctx->app_id, vr);
            return true;
    }

    post_verification(ctx, conf, request_valid);
    return request_valid;
}

#if DEBUG
const char *json_context(request_context *ctx) {
    return context_to_json_string(ctx);
}
#endif
