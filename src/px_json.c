#include "px_json.h"

#include <jansson.h>
#include <apr_pools.h>
#include <http_log.h>
#include <apr_strings.h>

static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";

static const char *PASS_REASON_STR[] = {
    [PASS_REASON_NONE] = "none",
    [PASS_REASON_COOKIE] = "cookie",
    [PASS_REASON_TIMEOUT] = "timeout",
    [PASS_REASON_S2S] = "s2s",
    [PASS_REASON_S2S_TIMEOUT] = "s2s_timeout",
    [PASS_REASON_CAPTCHA] = "captcha",
    [PASS_REASON_CAPTCHA_TIMEOUT] = "captcha_timeout",
    [PASS_REASON_ERROR] = "error",
};

static const char *CALL_REASON_STR[] = {
    [CALL_REASON_NONE] = "none",
    [CALL_REASON_NO_COOKIE] = "no_cookie",
    [CALL_REASON_EXPIRED_COOKIE] = "cookie_expired",
    [CALL_REASON_COOKIE_DECRYPTION_FAILED] = "cookie_decryption_failed",
    [CALL_REASON_COOKIE_VALIDATION_FAILED] = "cookie_validation_failed",
    [CALL_REASON_SENSITIVE_ROUTE] = "sensitive_route",
    [CALL_REASON_CAPTCHA_FAILED] = "captcha_failed",
};

static const char *BLOCK_REASON_STR[] = {
    [BLOCK_REASON_NONE] = "none",
    [BLOCK_REASON_COOKIE] = "cookie_high_score",
    [BLOCK_REASON_SERVER] = "s2s_high_score",
};

static const char *TOKEN_ORIGIN_STR[] = {
    [TOKEN_ORIGIN_COOKIE] = "cookie",
    [TOKEN_ORIGIN_HEADER] = "header",
};

static const char *ACTION_STR[] = {
    [ACTION_CAPTCHA] = "captcha",
    [ACTION_BLOCK] = "block",
};

static const char *CAPTCHA_TYPE_STR[] = {
    [CAPTCHA_TYPE_RECAPTCHA] = "reCaptcha",
};

// format json requests
//
char *create_activity(const char *activity_type, const px_config *conf, const request_context *ctx) {
    json_t *details = json_pack("{s:i, s:s, s:s, s:s, s:s}",
            "block_score", ctx->score,
            "block_reason", BLOCK_REASON_STR[ctx->block_reason],
            "http_method", ctx->http_method,
            "http_version", ctx->http_version,
            "module_version", conf->module_version,
            "cookie_origin", TOKEN_ORIGIN_STR[ctx->token_origin]);

    if (strcmp(activity_type, BLOCKED_ACTIVITY_TYPE) == 0 && ctx->uuid) {
        json_object_set_new(details, "block_uuid", json_string(ctx->uuid));
    } else {
        // adding decrypted cookie to page_requested activity
        if (ctx->px_cookie) {
            json_object_set_new(details, "px_cookie", json_string(ctx->px_cookie_decrypted));
        }

        if (ctx->api_rtt) {
            json_object_set_new(details, "risk_rtt", json_integer(ctx->api_rtt * 1000)); // seconds to ms
        }

        // adding uuid to page_requested activity
        if (ctx->uuid) {
            json_object_set_new(details, "client_uuid", json_string(ctx->uuid));
        }

        const char *pass_reason_str = PASS_REASON_STR[ctx->pass_reason];
        json_object_set_new(details, "pass_reason", json_string(pass_reason_str));

    }

    // Extract all headers and jsonfy it
    json_t *j_headers = json_object();
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    for (int i = 0; i < header_arr->nelts; i++) {
        apr_table_entry_t h = APR_ARRAY_IDX(header_arr, i, apr_table_entry_t);
        json_object_set_new(j_headers, h.key, json_string(h.val));
    }

    json_t *activity = json_pack("{s:s, s:s, s:s, s:s, s:O, s:O}",
            "type", activity_type,
            "socket_ip", ctx->ip,
            "url", ctx->full_url,
            "px_app_id", conf->app_id,
            "details", details,
            "headers", j_headers);

    json_decref(details);
    json_decref(j_headers);

    if (ctx->vid) {
        json_object_set_new(activity, "vid", json_string(ctx->vid));
    }

    char *request_str = json_dumps(activity, JSON_COMPACT);

    json_decref(activity);
    return request_str;
}

json_t *headers_to_json_helper(const apr_array_header_t *arr) {
    json_t *j_headers = json_array();
    // Extract all headers and jsonfy it
    if (arr) {
        for (int i = 0; i < arr->nelts; i++) {
            apr_table_entry_t h = APR_ARRAY_IDX(arr, i, apr_table_entry_t);
            json_t *j_header = json_object();
            json_object_set_new(j_header, "name", json_string(h.key));
            json_object_set_new(j_header, "value", json_string(h.val));
            json_array_append_new(j_headers, j_header);
        }
    }
    return j_headers;
}

char *create_risk_payload(const request_context *ctx, const px_config *conf) {
    // headers array
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    json_t *j_headers = headers_to_json_helper(header_arr);

    // request object
    json_t *j_request = json_pack("{s:s,s:s,s:s,s:O}",
            "ip", ctx->ip,
            "uri", ctx->uri,
            "url", ctx->full_url,
            "headers", j_headers);
    json_decref(j_headers);

    // additional object
    json_t *j_additional = json_pack("{s:s, s:s, s:s, s:s, s:s}",
            "s2s_call_reason", CALL_REASON_STR[ctx->call_reason],
            "http_method", ctx->http_method,
            "http_version", ctx->http_version,
            "module_version", conf->module_version,
            "cookie_origin", TOKEN_ORIGIN_STR[ctx->token_origin]);

    if (ctx->px_cookie) {
        json_object_set_new(j_additional, "px_cookie", json_string(ctx->px_cookie_decrypted));
    }
    if (ctx->px_cookie_orig) {
        json_object_set_new(j_additional, "px_cookie_orig", json_string(ctx->px_cookie_orig));
    }

    // risk api object
    json_t *j_risk = json_pack("{s:O,s:O}",
            "request", j_request,
            "additional", j_additional);
    json_decref(j_request);
    json_decref(j_additional);

    if (ctx->vid) {
        json_object_set_new(j_risk, "vid", json_string(ctx->vid));
    }
    if (ctx->uuid) {
        json_object_set_new(j_risk, "uuid", json_string(ctx->uuid));
    }

    char *request_str = json_dumps(j_risk, JSON_COMPACT);
    json_decref(j_risk);
    return request_str;
}

char *create_captcha_payload(const request_context *ctx, const px_config *conf) {
    // headers array
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    json_t *j_headers = headers_to_json_helper(header_arr);

    // request object
    json_t *j_request = json_pack("{s:s,s:s,s:s,s:s,s:O}",
            "ip", ctx->ip,
            "uri", ctx->uri,
            "url", ctx->full_url,
            "captchaType", CAPTCHA_TYPE_STR[ctx->captcha_type],
            "headers", j_headers);
    json_decref(j_headers);

    // captcha object
    json_t *j_captcha = json_object();
    json_object_set_new(j_captcha, "request", j_request);
    if (ctx->vid) {
        json_object_set_new(j_captcha, "vid", json_string(ctx->vid));
    }
    if (ctx->uuid) {
        json_object_set_new(j_captcha, "uuid", json_string(ctx->uuid));
    }
    if (ctx->px_captcha) {
        json_object_set_new(j_captcha, "pxCaptcha", json_string(ctx->px_captcha));
    }
    if (ctx->hostname) {
        json_object_set_new(j_captcha, "hostname", json_string(ctx->hostname));
    }
    if (ctx->api_rtt) {
        json_object_set_new(j_captcha, "risk_rtt", json_integer(ctx->api_rtt));
    }

    // dump as string
    char *request_str = json_dumps(j_captcha, JSON_COMPACT);
    json_decref(j_captcha);
    return request_str;
}

captcha_response *parse_captcha_response(const char* captcha_response_str, const request_context *ctx) {
    json_error_t j_error;
    json_t *j_response = json_loads(captcha_response_str, 0, &j_error);
    if (!j_response) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: parse_captcha_response: failed to parse. error (%s), response (%s)", ctx->app_id, j_error.text, captcha_response_str);
        return NULL;
    }

    int status = -1;
    const char *uuid = NULL;
    const char *vid = NULL;
    const char *cid = NULL;
    if (json_unpack(j_response, "{s:i,s?s,s?s,s?s}",
                "status", &status,
                "uuid", &uuid,
                "cid", &cid,
                "vid", &vid)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: parse_captcha_response: failed to unpack. response (%s)", ctx->app_id, captcha_response_str);
        json_decref(j_response);
        return NULL;
    }

    captcha_response *parsed_response = (captcha_response*)apr_palloc(ctx->r->pool, sizeof(captcha_response));
    if (parsed_response) {
        parsed_response->status = status;
        parsed_response->uuid = apr_pstrdup(ctx->r->pool, uuid);
        parsed_response->vid = apr_pstrdup(ctx->r->pool, vid ? vid : "");
        parsed_response->cid = apr_pstrdup(ctx->r->pool, cid);
    }
    json_decref(j_response);
    return parsed_response;
}

risk_response* parse_risk_response(const char* risk_response_str, const request_context *ctx) {
    json_error_t j_error;
    json_t *j_response = json_loads(risk_response_str, 0, &j_error);
    if (!j_response) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: parse_risk_response: failed to parse risk response (%s)", ctx->app_id, risk_response_str);
        return NULL;
    }

    int status = -1;
    int score = 0;
    const char *uuid = NULL;
    const char *action = NULL;
    if (json_unpack(j_response, "{s:i,s:s,s:i,s:s}",
                "status", &status,
                "uuid", &uuid,
                "score", &score,
                "action", &action
                )) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: parse_risk_response: failed to unpack risk response (%s)", ctx->app_id, risk_response_str);
        json_decref(j_response);
        return NULL;
    }

    risk_response *parsed_response = (risk_response*)apr_palloc(ctx->r->pool, sizeof(risk_response));
    if (parsed_response) {
        parsed_response->uuid = apr_pstrdup(ctx->r->pool, uuid);
        parsed_response->status = status;
        parsed_response->score = score;
        parsed_response->action = action;
    }
    json_decref(j_response);
    return parsed_response;
}

char *create_mobile_response(px_config *cfg, request_context *ctx, const char *compiled_html) {
    json_t *j_mobile_response = json_pack("{s:s,s:s,s:s,s:s}",
            "action", ACTION_STR[ctx->action],
            "appId", ctx->app_id,
            "page", compiled_html,
            "collectorUrl", cfg->base_url);

    if (ctx->vid) {
        json_object_set_new(j_mobile_response, "vid", json_string(ctx->vid));
    }
    if (ctx->uuid) {
        json_object_set_new(j_mobile_response, "uuid", json_string(ctx->uuid));
    }

    // dump as string
    char *request_str = json_dumps(j_mobile_response, JSON_COMPACT);
    json_decref(j_mobile_response);
    return request_str;
}

char *create_json_response(px_config *cfg, request_context *ctx) {
    json_t *j_response = json_pack("{}");

    if (cfg->vid_header_enabled && ctx->vid) {
        json_object_set_new(j_response, "vid", json_string(ctx->vid));
    }

    if (cfg->uuid_header_enabled && ctx->uuid) {
        json_object_set_new(j_response, "uuid", json_string(ctx->uuid));
    }

    char *request_str = json_dumps(j_response, JSON_COMPACT);
    json_decref(j_response);
    return request_str;
}

#ifdef DEBUG
const char* context_to_json_string(request_context *ctx) {
    json_error_t error;
    json_t *px_cookies, *headers, *ctx_json;

    // format headers as key:value in JSON
    headers = json_object();
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    if (header_arr) {
        for (int i = 0; i < header_arr->nelts; i++) {
            apr_table_entry_t h = APR_ARRAY_IDX(header_arr, i, apr_table_entry_t);
            json_object_set(headers, h.key, json_string(h.val));
        }
    }

    ctx_json = json_pack_ex(&error, JSON_DECODE_ANY, "{ss, ss, ss, ss, ss, ss, ss, ss, ss, si, ss, sb, sb, sO}",
            "ip", ctx->ip,
            "hostname", ctx->hostname,
            "full_url", ctx->full_url,
            "http_version", ctx->http_version,
            "http_method", ctx->http_method,
            "block_reason", BLOCK_REASON_STR[ctx->block_reason],
            "s2s_call_reason", CALL_REASON_STR[ctx->call_reason],
            "pass_reason", PASS_REASON_STR[ctx->pass_reason],
            "useragent", ctx->useragent,
            "score", ctx->score,
            "uri", ctx->uri,
            "is_made_s2s_api_call", ctx->made_api_call,
            "sensitive_route", ctx->call_reason == CALL_REASON_SENSITIVE_ROUTE,
            "headers", headers);
    json_decref(headers);

    if (!ctx_json) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: context_to_json_string error: %s", ctx->app_id, error.text);
        return NULL;
    }

    // nullable fields
    if (ctx->vid) {
        json_object_set_new(ctx_json, "vid", json_string(ctx->vid));
    }
    if (ctx->uuid) {
        json_object_set_new(ctx_json, "uuid", json_string(ctx->uuid));
    }
    if (ctx->px_cookie) {
        json_t *px_cookies = json_pack("{ ss }", "v1", ctx->px_cookie);
        json_object_set_new(ctx_json, "px_cookies", px_cookies);
    }
    if (ctx->px_cookie_decrypted) {
        json_object_set_new(ctx_json, "decoded_px_cookie", json_string(ctx->px_cookie_decrypted));
    }
    if (ctx->px_captcha) {
        json_object_set_new(ctx_json, "px_captcha", json_string(ctx->px_captcha));
    }

    const char *context_str = json_dumps(ctx_json, JSON_ENCODE_ANY);
    json_decref(ctx_json);
    json_decref(px_cookies);

    return context_str;
}
#endif
