#include "px_json.h"

#include <jansson.h>
#include <apr_pools.h>
#include <http_log.h>
#include <apr_strings.h>

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_perimeterx]:" __VA_ARGS__)

static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";

// format json requests
//

char *create_activity(const char *activity_type, const px_config *conf, const request_context *ctx) {
    json_t *details = json_pack("{s:i, s:s, s:s, s:s, s:s}",
            "block_score", ctx->score,
            "block_reason", BLOCK_REASON_STR[ctx->block_reason],
            "http_method", ctx->http_method,
            "http_version", ctx->http_version,
            "module_version", conf->module_version);


    if (strcmp(activity_type, BLOCKED_ACTIVITY_TYPE) == 0 && ctx->uuid) {
        json_object_set_new(details, "block_uuid", json_string(ctx->uuid));
    } else {
        // adding decrypted cookie to page_requested activity
        if (ctx->px_cookie) {
            json_object_set_new(details, "px_cookie", json_string(ctx->px_cookie_decrypted));
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
    json_t *j_additional = json_pack("{s:s, s:s, s:s, s:s}",
            "s2s_call_reason", S2S_CALL_REASON_STR[ctx->call_reason],
            "http_method", ctx->http_method,
            "http_version", ctx->http_version,
            "module_version", conf->module_version);
    if (ctx->px_cookie) {
        json_object_set_new(j_additional, "px_cookie", json_string(ctx->px_cookie_decrypted));
    }
    if (ctx->px_cookie_orig) {
        json_object_set_new(j_additional, "px_cookie_orig", json_string(ctx->px_cookie_orig));
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
    json_t *j_request = json_pack("{s:s,s:s,s:s,s:O}",
            "ip", ctx->ip,
            "uri", ctx->uri,
            "url", ctx->full_url,
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

    // dump as string
    char *request_str = json_dumps(j_captcha, JSON_COMPACT);
    json_decref(j_captcha);
    return request_str;
}

captcha_response *parse_captcha_response(const char* captcha_response_str, const request_context *ctx) {
    json_error_t j_error;
    json_t *j_response = json_loads(captcha_response_str, 0, &j_error);
    if (!j_response) {
        ERROR(ctx->r->server, "parse_captcha_response: failed to parse. error (%s), response (%s)",
                j_error.text, captcha_response_str);
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
        ERROR(ctx->r->server, "parse_captcha_response: failed to unpack. response (%s)", captcha_response_str);
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
        ERROR(ctx->r->server, "parse_risk_response: failed to parse risk response. (%s)", risk_response_str);
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
        ERROR(ctx->r->server, "parse_risk_response: failed to unpack risk response. (%s)", risk_response_str);
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

