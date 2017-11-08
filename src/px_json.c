#include "px_json.h"

#include <jansson.h>
#include <apr_pools.h>
#include <http_log.h>
#include <apr_strings.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";
static const char *MONITOR_MODE = "monitor";
static const char *ACTIVE_BLOCKING_MODE = "active_blocking";

// using cookie as value instead of payload, changing it will effect the collector
static const char *PASS_REASON_STR[] = {
    [PASS_REASON_NONE] = "none",
    [PASS_REASON_PAYLOAD] = "cookie",
    [PASS_REASON_TIMEOUT] = "timeout",
    [PASS_REASON_S2S] = "s2s",
    [PASS_REASON_S2S_TIMEOUT] = "s2s_timeout",
    [PASS_REASON_CAPTCHA] = "captcha",
    [PASS_REASON_CAPTCHA_TIMEOUT] = "captcha_timeout",
    [PASS_REASON_ERROR] = "error",
    [PASS_REASON_MONITOR_MODE] = "monitor_mode",
};

// using cookie as value instead of payload, changing it will effect the collector
static const char *CALL_REASON_STR[] = {
    [CALL_REASON_NONE] = "none",
    [CALL_REASON_NO_PAYLOAD] = "no_cookie",
    [CALL_REASON_EXPIRED_PAYLOAD] = "cookie_expired",
    [CALL_REASON_PAYLOAD_DECRYPTION_FAILED] = "cookie_decryption_failed",
    [CALL_REASON_PAYLOAD_VALIDATION_FAILED] = "cookie_validation_failed",
    [CALL_REASON_SENSITIVE_ROUTE] = "sensitive_route",
    [CALL_REASON_CAPTCHA_FAILED] = "captcha_failed",
    [CALL_REASON_MOBILE_SDK_CONNECTION_ERROR] = "mobile_sdk_connection_error",
};

// using cookie as value instead of payload, changing it will effect the collector
static const char *BLOCK_REASON_STR[] = {
    [BLOCK_REASON_NONE] = "none",
    [BLOCK_REASON_PAYLOAD] = "cookie_high_score",
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
    [CAPTCHA_TYPE_FUNCAPTCHA] = "funCaptcha",
};


static bool is_sensitive_header(char *key, apr_array_header_t* sensitive_headers){
    for (int i = 0; i < sensitive_headers->nelts; i++) {
        const char *sensitive_header = APR_ARRAY_IDX(sensitive_headers, i, const char*);
        if (!strcmp(sensitive_header, key)) {
            return true;
        }
    }
    return false;
}

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
        // adding decrypted payload to page_requested activity
        if (ctx->px_payload) {
            json_object_set_new(details, "px_cookie", json_string(ctx->px_payload_decrypted));
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
        if (!is_sensitive_header(h.key, conf->sensitive_header_keys)) {
            json_object_set_new(j_headers, h.key, json_string(h.val));
        }
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

json_t *headers_to_json_helper(const apr_array_header_t *arr,apr_array_header_t *sensitive_headers) {
    json_t *j_headers = json_array();
    // Extract all headers and jsonfy it
    if (arr) {
        for (int i = 0; i < arr->nelts; i++) {
            apr_table_entry_t h = APR_ARRAY_IDX(arr, i, apr_table_entry_t);
            if (!is_sensitive_header(h.key, sensitive_headers)) {
                json_t *j_header = json_object();
                json_object_set_new(j_header, "name", json_string(h.key));
                json_object_set_new(j_header, "value", json_string(h.val));
                json_array_append_new(j_headers, j_header);
            }
        }
    }
    return j_headers;
}

json_t *config_array_to_json_array(const apr_array_header_t *arr) {
    json_t *j_headers = json_array();
    // Extract all headers and jsonfy it
    if (arr) {
        for (int i = 0; i < arr->nelts; i++) {
            char *h = APR_ARRAY_IDX(arr, i, char*);
            json_array_append_new(j_headers, json_string(h));
        }
    }
    return j_headers;
}

static apr_array_header_t *json_arr_to_arr_helper(const json_t *j_arr, apr_pool_t *pool, px_config *conf, server_rec *server) {
    if(!json_is_array(j_arr)){
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "[%s]: json_arr_to_arr_helper: failed to to get array", conf->app_id);
        return NULL;
    }

    size_t j_size = json_array_size(j_arr);
    apr_array_header_t *apr_arr = apr_array_make(pool, j_size, sizeof(const char*));

    for (int i = 0; i < j_size; i++) {
        json_t *elem = json_array_get(j_arr, i);
        const char** entry = apr_array_push(apr_arr);
        *entry = apr_pstrdup(pool, json_string_value(elem));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "[%s]: json_arr_to_arr_helper: json data is %s", conf->app_id, json_string_value(elem));
    }

    return apr_arr;
}

char *create_risk_payload(const request_context *ctx, const px_config *conf) {
    // headers array
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    json_t *j_headers = headers_to_json_helper(header_arr, conf->sensitive_header_keys);

    // request object
    json_t *j_request = json_pack("{s:s,s:s,s:s,s:O}",
            "ip", ctx->ip,
            "uri", ctx->uri,
            "url", ctx->full_url,
            "headers", j_headers);
    json_decref(j_headers);

    const char *module_mode = conf->monitor_mode ? MONITOR_MODE : ACTIVE_BLOCKING_MODE;

    // additional object
    json_t *j_additional = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s}",
            "s2s_call_reason", CALL_REASON_STR[ctx->call_reason],
            "http_method", ctx->http_method,
            "http_version", ctx->http_version,
            "module_version", conf->module_version,
            "risk_mode", module_mode,
            "cookie_origin", TOKEN_ORIGIN_STR[ctx->token_origin]);

    if (ctx->px_payload) {
        json_object_set_new(j_additional, "px_cookie", json_string(ctx->px_payload_decrypted));
    }
    if (ctx->px_payload_orig) {
        json_object_set_new(j_additional, "px_cookie_orig", json_string(ctx->px_payload_orig));
    }
    if (ctx->px_payload_hmac) {
        json_object_set_new(j_additional, "px_cookie_hmac", json_string(ctx->px_payload_hmac));
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
    json_t *j_headers = headers_to_json_helper(header_arr, conf->sensitive_header_keys);

    // request object
    json_t *j_request = json_pack("{s:s,s:s,s:s,s:s,s:O}",
            "ip", ctx->ip,
            "uri", ctx->uri,
            "url", ctx->full_url,
            "captchaType", CAPTCHA_TYPE_STR[conf->captcha_type],
            "headers", j_headers);
    json_decref(j_headers);

    // captcha object
    json_t *j_captcha = json_object();
    json_object_set_new(j_captcha, "request", j_request);

    if (ctx->px_captcha) {
        json_object_set_new(j_captcha, "pxCaptcha", json_string(ctx->px_captcha));
    }
    if (ctx->hostname) {
        json_object_set_new(j_captcha, "hostname", json_string(ctx->hostname));
    }
    if (ctx->api_rtt) {
        json_object_set_new(j_captcha, "risk_rtt", json_integer(ctx->api_rtt));
    }

    json_t *j_additional = json_pack("{s:s}",
            "module_version", conf->module_version);

    json_object_set_new(j_captcha, "additional", j_additional);

    // dump as string
    char *request_str = json_dumps(j_captcha, JSON_COMPACT);
    json_decref(j_captcha);
    return request_str;
}

captcha_response *parse_captcha_response(const char* captcha_response_str, const request_context *ctx) {
    json_error_t j_error;
    json_t *j_response = json_loads(captcha_response_str, 0, &j_error);
    if (!j_response) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server,
                "[%s]: parse_captcha_response: failed to parse. error (%s), response (%s)", ctx->app_id, j_error.text, captcha_response_str);
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server,
                "[%s]: parse_captcha_response: failed to unpack. response (%s)", ctx->app_id, captcha_response_str);
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

remote_config *parse_remote_config(apr_pool_t *pool, const char* remote_config_str, px_config *conf, server_rec *server) {
    json_error_t j_error;
    json_t *j_response = json_loads(remote_config_str, 0, &j_error);
    if (!j_response) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "[%s]: parse_remote_config: failed to remote_config response (%s)", conf->app_id, remote_config_str);
        return NULL;
    }

    char *cookie_key = NULL, *app_id = NULL, *module_mode = NULL, *checksum = NULL;
    int blocking_score = 0, debug_mode = 0, module_enabled = 0, risk_timeout = 0, connect_timeout = 0;

    if (json_unpack(j_response, "{s:b,s:s,s:i,s:s,s:s,s:i,s:i,s:b,s:s}",
                "moduleEnabled", &module_enabled,
                "cookieKey", &cookie_key,
                "blockingScore", &blocking_score,
                "appId", &app_id,
                "moduleMode", &module_mode,
                "connectTimeout", &connect_timeout,
                "riskTimeout", &risk_timeout,
                "debugMode", &debug_mode,
                "checksum", &checksum )) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "[%s]: parse_remote_config: failed to unpack remote config response (%s)", conf->app_id, remote_config_str);
        json_decref(j_response);
        return NULL;
    }

    remote_config *remote_conf = apr_palloc(pool, sizeof(remote_config));

    if (remote_conf) {
        remote_conf->module_enabled = module_enabled ? true : false;
        remote_conf->cookie_key = apr_pstrdup(pool, cookie_key);
        remote_conf->blocking_score = blocking_score;
        remote_conf->app_id = apr_pstrdup(pool, app_id);
        remote_conf->module_mode = apr_pstrdup(pool, module_mode);
        remote_conf->connect_timeout = connect_timeout;
        remote_conf->risk_timeout = risk_timeout;
        remote_conf->debug_mode = debug_mode ? true : false;
        remote_conf->checksum = apr_pstrdup(pool, checksum);

        remote_conf->ip_header_keys = json_arr_to_arr_helper(json_object_get(j_response, "ipHeaders"), pool, conf, server);
        remote_conf->sensitive_header_keys = json_arr_to_arr_helper(json_object_get(j_response, "sensitiveHeaders"), pool, conf, server);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "[%s]: parse_remote_remote_config: parsed response module_mode[%i] cookie_key[%s] blocking_score[%i] app_id[%s] module_mode[%s] connect_timeout[%ld] risk_timeout[%ld] debug_mode[%i] checksum[%s]", conf->app_id, remote_conf->module_enabled, remote_conf->cookie_key, remote_conf->blocking_score, remote_conf->app_id, remote_conf->module_mode, remote_conf->connect_timeout, remote_conf->risk_timeout, remote_conf->debug_mode, remote_conf->checksum);
    }

    json_decref(j_response);

    return remote_conf;
}

risk_response* parse_risk_response(const char* risk_response_str, const request_context *ctx) {
    json_error_t j_error;
    json_t *j_response = json_loads(risk_response_str, 0, &j_error);
    if (!j_response) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server,
                "[%s]: parse_risk_response: failed to parse risk response (%s)", ctx->app_id, risk_response_str);
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server,
                "[%s]: parse_risk_response: failed to unpack risk response (%s)", ctx->app_id, risk_response_str);
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

    if (ctx->vid) {
        json_object_set_new(j_response, "vid", json_string(ctx->vid));
    }

    if (ctx->uuid) {
        json_object_set_new(j_response, "uuid", json_string(ctx->uuid));
    }

    char *request_str = json_dumps(j_response, JSON_COMPACT);
    json_decref(j_response);
    return request_str;
}

char* config_to_json_string(px_config *cfg, const char *update_reason) {
    json_error_t error;
    json_t *ctx_json = json_object();
    json_t *details_json = json_object();
    json_t *config_json = json_object();

    json_object_set(config_json, "app_id", json_string(cfg->app_id));
    json_object_set(config_json, "module_enabled", json_boolean(cfg->module_enabled));
    json_object_set(config_json, "api_timeout_ms", json_integer(cfg->api_timeout_ms));
    json_object_set(config_json, "captcha_timeout", json_integer(cfg->captcha_timeout));
    json_object_set(config_json, "send_page_activities", json_boolean(cfg->send_page_activities));
    json_object_set(config_json, "blocking_score", json_integer(cfg->blocking_score));
    json_object_set(config_json, "captcha_enabled", json_boolean(cfg->captcha_enabled));
    json_object_set(config_json, "module_version", json_string(cfg->module_version));
    json_object_set(config_json, "skip_mod_by_envvar", json_boolean(cfg->skip_mod_by_envvar));
    json_object_set(config_json, "curl_pool_size", json_integer(cfg->curl_pool_size));
    json_object_set(config_json, "base_url", json_string(cfg->base_url));
    json_object_set(config_json, "risk_api_url", json_string(cfg->risk_api_url));
    json_object_set(config_json, "captcha_api_url", json_string(cfg->captcha_api_url));
    json_object_set(config_json, "activities_api_url", json_string(cfg->activities_api_url));
    json_object_set(config_json, "auth_header", json_string(cfg->auth_header));
    json_object_set(config_json, "routes_whitelist", config_array_to_json_array(cfg->routes_whitelist));
    json_object_set(config_json, "useragents_whitelist", config_array_to_json_array(cfg->useragents_whitelist));
    json_object_set(config_json, "custom_file_ext_whitelist", config_array_to_json_array(cfg->custom_file_ext_whitelist));
    json_object_set(config_json, "ip_header_keys", config_array_to_json_array(cfg->ip_header_keys));
    json_object_set(config_json, "sensitive_header_keys", config_array_to_json_array(cfg->sensitive_header_keys));
    json_object_set(config_json, "sensitive_routes", config_array_to_json_array(cfg->sensitive_routes));
    json_object_set(config_json, "enabled_hostnames", config_array_to_json_array(cfg->enabled_hostnames));
    json_object_set(config_json, "sensitive_routes_prefix", config_array_to_json_array(cfg->sensitive_routes_prefix));
    json_object_set(config_json, "background_activity_send", json_boolean(cfg->background_activity_send));
    json_object_set(config_json, "background_activity_workers", json_integer(cfg->background_activity_workers));
    json_object_set(config_json, "background_activity_queue_size", json_integer(cfg->background_activity_queue_size));
    json_object_set(config_json, "px_errors_threshold", json_integer(cfg->px_errors_threshold));
    json_object_set(config_json, "health_check_interval", json_integer(cfg->health_check_interval));
    json_object_set(config_json, "px_health_check", json_boolean(cfg->px_health_check));
    json_object_set(config_json, "score_header_name", json_string(cfg->score_header_name));
    json_object_set(config_json, "vid_header_enabled", json_boolean(cfg->vid_header_enabled));
    json_object_set(config_json, "uuid_header_enabled", json_boolean(cfg->uuid_header_enabled));
    json_object_set(config_json, "uuid_header_name", json_string(cfg->uuid_header_name));
    json_object_set(config_json, "vid_header_name", json_string(cfg->vid_header_name));
    json_object_set(config_json, "json_response_enabled", json_boolean(cfg->json_response_enabled));
    json_object_set(config_json, "cors_headers_enabled", json_boolean(cfg->cors_headers_enabled));
    json_object_set(config_json, "captcha_type", json_integer(cfg->captcha_type));
    json_object_set(config_json, "monitor_mode", json_boolean(cfg->monitor_mode));
    json_object_set(config_json, "enable_token_via_header", json_boolean(cfg->enable_token_via_header));
    json_object_set(config_json, "remote_config_enabled", json_boolean(cfg->remote_config_enabled));
    json_object_set(config_json, "remote_config_url", json_string(cfg->remote_config_url));
    json_object_set(config_json, "remote_config_interval_ms", json_integer(cfg->remote_config_interval_ms));
    json_object_set(config_json, "custom_logo", json_string(cfg->custom_logo));
    json_object_set(config_json, "css_ref", json_string(cfg->css_ref));
    json_object_set(config_json, "js_ref", json_string(cfg->js_ref));
    json_object_set(config_json, "block_page_url", json_string(cfg->block_page_url));
    json_object_set(config_json, "proxy_url", json_string(cfg->proxy_url));
    json_object_set(config_json, "score_header_enabled", json_boolean(cfg->score_header_enabled));

    json_object_set(details_json, "module_version", json_string(cfg->module_version));
    json_object_set(details_json, "update_reason", json_string(update_reason));
    json_object_set(details_json, "enforcer_configs", config_json);


    apr_time_t timems = apr_time_now() / 1000;
    char tztimems[20];
    snprintf(tztimems, sizeof(tztimems), "%"APR_TIME_T_FMT, timems);

    json_object_set(ctx_json, "type", json_string("enforcer_telemetry"));
    json_object_set(ctx_json, "timestamp", json_string(tztimems));
    json_object_set(ctx_json, "app_id", json_string(cfg->app_id));
    json_object_set(ctx_json, "details", details_json);

    char *context_str = json_dumps(ctx_json, JSON_ENCODE_ANY);
    json_decref(ctx_json);

    return context_str;
}

#ifdef DEBUG
const char* context_to_json_string(request_context *ctx) {
    json_error_t error;
    json_t *px_payloads, *headers, *ctx_json;

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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server,
                "[%s]: context_to_json_string error: %s", ctx->app_id, error.text);
        return NULL;
    }

    // nullable fields
    if (ctx->vid) {
        json_object_set_new(ctx_json, "vid", json_string(ctx->vid));
    }
    if (ctx->uuid) {
        json_object_set_new(ctx_json, "uuid", json_string(ctx->uuid));
    }
    if (ctx->px_payload) {
        json_t *px_payloads = json_pack("{ ss }", "v1", ctx->px_payload);
        json_object_set_new(ctx_json, "px_cookies", px_payloads);
    }
    if (ctx->px_payload_decrypted) {
        json_object_set_new(ctx_json, "decoded_px_cookie", json_string(ctx->px_payload_decrypted));
    }
    if (ctx->px_captcha) {
        json_object_set_new(ctx_json, "px_captcha", json_string(ctx->px_captcha));
    }

    const char *context_str = json_dumps(ctx_json, JSON_ENCODE_ANY);
    json_decref(ctx_json);
    json_decref(px_payloads);

    return context_str;
}
#endif
