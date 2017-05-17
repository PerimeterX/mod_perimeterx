#ifndef PX_TYPES_H
#define PX_TYPES_H

#include <stdbool.h>
#include <apr_tables.h>
#include <http_protocol.h>
#include <apr_thread_pool.h>
#include <apr_queue.h>

#include "curl_pool.h"

typedef struct px_config_t {
    const char *app_id;
    const char *cookie_key;
    const char *auth_token;
    const char *block_page_url;
    const char *base_url;
    const char *risk_api_url;
    const char *captcha_api_url;
    const char *activities_api_url;
    const char *css_ref;
    const char *js_ref;
    const char *custom_logo;
    char *auth_header;
    bool module_enabled;
    bool captcha_enabled;
    bool skip_mod_by_envvar;
    int blocking_score;
    long api_timeout;
    bool send_page_activities;
    const char *module_version;
    curl_pool *curl_pool;
    int curl_pool_size;
    apr_array_header_t *routes_whitelist;
    apr_array_header_t *useragents_whitelist;
    apr_array_header_t *custom_file_ext_whitelist;
    apr_array_header_t *ip_header_keys;
    apr_array_header_t *sensitive_routes;
    apr_array_header_t *sensitive_routes_prefix;
    apr_array_header_t *enabled_hostnames;
    bool background_activity_send;
    int background_activity_workers;
    int background_activity_queue_size;
    apr_queue_t *activity_queue;
    apr_thread_pool_t *activity_thread_pool;
} px_config;

typedef struct activity_consumer_data_t {
    px_config *config;
    server_rec *server;
} activity_consumer_data;

typedef enum {
    VALID,
    NO_SIGNING,
    EXPIRED,
    INVALID,
    DECRYPTION_FAILED,
    NULL_COOKIE
} validation_result_t;

typedef enum s2s_call_reason_t {
    NONE,
    NO_COOKIE,
    EXPIRED_COOKIE,
    COOKIE_DECRYPTION_FAILED,
    COOKIE_VALIDATION_FAILED,
    SENSITIVE_ROUTE,
    CAPTCHA_FAILED
} s2s_call_reason_t;

typedef enum {
    DIDNT_PASS,
    PASSED_WITH_COOKIE,
    PASSED_WITH_TIMEOUT,
    PASSED_WITH_S2S,
    PASSED_WITH_S2S_TIMEOUT,
    PASSED_WITH_CAPTCHA,
    PASSED_WITH_CAPTCHA_TIMEOUT,
    PASSED_WITH_ERROR
} pass_reason_t;

static const char *PASS_REASON_STR[] = {
    "none",
    "cookie",
    "timeout",
    "s2s",
    "s2s_timeout",
    "captcha",
    "captcha_timeout",
    "error"
};

static const char *S2S_CALL_REASON_STR[] = {
    "none",
    "no_cookie",
    "cookie_expired",
    "cookie_decryption_failed",
    "cookie_validation_failed",
    "sensitive_route",
    "captcha_failed"
};

typedef enum {
    NO_BLOCKING,
    COOKIE,
    SERVER
} block_reason_t;

static const char *BLOCK_REASON_STR[] = {
    "none",
    "cookie_high_score",
    "s2s_high_score"
};

typedef struct risk_cookie_t {
    const char *timestamp;
    long long ts;
    const char *hash;
    const char *uuid;
    const char *vid;
    const char *a;
    const char *b;
    int a_val;
    int b_val;
} risk_cookie;

typedef struct risk_response_t {
    const char* uuid;
    int status;
    int score;
} risk_response;

typedef struct captcha_response_t {
    int status;
    const char *uuid;
    const char *vid;
    const char *cid;
} captcha_response;

typedef struct request_context_t {
    const char *px_cookie;
    const char *px_cookie_decrypted;
    const char *px_captcha;
    const char *ip;
    const char *vid;
    const char *uuid;
    apr_table_t *headers;
    const char *hostname;
    const char *uri;
    const char *useragent;
    const char *full_url;
    const char *http_method;
    const char *http_version;
    const char *px_cookie_orig;
    int score;
    block_reason_t block_reason;
    s2s_call_reason_t call_reason;
    pass_reason_t pass_reason;
    bool block_enabled;
    request_rec *r;
} request_context;

#endif
