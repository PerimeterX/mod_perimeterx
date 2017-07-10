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
    bool score_header_enabled;
    const char *score_header_name;
    long api_timeout_ms;
    bool is_captcha_timeout_set;
    long captcha_timeout;
    bool send_page_activities;
    const char *module_version;
    curl_pool *curl_pool;
    int curl_pool_size;
    const char *proxy_url;
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

    bool px_service_monitor;
    apr_thread_mutex_t *health_check_cond_mutex;
    apr_thread_t *health_check_thread;
    apr_thread_cond_t *health_check_cond;
    int px_errors_threshold;
    volatile apr_uint32_t px_errors_count;
    long health_check_interval; // in ms
} px_config;

typedef struct health_check_data_t {
    server_rec *server;
    px_config *config;
} health_check_data;

typedef struct activity_consumer_data_t {
    px_config *config;
    server_rec *server;
} activity_consumer_data;

typedef enum {
    VALIDATION_RESULT_VALID,
    VALIDATION_RESULT_NO_SIGNING,
    VALIDATION_RESULT_EXPIRED,
    VALIDATION_RESULT_INVALID,
    VALIDATION_RESULT_DECRYPTION_FAILED,
    VALIDATION_RESULT_NULL_COOKIE
} validation_result_t;

typedef enum call_reason_t {
    CALL_REASON_NONE,
    CALL_REASON_NO_COOKIE,
    CALL_REASON_EXPIRED_COOKIE,
    CALL_REASON_COOKIE_DECRYPTION_FAILED,
    CALL_REASON_COOKIE_VALIDATION_FAILED,
    CALL_REASON_SENSITIVE_ROUTE,
    CALL_REASON_CAPTCHA_FAILED,
} call_reason_t;

typedef enum {
    PASS_REASON_NONE,
    PASS_REASON_COOKIE,
    PASS_REASON_TIMEOUT,
    PASS_REASON_S2S,
    PASS_REASON_S2S_TIMEOUT,
    PASS_REASON_CAPTCHA,
    PASS_REASON_CAPTCHA_TIMEOUT,
    PASS_REASON_ERROR,
} pass_reason_t;

typedef enum {
    BLOCK_REASON_NONE,
    BLOCK_REASON_COOKIE,
    BLOCK_REASON_SERVER,
} block_reason_t;

typedef enum {
    TOKEN_ORIGIN_COOKIE,
    TOKEN_ORIGIN_HEADER,
} token_origin_t;

typedef enum {
    ACTION_CAPTCHA,
    ACTION_BLOCK,
} action_t;

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
    const char *uuid;
    int status;
    int score;
    const char *action;
} risk_response;

typedef struct captcha_response_t {
    int status;
    const char *uuid;
    const char *vid;
    const char *cid;
} captcha_response;

typedef struct request_context_t {
    const char *app_id;
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
    call_reason_t call_reason;
    pass_reason_t pass_reason;
    bool block_enabled;
    bool made_api_call;
    request_rec *r;
    double api_rtt;
    token_origin_t token_origin;
    action_t action;
} request_context;

#endif
