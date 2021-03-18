#ifndef PX_TYPES_H
#define PX_TYPES_H

#include <stdbool.h>
#include <apr_tables.h>
#include <http_protocol.h>
#include <apr_thread_pool.h>
#include <apr_queue.h>
#include <apr_thread_rwlock.h>

#include "curl_pool.h"

typedef struct px_config_t {
    // px module server memory pool
    const server_rec *server;
    apr_pool_t *pool;
    const char *app_id;
    const char *payload_key;
    const char *auth_token;
    const char *block_page_url;
    const char *base_url;
    bool base_url_is_set;
    const char *risk_api_url;
    const char *activities_api_url;
    const char *telemetry_api_url;
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
    long connect_timeout_ms;
    bool send_page_activities;
    const char *module_version;
    curl_pool *curl_pool;
    curl_pool *redirect_curl_pool;
    int curl_pool_size;
    int redirect_curl_pool_size;
    const char *proxy_url;
    apr_array_header_t *routes_whitelist;
    apr_array_header_t *useragents_whitelist;
    apr_array_header_t *custom_file_ext_whitelist;
    apr_array_header_t *ip_header_keys;
    apr_array_header_t *sensitive_routes;
    apr_array_header_t *sensitive_routes_prefix;
    apr_array_header_t *enabled_hostnames;
    apr_array_header_t *sensitive_header_keys;
    bool background_activity_send;
    int background_activity_workers;
    int background_activity_queue_size;
    apr_queue_t *background_activity_queue;
    apr_thread_t *background_activity_thread;
    bool px_health_check;
    apr_thread_mutex_t *health_check_cond_mutex;
    apr_thread_t *health_check_thread;
    apr_thread_cond_t *health_check_cond;
    apr_uint32_t px_errors_threshold;
    volatile apr_uint32_t px_errors_count;
    long health_check_interval; // in ms
    bool should_exit_thread;
    apr_thread_t *remote_config_thread;
    apr_thread_rwlock_t *remote_config_lock;
    bool enable_token_via_header;
    bool uuid_header_enabled;
    bool vid_header_enabled;
    const char *vid_header_name;
    const char *uuid_header_name;
    bool origin_wildcard_enabled;
    const char *origin_envvar_name;
    bool json_response_enabled;
    bool cors_headers_enabled;
    bool monitor_mode;
    bool first_party_enabled;
    bool first_party_xhr_enabled;
    const char *client_path_prefix;
    const char *xhr_path_prefix;
    const char *client_external_path;
    const char *collector_base_uri;
    const char *client_base_uri;
    bool remote_config_enabled;
    const char *remote_config_url;
    int remote_config_interval_ms;
    char *checksum;
    int background_activity_wakeup_fds[2];
    int px_debug;
    int log_level_err;
    int log_level_debug;
    const char *captcha_external_path;
    const char *captcha_internal_path;
    apr_array_header_t *custom_parameters;
} px_config;

typedef struct thread_data_t {
    server_rec *server;
    px_config *conf;
} thread_data;

typedef struct activity_consumer_data_t {
    px_config *conf;
    server_rec *server;
} activity_consumer_data;

typedef enum {
    VALIDATION_RESULT_VALID,
    VALIDATION_RESULT_NO_SIGNING,
    VALIDATION_RESULT_EXPIRED,
    VALIDATION_RESULT_INVALID,
    VALIDATION_RESULT_DECRYPTION_FAILED,
    VALIDATION_RESULT_NULL_PAYLOAD,
    VALIDATION_RESULT_MOBILE_SDK_CONNECTION_ERROR,
    VALIDATION_RESULT_MOBILE_SDK_PINNING_ERROR
} validation_result_t;

typedef enum call_reason_t {
    CALL_REASON_NONE,
    CALL_REASON_NO_PAYLOAD,
    CALL_REASON_EXPIRED_PAYLOAD,
    CALL_REASON_PAYLOAD_DECRYPTION_FAILED,
    CALL_REASON_PAYLOAD_VALIDATION_FAILED,
    CALL_REASON_SENSITIVE_ROUTE,
    CALL_REASON_MOBILE_SDK_CONNECTION_ERROR,
    CALL_REASON_MOBILE_SDK_PINNING_ERROR
} call_reason_t;

typedef enum {
    PASS_REASON_NONE,
    PASS_REASON_PAYLOAD,
    PASS_REASON_TIMEOUT,
    PASS_REASON_S2S,
    PASS_REASON_S2S_TIMEOUT,
    PASS_REASON_ERROR,
    PASS_REASON_MONITOR_MODE,
} pass_reason_t;

typedef enum {
    BLOCK_REASON_NONE,
    BLOCK_REASON_PAYLOAD,
    BLOCK_REASON_SERVER,
} block_reason_t;

typedef enum {
    TOKEN_ORIGIN_COOKIE,
    TOKEN_ORIGIN_HEADER,
} token_origin_t;

typedef enum {
    ACTION_CAPTCHA,
    ACTION_BLOCK,
    ACTION_CHALLENGE,
} action_t;

typedef struct risk_payload_t {
    const char *timestamp;
    long long ts;
    const char *hash;
    const char *uuid;
    const char *vid;
    const char *a;
    const char *b;
    int a_val;
    int b_val;
    const char *action;
    int score;
} risk_payload;

typedef struct risk_response_t {
    const char *uuid;
    int status;
    int score;
    const char *action;
    const char *action_data_body;
} risk_response;

typedef struct request_context_t {
    px_config *conf;
    const char *app_id;
    const char *px_payload;
    const char *px_payload1;
    const char *px_payload3;
    int px_payload_version;
    const char *px_payload_decrypted;
    const char *px_payload_hmac;
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
    const char *px_payload_orig;
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
    bool response_application_json;
    const char *action_data_body;
    const char *captcha_js_src;
} request_context;

typedef struct redirect_response_t {
    const char *content;
    const char *response_content_type;
    int content_size;
    apr_array_header_t *response_headers;
    bool predefined;
    long http_code; // HTTP code of proxy response
} redirect_response;

#endif
