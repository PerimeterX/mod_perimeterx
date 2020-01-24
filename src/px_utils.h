#ifndef PX_UTILS_H
#define PX_UTILS_H

#include <http_protocol.h>
#include <apr_pools.h>
#include <http_log.h>
#include <openssl/hmac.h>
#include "px_types.h"

#if defined(__GNUC__)
#  define UNUSED __attribute__((__unused__))
#else
#  define UNUSED
#endif

struct response_t {
    char* data;
    size_t size;
    server_rec *server;
    request_rec *r;
    apr_array_header_t *headers;
    const char *app_id;
    apr_pool_t *pool;
};

const char *get_request_ip(const request_rec *r, const px_config *conf);
const char *pescape_urlencoded(apr_pool_t *p, const char *str);
int extract_payload_from_header(apr_pool_t *pool, apr_table_t *headers, const char **payload3, const char **payload1);
CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long connect_timeout, long timeout, px_config *conf, server_rec *server, char **response_data);
CURLcode redirect_helper(CURL* curl, const char *base_url, const char *uri, const char *vid, px_config *conf, request_rec *r, const char **response_data,  apr_array_header_t **response_headers, int *content_size);
size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream);
size_t write_response_pool_cb(void* contents, size_t size, size_t nmemb, void *stream);
void update_and_notify_health_check(px_config *conf);


#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
#endif

bool px_hmac_str(const char *key, const char *str, char *signature, int signature_len);

/* Logging */
#define LOGGER_ERROR_HDR "[PerimeterX - ERROR][%s] - %s: %s"
#define LOGGER_DEBUG_HDR "[PerimeterX - DEBUG][%s] - %s: %s"

void px_log(const px_config *conf, apr_pool_t *pool, bool log_debug, int level, const char *func, const char *fmt, ...);

// logging macros (not thread-safe !)
#define px_log_error(...) px_log(conf, conf->pool, 0, conf->log_level_err, __FUNCTION__, "%s", __VA_ARGS__)
#define px_log_error_fmt(fmt, ...) px_log(conf, conf->pool, 0, conf->log_level_err, __FUNCTION__, fmt, __VA_ARGS__)
#define px_log_debug(...) px_log(conf, conf->pool, 1, conf->log_level_debug, __FUNCTION__, "%s", __VA_ARGS__)
#define px_log_debug_fmt(fmt, ...) px_log(conf, conf->pool, 1, conf->log_level_debug, __FUNCTION__, fmt, __VA_ARGS__)

// logging macros (thread-safe)
#define px_log_thd(conf,  pool, log_debug, level, func, fmt, ...) \
    do { \
        if (!conf) { \
            break; \
        } \
        if (conf->remote_config_lock) {  \
            apr_thread_rwlock_rdlock(conf->remote_config_lock); \
        } \
        px_log(conf, pool, log_debug, level, func, fmt, __VA_ARGS__); \
        if (conf->remote_config_lock) {  \
            apr_thread_rwlock_unlock(conf->remote_config_lock); \
        } \
    } while(0)
#define px_log_error_thd(...) px_log_thd(conf,  pool, 0, conf->log_level_err, __FUNCTION__, "%s", __VA_ARGS__)
#define px_log_error_thd_fmt(fmt, ...) px_log_thd(conf,  pool, 0, conf->log_level_err, __FUNCTION__, fmt, __VA_ARGS__)
#define px_log_debug_thd(...) px_log_thd(conf,  pool, 1, conf->log_level_debug, __FUNCTION__, "%s", __VA_ARGS__)
#define px_log_debug_thd_fmt(fmt, ...) px_log_thd(conf,  pool, 1, conf->log_level_debug, __FUNCTION__, fmt, __VA_ARGS__)

#endif
