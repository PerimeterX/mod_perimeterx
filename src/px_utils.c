#include "px_utils.h"

#include <arpa/inet.h>
#include <apr_strings.h>
#include <http_log.h>

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_perimeterx]:" __VA_ARGS__)

size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream) {
    struct response_t *res = (struct response_t*)stream;
    size_t realsize = size * nmemb;
    res->data = realloc(res->data, res->size + realsize + 1);
    if (res->data == NULL) {
        ERROR(res->server, "not enough memory for post_request buffer alloc");
        return 0;
    }
    memcpy(&(res->data[res->size]), contents, realsize);
    res->size += realsize;
    res->data[res->size] = 0;
    return realsize;
}

const char* extract_first_ip(apr_pool_t *p, const char *ip) {
    const char *first_ip = ip;
    while (*first_ip == ' ') {
        first_ip++;
    }
    const char *sep = first_ip;
    while (*sep && *sep != ' ' && *sep != ',') {
        sep++;
    }
    if (*sep) {
        first_ip = apr_pstrndup(p, first_ip, sep - first_ip);
    }
    return first_ip;
}

const char *get_request_ip(const request_rec *r, const px_config *conf) {
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    const char* socket_ip =  r->useragent_ip;
# else
    const char* socket_ip = r->connection->remote_ip;
#endif
    const apr_array_header_t *ip_header_keys = conf->ip_header_keys;
    // looking for the first valid ip address in the configured IPHeader list
    for (int i = 0; i < ip_header_keys->nelts; i++) {
        const char *ip_header_key = APR_ARRAY_IDX(ip_header_keys, i, const char*);
        const char *ip = apr_table_get(r->headers_in, ip_header_key);
        if (ip) {
            // extracting the first ip if there header contains a list of ip separated by commas
            const char *first_ip = extract_first_ip(r->pool, ip);
            // validation ip
            in_addr_t addr;
            if (inet_pton(AF_INET, first_ip, &addr) == 1 || inet_pton(AF_INET6, first_ip, &addr) == 1) {
                return first_ip;
            }
        }
    }
    // no valid ip found in IPHeader values - using socket_ip as a fallback
    return socket_ip;
}
