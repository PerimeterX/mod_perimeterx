#include "px_utils.h"

#include <arpa/inet.h>
#include <apr_strings.h>
#include <http_log.h>

static const char *JSON_CONTENT_TYPE = "Content-Type: application/json";
static const char *EXPECT = "Expect:";

CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, const px_config *conf, server_rec *server, char **response_data) {
    struct response_t response;
    struct curl_slist *headers = NULL;
    long status_code;
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    response.data = malloc(1);
    response.size = 0;
    response.server = server;

    headers = curl_slist_append(headers, conf->auth_header);
    headers = curl_slist_append(headers, JSON_CONTENT_TYPE);
    headers = curl_slist_append(headers, EXPECT);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, conf->api_timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &response);
    CURLcode status = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (status == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (status_code == HTTP_OK) {
            if (response_data != NULL) {
                *response_data = response.data;
            } else {
                free(response.data);
            }
            return status;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server, "[%s]: post_request: status: %lu, url: %s", conf->app_id, status_code, url);
        status = CURLE_HTTP_RETURNED_ERROR;
    } else {
        size_t len = strlen(errbuf);
        if (len) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server, "[%s]: post_request failed: %s", conf->app_id, errbuf);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server, "[%s]: post_request failed: %s", conf->app_id, curl_easy_strerror(status));
        }
    }
    free(response.data);
    *response_data = NULL;
    return status;
}

size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream) {
    struct response_t *res = (struct response_t*)stream;
    size_t realsize = size * nmemb;
    res->data = realloc(res->data, res->size + realsize + 1);
    if (res->data == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, res->server, "[%s]: not enough memory for post_request buffer alloc", res->app_id);
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
