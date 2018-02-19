#include "px_utils.h"

#include <apr_atomic.h>

#include <arpa/inet.h>
#include <apr_strings.h>
#include <http_log.h>
#include "ap_config.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

#define BLOCKSIZE 4096
#define T_ESCAPE_URLENCODED    (16)
#define TEST_CHAR(c, f)        (test_char_table[(unsigned)(c)] & (f))

struct response_t {
    char* data;
    size_t size;
    server_rec *server;
    request_rec *r;
    apr_array_header_t *headers;
    const char *app_id;
};


static const char *JSON_CONTENT_TYPE = "Content-Type: application/json";
static const char *EXPECT = "Expect:";
static const char *MOBILE_SDK_HEADER = "X-PX-AUTHORIZATION";
static const char *ENFORCER_TRUE_IP = "x-px-enforcer-true-ip";
static const char *FIRST_PARTY_HEADER = "x-px-first-party";
static const char *FIRST_PARTY_HEADER_VALUE = "1";
static const unsigned char test_char_table[256] = {
    32,30,30,30,30,30,30,30,30,30,31,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,6,16,63,22,17,22,49,17,
    17,17,1,16,16,0,0,18,0,0,0,0,0,0,0,0,0,0,16,23,
    55,16,55,23,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,23,31,23,23,0,23,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,23,23,23,17,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30 
};

static void update_and_notify_health_check(px_config *conf) {
    if (!conf->px_health_check) {
        return;
    }
    apr_uint32_t old_value = apr_atomic_inc32(&conf->px_errors_count);
    apr_thread_mutex_lock(conf->health_check_cond_mutex);
    if (old_value >= conf->px_errors_threshold) {
        apr_thread_cond_signal(conf->health_check_cond);
    }
    apr_thread_mutex_unlock(conf->health_check_cond_mutex);
}

static int read_body(request_rec *r, char **body) {
    *body = NULL;
    int ret = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if(OK == ret && ap_should_client_block(r)) {
        char* buffer = (char*)apr_pcalloc(r->pool, BLOCKSIZE);
        int len;
        char *data = malloc(1);
        int d_size = 0;
        data[0] = '\0';
        while((len=ap_get_client_block(r, buffer, BLOCKSIZE)) > 0) {
            data = realloc(data, d_size + len + 1);
            if (data == NULL) {
                return -1;
            }
            memcpy(&(data[d_size]), buffer, len);
            d_size += len;
            data[d_size] = '\0';
        }
        if (len == -1) {
            free(data);
            return -1;
        }
        *body = data;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "requrest_rec body[%s]", data);
        return 0;
    }
    return -1;
}

static size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream) {
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

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *stream) {
   struct response_t *res = (struct response_t*)stream;
   size_t realsize = size * nitems;

   if (realsize > 2 && buffer[realsize-2]  == '\r' && buffer[realsize-1] == '\n') {
        char *header = apr_pstrndup(res->r->pool, buffer, realsize-2); 
        
        char *value = NULL;
        char *key = apr_strtok (header, ":", &value);
        if (strlen(value) > 0 && strlen(key) > 0) {
            const char** entry = apr_array_push(res->headers);
            *entry = apr_psprintf(res->r->pool, "%s: %s", key, value);
        }
   }
   return realsize;
}

static const char* extract_first_ip(apr_pool_t *p, const char *ip) {
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
    const char* socket_ip =  r->useragent_ip;
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
            struct in6_addr ipv6_addr;
            if (inet_pton(AF_INET, first_ip, &addr) == 1 || inet_pton(AF_INET6, first_ip, &ipv6_addr) == 1) {
                return first_ip;
            }
        }
    }
    // no valid ip found in IPHeader values - using socket_ip as a fallback
    return socket_ip;
}

CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long timeout, px_config *conf, server_rec *server, char **response_data) {
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &response);
    if (conf->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, conf->proxy_url);
    }
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
        update_and_notify_health_check(conf);
        size_t len = strlen(errbuf);
        if (len) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server, "[%s]: post_request failed: %s", conf->app_id, errbuf);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server, "[%s]: post_request failed: %s", conf->app_id, curl_easy_strerror(status));
        }
    }
    free(response.data);
    if (response_data != NULL) {
        *response_data = NULL;
    }
    return status;
}

// returns the payload version, 0 if error msg, -1 if header not found
int extract_payload_from_header(apr_pool_t *pool, apr_table_t *headers, const char **payload3, const char **payload1) {
    *payload3 = NULL;
    *payload1 = NULL;
    const char *header_value = apr_table_get(headers, MOBILE_SDK_HEADER);
    if (header_value) {
        char *rest;
        char *header_cpy = apr_pstrdup(pool, header_value);
        const char *prefix = apr_strtok(header_cpy, ":", &rest);
        if (prefix == NULL) {
            // Setting payload to "" so it will fail on decryption
            *payload3 = "";
            return 0;
        }
        const char *postfix = apr_strtok(NULL, "", &rest);
        // if postfix is empty, use prefix as payload number, in this case version will be 0
        if (postfix == NULL) {
            *payload3 = prefix;
            return 0;
        }
        int version = apr_atoi64(prefix);
        switch (version) {
            case 1:
                *payload1 = postfix;
                break;
            case 3:
                *payload3 = postfix;
                break;
        }
        return version;
    }
    return -1;
}

static const char c2x_table[] = "0123456789abcdef";

static unsigned char *c2x(unsigned what, unsigned char prefix, unsigned char *where) {
    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}

int escape_urlencoded(char *escaped, const char *str, apr_size_t *len) {
    apr_size_t size = 1;
    int found = 0;
    const unsigned char *s = (const unsigned char *) str;
    unsigned char *d = (unsigned char *) escaped;
    unsigned c;

    if (s) {
        if (d) {
            while ((c = *s)) {
                if (TEST_CHAR(c, T_ESCAPE_URLENCODED)) {
                    d = c2x(c, '%', d);
                    size += 2;
                    found = 1;
                }
                else if (c == ' ') {
                    *d++ = '+';
                    found = 1;
                }
                else {
                    *d++ = c;
                }
                ++s;
                size++;
            }
            *d = '\0';
        }
        else {
            while ((c = *s)) {
                if (TEST_CHAR(c, T_ESCAPE_URLENCODED)) {
                    size += 2;
                    found = 1;
                }
                else if (c == ' ') {
                    found = 1;
                }
                ++s;
                size++;
            }
        }
    }

    if (len) {
        *len = size;
    }
    if (!found) {
        return 1;
    }

    return 0;
}

const char *pescape_urlencoded(apr_pool_t *p, const char *str) {
    apr_size_t len;       
    if (escape_urlencoded(NULL, str, &len) == 0) {
            char *encoded = apr_palloc(p, len);
            escape_urlencoded(encoded, str, NULL);
            return encoded;
    }
    return str;      
}

CURLcode redirect_helper(CURL* curl, const char *base_url, const char *uri, const char *vid, px_config *conf, request_rec *r, char **response_data, apr_array_header_t **response_headers, int *content_size) {
    const char *url = apr_pstrcat(r->pool, base_url, uri, NULL);
    //const char *data;

    struct response_t response;
    struct curl_slist *headers = NULL;
    long status_code;
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    response.data = malloc(1);
    response.size = 0;
    response.headers = apr_array_make(r->pool, 0, sizeof(char*));
    response.r = r;
    response.server = r->server;

    // Prepare headers
    const apr_array_header_t *header_arr = apr_table_elts(r->headers_in);

    if (header_arr) {
        for (int i = 0; i < header_arr->nelts; i++) {
            apr_table_entry_t h = APR_ARRAY_IDX(header_arr, i, apr_table_entry_t);
            if (strcasecmp(h.key, "Host") != 0) {
                headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", h.key, h.val));
            }
        }
    }

    // append vid cookie
    if (vid) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: redirect_helper: attaching vid header 'Cookie: pxvid=%s'", conf->app_id, vid);
        headers = curl_slist_append(headers, apr_psprintf(r->pool, "Cookie: pxvid=%s;", vid));
    }

    // Attach first party logics
    headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", FIRST_PARTY_HEADER, FIRST_PARTY_HEADER_VALUE));
    headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", ENFORCER_TRUE_IP, get_request_ip(r, conf)));
    headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", "Host", &base_url[8]));

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    // Case we have body
    char *body;
    int body_res = read_body(r, &body);
    if (body_res == 0 && strcmp(r->method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    }
    
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, conf->api_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &response);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*) &response);
    if (conf->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, conf->proxy_url);
    }
    CURLcode status = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    
    if (body) {
        free(body);
    }

    if (status == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (status_code == HTTP_OK) {
            if (response_data != NULL) {
                *response_headers = response.headers;
                *response_data = response.data;
                *content_size = response.size;
            } else {
                free(response.data);
            }
            return status;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: post_request: status: %lu, url: %s", conf->app_id, status_code, url);
        status = CURLE_HTTP_RETURNED_ERROR;
    } else {
        update_and_notify_health_check(conf);
        size_t len = strlen(errbuf);
        if (len) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: post_request failed: %s", conf->app_id, errbuf);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: post_request failed: %s", conf->app_id, curl_easy_strerror(status));
        }
    }
    free(response.data);
    return status;
}
