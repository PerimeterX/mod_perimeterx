#include "px_utils.h"

#include <apr_atomic.h>

#include <arpa/inet.h>
#include <apr_strings.h>
#include <openssl/hmac.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

#define BLOCKSIZE 4096
#define T_ESCAPE_URLENCODED    (16)
#define TEST_CHAR(c, f)        (test_char_table[(unsigned)(c)] & (f))

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

void update_and_notify_health_check(px_config *conf) {
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

/**
 * Use this function to read the body from request_rec
 * Pointer to data will be set to body
 * Returns -1 if failed
 */
static int read_body(request_rec *r, char **body) {
    *body = NULL;
    int ret = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if(OK == ret && ap_should_client_block(r)) {
        char* buffer = apr_pcalloc(r->pool, BLOCKSIZE);
        int len;
        char *data = apr_pcalloc(r->pool, 1);
        int d_size = 0;

        data[0] = '\0';
        // Read body
        while((len=ap_get_client_block(r, buffer, BLOCKSIZE)) > 0) {
            char *tmp;

            // there is no apr_realloc
            tmp = apr_pcalloc(r->pool, d_size + len + 1);
            memcpy(tmp, data, d_size + 1);
            data = tmp;

            memcpy(&(data[d_size]), buffer, len);
            d_size += len;
            data[d_size] = '\0';
        }
        if (len == -1) {
            return -1;
        }
        *body = data;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "requrest_rec body[%s]", data);
        return 0;
    }
    return -1;
}

size_t write_response_pool_cb(void* contents, size_t size, size_t nmemb, void *stream) {
    struct response_t *res = (struct response_t*)stream;
    size_t realsize = size * nmemb;
    char *tmp;
    tmp = apr_pcalloc(res->pool, res->size + realsize + 1);
    memcpy(tmp, res->data, res->size + 1);

    res->data = tmp;
    memcpy(&(res->data[res->size]), contents, realsize);
    res->size += realsize;
    res->data[res->size] = 0;
    return realsize;
}

size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream) {
    struct response_t *res = (struct response_t*)stream;
    size_t realsize = size * nmemb;
    char *tmp;
    tmp = realloc(res->data, res->size + realsize + 1);
    if (tmp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, res->server, "[%s]: not enough memory for post_request buffer alloc", res->app_id);
        free(res->data);
        return 0;
    }
    res->data = tmp;
    memcpy(&(res->data[res->size]), contents, realsize);
    res->size += realsize;
    res->data[res->size] = 0;
    return realsize;
}

/*
 * Callback function used for libCurl to exract response headers from curl request
 * Sets an array of headers on response_t->headers
 * Only headers that have 'key: value' format will be added
 * Headers like HTTP/1.1 200 OK will be ignored
 * Returns the real size of the header
 */
static size_t header_callback(char *buffer, size_t size, size_t nitems, void *stream) {
   struct response_t *res = (struct response_t*)stream;
   size_t realsize = size * nitems;

   // Verify that real size is bigger than 2 and last bytes are  \r \n
   if (realsize > 2 && buffer[realsize-2]  == '\r' && buffer[realsize-1] == '\n') {
        char *header = apr_pstrndup(res->r->pool, buffer, realsize-2);
        // Take only headers that have a valid format key: value
        if (strrchr(header, ':')) {
            const char** entry = apr_array_push(res->headers);
            *entry = header;
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

// return true if response could contain a body
static bool should_receive_body(long status_code) {
    if (status_code >= HTTP_CONTINUE && status_code < HTTP_OK) {
        return false;
    }

    // No Content
    if (status_code == HTTP_NO_CONTENT) {
        return false;
    }

    return true;
}

CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long connect_timeout, long timeout, px_config *conf, server_rec *server, char **response_data) {
    struct response_t response;
    struct curl_slist *headers = NULL;
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
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &response);
    if (conf->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, conf->proxy_url);
    }
    CURLcode status = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (status == CURLE_OK) {
        long status_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        px_log_debug_fmt("status: %lu, body: %d, url: %s", status_code, response.size, url);
        if (should_receive_body(status_code) && response.size) {
            if (response_data != NULL) {
                *response_data = response.data;
                // the caller frees the data
                return status;
            }

        // we support 204 (no content) and 304 (not modified)
        } else if (status_code == 204 || status_code == 304) {

        // unsupported HTTP code
        } else {
            status = CURLE_HTTP_RETURNED_ERROR;
        }
    } else {
        update_and_notify_health_check(conf);
        size_t len = strlen(errbuf);
        if (len) {
            px_log_debug_fmt("failed for %s: %s", url, errbuf);
        } else {
            px_log_debug_fmt("failed for %s: %s", url, curl_easy_strerror(status));
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
            default:
                return -1;
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

// Functions escape_urlencoded & pescape_urlencoded were copied from APR v1.6
// http://svn.apache.org/repos/asf/apr/apr/branches/1.6.x/include/apr_escape.h
static int escape_urlencoded(char *escaped, const char *str, apr_size_t *len) {
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

/*
 * Helper function to send http request as a proxy
 * The headers from the original request will be copied (except for Host & sensitive headers)
 * and the body of the request will also be copied
 * The data will be set on response_data, content_size, response_headers
 * Unlike post_request_helper, response_data doesn't have to be free as it being allocated using apr
 * Returns CURLcode
 */
CURLcode redirect_helper(CURL* curl, const char *base_url, const char *uri, const char *vid, px_config *conf, request_rec *r, const char **response_data, apr_array_header_t **response_headers, int *content_size) {
    const char *url = apr_pstrcat(r->pool, base_url, uri, NULL);
    struct response_t response;
    struct curl_slist *headers = NULL;
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

            // Remove sensitive headers
            if (strcasecmp(h.key, "Host") == 0) {
                continue;
            }

            bool skip = false;
            for (int j = 0; j < conf->sensitive_header_keys->nelts; j++) {
                const char *s = APR_ARRAY_IDX(conf->sensitive_header_keys, j, char*);

                if (strcasecmp(h.key, s) == 0) {
                    skip = true;
                    break;
                }
            }

            if (skip) {
                continue;
            }

            headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", h.key, h.val));
        }
    }

    // append vid cookie
    if (vid) {
        px_log_debug_fmt("attaching vid header 'Cookie: pxvid=%s'", vid);
        headers = curl_slist_append(headers, apr_psprintf(r->pool, "Cookie: pxvid=%s;", vid));
    }

    // Attach first party logics
    headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", FIRST_PARTY_HEADER, FIRST_PARTY_HEADER_VALUE));
    headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", ENFORCER_TRUE_IP, get_request_ip(r, conf)));

    const char *xff = apr_table_get(r->headers_in, "X-Forwarded-For");
    if (xff) {
        headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s,%s", "X-Forwarded-For", xff, r->useragent_ip));
    } else {
        headers = curl_slist_append(headers, apr_psprintf(r->pool, "%s: %s", "X-Forwarded-For", r->useragent_ip));
    }
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

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, conf->connect_timeout_ms);
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

    if (status == CURLE_OK) {
        long status_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        px_log_debug_fmt("status: %lu, body: %d, url: %s", status_code, response.size, url);

        *content_size = 0;

        // check for HTTP codes with body
        if (should_receive_body(status_code) && response.size) {
            *response_headers = response.headers;
            if (response_data != NULL) {
                *response_data = apr_pstrmemdup(r->pool, response.data, response.size);
                *content_size = response.size;
            }

        // we support 204 (no content) and 304 (not modified)
        } else if (status_code == 204 || status_code == 304) {
            *response_headers = response.headers;

        // unsupported HTTP code
        } else {
            status = CURLE_HTTP_RETURNED_ERROR;
        }
    } else {
        update_and_notify_health_check(conf);
        size_t len = strlen(errbuf);
        if (len) {
            px_log_debug_fmt("failed: %s", errbuf);
        } else {
            px_log_debug_fmt("failed: %s", curl_easy_strerror(status));
        }
    }
    free(response.data);
    return status;
}

void px_log(const px_config *conf, apr_pool_t *pool, bool log_debug, int level, const char *func, const char *fmt, ...) {
    // do not log debug messages if debugMode is disabled
    if (!conf || !pool || (!conf->px_debug && log_debug)) {
        return;
    }

    va_list ap;
    char *text;

    va_start(ap, fmt);
    text = apr_pvsprintf(pool, fmt, ap);
    va_end(ap);
    ap_log_error(APLOG_MARK,
        conf->px_debug ? level : conf->log_level_err,
        0, conf->server,
        log_debug ? LOGGER_DEBUG_HDR: LOGGER_ERROR_HDR,
        conf->app_id, func, text);
}

// generate HMAC SHA256 for str
// return true if signature is set
bool px_hmac_str(const char *key, const char *str, char *signature, int signature_len)
{
    unsigned char hash[32];

    HMAC_CTX *hmac = HMAC_CTX_new();
    if (!HMAC_Init_ex(hmac, key, strlen(key), EVP_sha256(), NULL)) {
        HMAC_CTX_free(hmac);
        return false;
    }
    if (!HMAC_Update(hmac,(unsigned char*)str, strlen(str))) {
        HMAC_CTX_free(hmac);
        return false;
    }
    unsigned int len = signature_len / 2;
    if (!HMAC_Final(hmac, hash, &len)) {
        HMAC_CTX_free(hmac);
        return false;
    }
    HMAC_CTX_free(hmac);

    unsigned int i;
    for (i = 0; i < len; i++) {
        sprintf(signature + (i * 2), "%02x", hash[i]);
    }

    return true;
}
