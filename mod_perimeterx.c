/*
 * PerimeterX Apache mod
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <jansson.h>

#include <curl/curl.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_strings.h"

#include "curl_pool.h"

#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
#include "util_cookies.h"
#endif

module AP_MODULE_DECLARE_DATA perimeterx_module;

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_perimeterx]:" __VA_ARGS__)

static const char *DEFAULT_BASE_URL = "https://sapi.perimeterx.net";
static const char *RISK_API = "/api/v1/risk";
static const char *CAPTCHA_API = "/api/v1/risk/captcha";
static const char *ACTIVITIES_API = "/api/v1/collector/s2s";

static const char *RISK_API_URL;
static const char *CAPTCHA_API_URL;
static const char *ACTIVITIES_API_URL;

// constants
//
static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";

static const char* FILE_EXT_WHITELIST[] = {
    ".css", ".bmp", ".tif", ".ttf", ".docx", ".woff2", ".js", ".pict", ".tiff", ".eot", ".xlsx", ".jpg", ".csv",
    ".eps", ".woff", ".xls", ".jpeg", ".doc", ".ejs", ".otf", ".pptx", ".gif", ".pdf", ".swf", ".svg", ".ps",
    ".ico", ".pls", ".midi", ".svgz", ".class", ".png", ".ppt", ".mid", "webp", ".jar" };

static const char *JSON_CONTENT_TYPE = "Content-Type: application/json";
static const char *EXPECT = "Expect:";

static const int BLOCK_PAGE_BUF_SIZE = 3000;
static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;

static const char *CAPTCHA_SCRIPT = "<script> \
            window.px_vid = '%s';\n \
            function handleCaptcha(response) { \n \
            var name = '_pxCaptcha';\n \
            var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();\n \
            var cookieParts = [name, '=', response + ':' + window.px_vid, '; expires=', expiryUtc, '; path=/'];\n \
            document.cookie = cookieParts.join('');\n \
            location.reload();\n \
            }\n \
            </script> \n";

static const char *BLOCKING_PAGE_FMT = "<html lang=\"en\">\n\
            <head>\n\
            <link type=\"text/css\" rel=\"stylesheet\" media=\"screen, print\" href=\"//fonts.googleapis.com/css?family=Open+Sans:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800\">\n\
            <meta charset=\"UTF-8\">\n\
            <title>Access to This Page Has Been Blocked</title>\n\
            <style> p { width: 60%%; margin: 0 auto; font-size: 35px; } body { background-color: #a2a2a2; font-family: \"Open Sans\"; margin: 5%%; } img { width: 180px; } a { color: #2020B1; text-decoration: blink; } a:hover { color: #2b60c6; } </style>\n\
            </head>\n\
            <body cz-shortcut-listen=\"true\">\n\
            <div><img src=\"http://storage.googleapis.com/instapage-thumbnails/035ca0ab/e94de863/1460594818-1523851-467x110-perimeterx.png\"> </div>\n \
            <span style=\"color: white; font-size: 34px;\">Access to This Page Has Been Blocked</span> \n\
            <div style=\"font-size: 24px;color: #000042;\">\n\
            <br> Access to '%s' is blocked according to the site security policy.<br> Your browsing behaviour fingerprinting made us think you may be a bot. <br> <br> This may happen as a result of the following: \n\
            <ul>\n\
            <li>JavaScript is disabled or not running properly.</li>\n\
            <li>Your browsing behaviour fingerprinting are not likely to be a regular user.</li>\n\
            </ul>\n\
            To read more about the bot defender solution: <a href=\"https://www.perimeterx.com/bot-defender\">https://www.perimeterx.com/bot-defender</a><br> If you think the blocking was done by mistake, contact the site administrator. <br> \n\
            <br><span style=\"font-size: 20px;\">Block Reference: <span style=\"color: #525151;\">#'%s'</span></span> \n\
            </div>\n\
            </body>\n\
            </html>";

static const char *CAPTCHA_BLOCKING_PAGE_FMT  = "<html lang=\"en\">\n \
            <head>\n \
            <link type=\"text/css\" rel=\"stylesheet\" media=\"screen, print\" href=\"//fonts.googleapis.com/css?family=Open+Sans:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800\">\n\
            <meta charset=\"UTF-8\">\n \
            <title>Access to This Page Has Been Blocked</title>\n \
            <style> p { width: 60%%; margin: 0 auto; font-size: 35px; } body { background-color: #a2a2a2; font-family: \"Open Sans\"; margin: 5%%; } img { width: 180px; } a { color: #2020B1; text-decoration: blink; } a:hover { color: #2b60c6; } </style>\n \
            <script src=\"https://www.google.com/recaptcha/api.js\"></script> \
            <script> \
            window.px_vid = '%s';\n \
            function handleCaptcha(response) { \n \
            var name = '_pxCaptcha';\n \
            var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();\n \
            var cookieParts = [name, '=', response + ':' + window.px_vid, '; expires=', expiryUtc, '; path=/'];\n \
            document.cookie = cookieParts.join('');\n \
            location.reload();\n \
            }\n \
            </script> \n \
            </head>\n \
            <body cz-shortcut-listen=\"true\">\n \
            <div><img src=\"http://storage.googleapis.com/instapage-thumbnails/035ca0ab/e94de863/1460594818-1523851-467x110-perimeterx.png\"> </div>\n \
            <span style=\"color: white; font-size: 34px;\">Access to This Page Has Been Blocked</span> \n \
            <div style=\"font-size: 24px;color: #000042;\">\n \
            <br> Access to '%s' is blocked according to the site security policy.<br> Your browsing behaviour fingerprinting made us think you may be a bot. <br> <br> This may happen as a result of the following: \n \
            <ul>\n \
            <li>JavaScript is disabled or not running properly.</li>\n \
            <li>Your browsing behaviour fingerprinting are not likely to be a regular user.</li>\n \
            </ul>\n \
            To read more about the bot defender solution: <a href=\"https://www.perimeterx.com/bot-defender\">https://www.perimeterx.com/bot-defender</a><br> If you think the blocking was done by mistake, contact the site administrator. <br> \n \
            <div class=\"g-recaptcha\" data-sitekey=\"6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b\" data-callback=\"handleCaptcha\" data-theme=\"dark\"></div>\n \
            <br><span style=\"font-size: 20px;\">Block Reference: <span style=\"color: #525151;\">#' %s '</span></span> \n \
            </div>\n \
            </body>\n \
            </html>";


static const char *ERROR_CONFIG_MISSING = "mod_perimeterx: config structure not allocated";

// px configuration

typedef struct px_config_t {
    const char *app_id;
    const char *cookie_key;
    const char *auth_token;
    const char *base_url;
    const char *block_page_template;
    char *auth_header;
    bool module_enabled;
    bool captcha_enabled;
    int blocking_score;
    long api_timeout;
    bool send_page_activities;
    const char *module_version;
    curl_pool *curl_pool;
    int curl_pool_size;
    apr_array_header_t *routes_whitelist;
    apr_array_header_t *useragents_whitelist;
    apr_array_header_t *ip_header_keys;
    apr_array_header_t *custom_file_ext_whitelist;
} px_config;

typedef enum {
    VALID,
    NO_SIGNING,
    EXPIRED,
    INVALID,
    NULL_COOKIE
} validation_result_t;

typedef enum s2s_call_reason_t {
    NONE,
    NO_COOKIE,
    EXPIRED_COOKIE,
    INVALID_COOKIE
} s2s_call_reason_t;

static const char *S2S_CALL_REASON_STR[] = {
    "none",
    "no_cookie",
    "expired_cookie",
    "invalid_cookie"
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

// risk cookie
//

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


// risk api response

typedef struct risk_response_t {
    const char* uuid;
    int status;
    int score;
} risk_response;

// captcha api response

typedef struct captcha_response_t {
    int status;
    const char *uuid;
    const char *vid;
    const char *cid;
} captcha_response;


// handled request context

typedef struct request_context_t {
    const char *px_cookie;
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
    int score;
    block_reason_t block_reason;
    s2s_call_reason_t call_reason;
    request_rec *r;
} request_context;


// response_t helper buffer for response data
//
struct response_t {
    char* data;
    size_t size;
    server_rec *server;
};

// post request response callback
//
static size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream) {
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

// http post request
//
char *post_request(const char *url, const char *payload, const char *auth_header, request_rec *r, curl_pool *curl_pool) {
    CURL *curl = curl_pool_get(curl_pool);
    struct response_t response;
    struct curl_slist *headers = NULL;
    long status_code;
    CURLcode res;

    response.data = malloc(1);
    response.size = 0;
    response.server = r->server;

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, JSON_CONTENT_TYPE);
    headers = curl_slist_append(headers, EXPECT);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &response);
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (status_code == 200) {
            curl_pool_put(curl_pool, curl);
            return response.data;
        }
        ERROR(r->server, "post_request: status: %ld, url: %s", status_code, url);
    } else {
        ERROR(r->server, "post_request: failed: %s", curl_easy_strerror(res));
    }
    curl_pool_put(curl_pool, curl);
    free(response.data);
    return NULL;
}

// --------------------------------------------------------------------------------

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

char *create_risk_payload(const request_context *ctx, const px_config *conf, bool cookie_expired) {
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
        json_object_set_new(j_additional, "px_cookie", json_string(ctx->px_cookie));
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
    if (cookie_expired && ctx->uuid) {
        json_object_set_new(j_risk, "uuid", json_string(ctx->uuid));
    }

    // dump as string
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
        ERROR(ctx->r->server, "parse_captcha_response: failed to parse. error (%s), reponse (%s)",
                j_error.text, captcha_response_str);
        return NULL;
    }

    int status = -1;
    const char *uuid = NULL;
    const char *vid = NULL;
    const char *cid = NULL;
    if (json_unpack(j_response, "{s:i,s:s,s:s,s?s}",
                "status", &status,
                "uuid", &uuid,
                "cid", &cid,
                "vid", &vid)) {
        ERROR(ctx->r->server, "parse_captcha_response: failed to unpack. reponse (%s)", captcha_response_str);
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
    const char *uuid = NULL;
    int non_human = 0;
    if (json_unpack(j_response, "{s:i,s:s,s:{s:i}}",
                "status", &status,
                "uuid", &uuid,
                "scores",
                "non_human", &non_human)) {
        ERROR(ctx->r->server, "parse_risk_response: failed to unpack risk response. (%s)", risk_response_str);
        json_decref(j_response);
        return NULL;
    }

    risk_response *parsed_response = (risk_response*)apr_palloc(ctx->r->pool, sizeof(risk_response));
    if (parsed_response) {
        parsed_response->uuid = apr_pstrdup(ctx->r->pool, uuid);
        parsed_response->status = status;
        parsed_response->score = non_human;
    }
    json_decref(j_response);
    return parsed_response;
}

// --------------------------------------------------------------------------------

int decode_base64(const char *s, unsigned char **o, int *len, apr_pool_t *p) {
    if (!s) {
        return -1;
    }
    int l = strlen(s);
    *o = (unsigned char*)apr_palloc(p, (l * 3 + 1));
    BIO *bio = BIO_new_mem_buf((void*)s, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bio, *o, l);
    BIO_free_all(b64);
    return 0;
}

void digest_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key, const char **signing_fields, int sign_fields_size, char buffer[65]) {
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);

    HMAC_Init_ex(&hmac, cookie_key, strlen(cookie_key), EVP_sha256(), NULL);

    if (cookie->timestamp) {
        HMAC_Update(&hmac, cookie->timestamp, strlen(cookie->timestamp));
    }
    if (cookie->a) {
        HMAC_Update(&hmac, cookie->a, strlen(cookie->a));
    }
    if (cookie->b) {
        HMAC_Update(&hmac, cookie->b, strlen(cookie->b));
    }
    if (cookie->uuid) {
        HMAC_Update(&hmac, cookie->uuid, strlen(cookie->uuid));
    }
    if (cookie->vid) {
        HMAC_Update(&hmac, cookie->vid, strlen(cookie->vid));
    }

    for (int i = 0; i < sign_fields_size; i++) {
        HMAC_Update(&hmac, signing_fields[i], strlen(signing_fields[i]));
    }

    int len = 32;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    for (int i = 0; i < 32; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
}

validation_result_t validate_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key) {
    if (cookie == NULL) {
        INFO(ctx->r->server, "validate_cookie: NO COOKIE");
        return NULL_COOKIE;
    }

    if (cookie->hash == NULL || strlen(cookie->hash) == 0) {
        INFO(ctx->r->server, "validate_cookie: NO SIGNING");
        return NO_SIGNING;
    }

    struct timeval te;
    gettimeofday(&te, NULL);
    long long currenttime = te.tv_sec * 1000LL + te.tv_usec / 1000;
    if (currenttime > cookie->ts) {
        INFO(ctx->r->server, "validate_cookie: COOKIE EXPIRED");
        return EXPIRED;
    }

    char signature[65];
    const char *signing_fields[] = { ctx->useragent } ;
    digest_cookie(cookie, ctx, cookie_key, signing_fields, sizeof(signing_fields)/sizeof(*signing_fields), signature);

    if (memcmp(signature, cookie->hash, 64) != 0) {
        INFO(ctx->r->server, "validate_cookie: SIGNATURE INVALID");
        return INVALID;
    }

    INFO(ctx->r->server, "validate_cookie: VALID");
    return VALID;
}

risk_cookie *parse_risk_cookie(const char *raw_cookie, request_context *ctx) {
    json_error_t error;
    json_t *j_cookie = json_loads(raw_cookie, 0, &error);
    if (!j_cookie) {
        ERROR(ctx->r->server, "cookie data: parse failed with error. raw_cookie (%s), text (%s)", raw_cookie, error.text);
        return NULL;
    }

    int a_val, b_val;
    char *hash, *uuid, *vid;
    json_int_t ts;
    if (json_unpack(j_cookie, "{s:s,s:s,s:{s:i,s:i},s:I,s:s}",
                "v", &vid,
                "u", &uuid,
                "s",
                "a", &a_val,
                "b", &b_val,
                "t", &ts,
                "h", &hash)) {
        ERROR(ctx->r->server, "cookie data: unpack json failed. raw_cookie (%s)", raw_cookie);
        json_decref(j_cookie);
        return NULL;
    }

    risk_cookie *cookie = (risk_cookie*)apr_palloc(ctx->r->pool, sizeof(risk_cookie));
    if (!cookie) {
        ERROR(ctx->r->server, "cookie data: failed to allocate risk cookie struct. raw_cookie (%s)", raw_cookie);
        json_decref(j_cookie);
        return NULL;
    }

    char buf[30] = {0};
    snprintf(buf, sizeof(buf), "%"JSON_INTEGER_FORMAT, ts);
    cookie->timestamp = apr_pstrdup(ctx->r->pool, buf);
    cookie->ts = ts;
    cookie->hash = apr_pstrdup(ctx->r->pool, hash);
    cookie->uuid = apr_pstrdup(ctx->r->pool, uuid);
    cookie->vid = apr_pstrdup(ctx->r->pool, vid);
    cookie->a_val = a_val;
    cookie->b_val = b_val;
    cookie->a = apr_psprintf(ctx->r->pool, "%d", a_val);
    cookie->b = apr_psprintf(ctx->r->pool, "%d", b_val);

    INFO(ctx->r->server,"cookie data: timestamp %s, vid %s, uuid %s hash %s scores: a %s b %s", cookie->timestamp, cookie->vid, cookie->uuid, cookie->hash, cookie->a, cookie->b);
    json_decref(j_cookie);
    return cookie;
}

risk_cookie *decode_cookie(const char *px_cookie, const char *cookie_key, request_context *r_ctx) {
    if (px_cookie == NULL) {
        return NULL;
    }

    char *px_cookie_cpy = apr_pstrdup(r_ctx->r->pool, px_cookie);
    // parse cookie
    char* saveptr;
    const char* delimieter = ":";
    const char* encoded_salt = strtok_r(px_cookie_cpy, delimieter, &saveptr);
    int iterations = atoi(strtok_r(NULL, delimieter, &saveptr));
    const char* encoded_payload = strtok_r(NULL, delimieter, &saveptr);

    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        ERROR(r_ctx->r->server,"Stoping cookie decryption: Number of iterations is illegal - %d", iterations);
        return NULL;
    }

    // decode payload
    unsigned char *payload;
    int payload_len;
    decode_base64(encoded_payload, &payload, &payload_len, r_ctx->r->pool);

    // decode salt
    unsigned char *salt;
    int salt_len;
    decode_base64(encoded_salt, &salt, &salt_len, r_ctx->r->pool);

    // pbkdf2
    const int iv_len = 16;
    const int key_len = 32;
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(r_ctx->r->pool, iv_len + key_len);
    if (PKCS5_PBKDF2_HMAC(cookie_key, strlen(cookie_key), salt, salt_len, iterations, EVP_sha256(),  iv_len + key_len, pbdk2_out) == 0) {
        ERROR(r_ctx->r->server,"PKCS5_PBKDF2_HMAC_SHA256 failed");
        return NULL;
    }
    const unsigned char key[32];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    const unsigned char iv[16];
    memcpy((void*)iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ERROR(r_ctx->r->server, "Decryption failed in: Init");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_palloc(r_ctx->r->pool, payload_len);
    int len;
    int dpayload_len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        ERROR(r_ctx->r->server, "Decryption failed in: Update");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        ERROR(r_ctx->r->server, "Decryption failed in: Final");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';

    // parse cookie string to risk struct
    risk_cookie *c = parse_risk_cookie((const char*)dpayload, r_ctx);

    // clean memory
    EVP_CIPHER_CTX_free(ctx);
    return c;
}

// --------------------------------------------------------------------------------

int rprintf_blocking_page(request_rec *r, const request_context *ctx, const px_config *conf) {
    if (conf->block_page_template) {
        return ap_rputs(conf->block_page_template, r);
    }
    return ap_rprintf(r, BLOCKING_PAGE_FMT, ctx->full_url, ctx->uuid);
}

int rprintf_captcha_blocking_page(request_rec *r, const request_context *ctx, const px_config *conf) {
    const char *vid = ctx->vid ? ctx->vid : "";
    if (conf->block_page_template) {
        const char *fmt_captcha_script = apr_psprintf(r->pool, CAPTCHA_SCRIPT, vid);
        return ap_rprintf(r, conf->block_page_template, fmt_captcha_script);
    }
    return ap_rprintf(r, CAPTCHA_BLOCKING_PAGE_FMT, vid, ctx->full_url, ctx->uuid);
}

bool verify_captcha(request_context *ctx, px_config *conf) {
    bool captcha_verified = false;

    if (!ctx->px_captcha) {
        return captcha_verified;
    }

    char *payload = create_captcha_payload(ctx, conf);
    if (!payload) {
        INFO(ctx->r->server, "verify_captcha: failed to format captcha payload. url: (%s)", ctx->full_url);
        return true;
    }

    char *response_str = post_request(CAPTCHA_API_URL, payload, conf->auth_header, ctx->r, conf->curl_pool);
    free(payload);
    if (!response_str) {
        INFO(ctx->r->server, "verify_captcha: failed to perform captcha validation request. url: (%s)", ctx->full_url);
        return true;
    }

    captcha_response *c = parse_captcha_response(response_str, ctx);
    free(response_str);
    if (c) {
        if (c->status == 0) {
            captcha_verified = true;
        } else {
            // TODO(barak): do we want to change ctx here?
            ctx->vid = NULL;
        }
        INFO(ctx->r->server, "verify_captcha: cookie validation status (%d)", captcha_verified);
    }
    return captcha_verified;
}

const char *get_request_ip(const request_rec *r, const px_config *conf) {
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    const char *socket_ip = r->useragent_ip;
# else
    const char *socket_ip =  r->connection->remote_ip;
#endif
    const apr_array_header_t *ip_header_keys = conf->ip_header_keys;
    for (int i = 0; i < ip_header_keys->nelts; i++) {
        const char *ip_header_key = APR_ARRAY_IDX(ip_header_keys, i, const char*);
        const char *ip = apr_table_get(r->headers_in, ip_header_key);
        if (ip) {
            return ip;
        } else {
            ERROR(r->server, "Invalid IP address from IPHeader configuration, using socket IP: %s", socket_ip);
            return socket_ip;
        }
    }
    return socket_ip;
}

request_context* create_context(request_rec *r, const px_config *conf) {
    request_context *ctx = (request_context*) apr_pcalloc(r->pool, sizeof(request_context));

    const char *px_cookie = NULL;
    const char *px_captcha_cookie = NULL;
    char *captcha_cookie = NULL;
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    apr_status_t status = ap_cookie_read(r, "_px", &px_cookie, 0);
    status = ap_cookie_read(r, "_pxCaptcha", &px_captcha_cookie, 0);
    if (status == APR_SUCCESS) {
        captcha_cookie = apr_pstrdup(r->pool, px_captcha_cookie);
    }

# else
    char *cookie = NULL;
    char *strtok_ctx = NULL;

    char *cookies = apr_pstrdup(r->pool, (char *) apr_table_get(r->headers_in, "Cookie"));
    if (cookies) {
        cookie = apr_strtok(cookies, ";", &strtok_ctx);

        while (cookie) {
            char *val_ctx;
            //trim leading space
            if (*cookie == ' ') {
                cookie ++;
            }
            if (strncmp(cookie, "_pxCaptcha", 10) == 0) {
                apr_pstrdup(r->pool, apr_strtok(cookie, "=", &val_ctx));
                captcha_cookie = apr_pstrdup(r->pool, apr_strtok(NULL, "", &val_ctx));
            } else if (strncmp(cookie, "_px", 3) == 0) {
                apr_strtok(cookie, "=", &val_ctx);
                px_cookie = apr_pstrdup(r->pool, apr_strtok(NULL, "", &val_ctx));
            }
            cookie = apr_strtok(NULL, ";", &strtok_ctx);
        }
    }
#endif

    ctx->ip = get_request_ip(r, conf);
    if (!ctx->ip) {
        ERROR(r->server, "Request IP is NULL");
    }

    ctx->px_cookie = px_cookie;
    ctx->uri = r->uri;
    ctx->hostname = r->hostname;
    ctx->http_method = r->method;
    ctx->useragent = apr_table_get(r->headers_in, "User-Agent");
    // TODO(barak): fill_url is missing the protocol like http:// or https://
    ctx->full_url = apr_pstrcat(r->pool, r->hostname, r->unparsed_uri, NULL);
    ctx->vid = NULL;

    if (captcha_cookie) {
        char *saveptr;
        ctx->px_captcha = apr_strtok(captcha_cookie, ":", &saveptr);
        ctx->vid = apr_strtok(NULL, "", &saveptr);
        INFO(r->server, "PXCaptcha cookie was found: %s", ctx->px_captcha);
    }

    // TODO(barak): parse without strtok
    char *saveptr;
    const char *delim = "/";
    char *protocol_cpy = apr_pstrdup(r->pool, r->protocol);
    apr_strtok(protocol_cpy , delim, &saveptr);
    const char *version = apr_strtok(NULL, delim, &saveptr);

    ctx->http_version = version;
    ctx->headers = r->headers_in;
    ctx->block_reason = NO_BLOCKING;
    ctx->call_reason = NONE;
    ctx->r = r;

    INFO(r->server, "create_context: useragent: (%s), px_cookie: (%s), full_url: (%s), hostname: (%s) , http_method: (%s), http_version: (%s), uri: (%s), ip: (%s)", ctx->useragent, ctx->px_cookie, ctx->full_url, ctx->hostname, ctx->http_method, ctx->http_version, ctx->uri, ctx->ip);

    return ctx;
}

risk_response* risk_api_get(const request_context *ctx, const px_config *conf, bool expired) {
    char *risk_payload = create_risk_payload(ctx, conf, expired);
    if (!risk_payload) {
        return NULL;
    }
    char *risk_response_str = post_request(RISK_API_URL , risk_payload, conf->auth_header, ctx->r, conf->curl_pool);
    free(risk_payload);
    if (!risk_response_str) {
        return NULL;
    }

    INFO(ctx->r->server, "risk_api_get: server response (%s)", risk_response_str);
    risk_response *risk_response = parse_risk_response(risk_response_str, ctx);
    free(risk_response_str);
    return risk_response;
}

void set_call_reason(request_context *ctx, validation_result_t vr) {
    switch(vr) {
        case NULL_COOKIE:
            ctx->call_reason = NO_COOKIE;
            break;
        case INVALID:
            ctx->call_reason = INVALID_COOKIE;
            break;
        case EXPIRED:
            ctx->call_reason = EXPIRED_COOKIE;
            break;
    }
}

static void post_verification(request_context *ctx, px_config *conf, bool request_valid) {
    const char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
    if (strcmp(activity_type, BLOCKED_ACTIVITY_TYPE) == 0 || conf->send_page_activities) {
        char *activity = create_activity(activity_type, conf, ctx);
        if (!activity) {
            ERROR(ctx->r->server, "post_verification: (%s) create activity failed", activity_type);
            return;
        }
        char *resp = post_request(ACTIVITIES_API_URL, activity, conf->auth_header, ctx->r, conf->curl_pool);
        free(activity);
        if (resp) {
            free(resp);
        } else {
            ERROR(ctx->r->server, "post_verification: (%s) send failed", activity_type);
        }
    }
}

static bool px_verify_request(request_context *ctx, px_config *conf) {
    bool expired = false;
    bool request_valid = true;
    risk_response *risk_response;

    if (conf->captcha_enabled && ctx->px_captcha) {
        if (verify_captcha(ctx, conf)) {
            post_verification(ctx, conf, true);
            return request_valid;
        }
    }

    validation_result_t vr = NULL_COOKIE;
    risk_cookie *c = decode_cookie(ctx->px_cookie, conf->cookie_key, ctx);
    if (c) {
        ctx->score = c->b_val;
        ctx->vid = c->vid;
        ctx->uuid = c->uuid;
        vr = validate_cookie(c, ctx, conf->cookie_key);
    }
    switch (vr) {
        case VALID:
            request_valid = ctx->score < conf->blocking_score;
            if (!request_valid) {
                ctx->block_reason = COOKIE;
            }
            break;
        case EXPIRED:
            expired = true;
        case NULL_COOKIE:
        case INVALID:
            set_call_reason(ctx, vr);
            risk_response = risk_api_get(ctx, conf, expired);
            if (risk_response) {
                ctx->score = risk_response->score;
                if (!ctx->uuid && risk_response->uuid) {
                    ctx->uuid = risk_response->uuid;
                }
                request_valid = ctx->score < conf->blocking_score;
                if (!request_valid) {
                    ctx->block_reason = SERVER;
                }
            } else {
                ERROR(ctx->r->server, "px_verify_request: could not complete risk_api request");
                return true;
            }
            break;
        default:
            ERROR(ctx->r->server, "px_verify_request: cookie decode failed returning valid result (%d)", vr);
            return true;
    }

    post_verification(ctx, conf, request_valid);
    return request_valid;
}

static bool px_should_verify_request(request_rec *r, px_config *conf) {
    if (!conf->module_enabled) {
        return false;
    }

    const char *file_ending = strrchr(r->uri, '.');
    // checking if added custom file extension whitelist
    if (conf->custom_file_ext_whitelist) {
        const apr_array_header_t *file_exts = conf->custom_file_ext_whitelist;
        for (int i = 0; i < file_exts->nelts; i++) {
            const char *file_ext = APR_ARRAY_IDX(file_exts, i, const char*);
            if (strncmp(file_ext, r->parsed_uri.path, strlen(file_ext)) == 0) {
                return false;
            }
        }
    } else {
        // if not - using default whitelist
        if (file_ending) {
            for (int i = 0; i < sizeof(FILE_EXT_WHITELIST)/sizeof(*FILE_EXT_WHITELIST); i++ ) {
                if (strcmp(file_ending, FILE_EXT_WHITELIST[i]) == 0) {
                    return false;
                }
            }
        }
    }

    // checks if request is filtered using PXWhitelistRoutes
    const apr_array_header_t *routes = conf->routes_whitelist;
    for (int i = 0; i < routes->nelts; i++) {
        const char *route = APR_ARRAY_IDX(routes, i, const char*);
        if (strncmp(route, r->parsed_uri.path, strlen(route)) == 0) {
            return false;
        }
    }

    // checks if request is filtered using PXWhitelistUserAgents
    const char *r_useragent = apr_table_get(r->headers_in, "User-Agent");
    if (r_useragent) {
        const apr_array_header_t *useragents = conf->useragents_whitelist;
        for (int i = 0; i < useragents->nelts; i++) {
            const char *useragent = APR_ARRAY_IDX(useragents, i, const char*);
            if (strcmp(useragent, r_useragent) == 0) {
                return false;
            }
        }
    }

    return true;
}

int px_handle_request(request_rec *r, px_config *conf) {
    if (!px_should_verify_request(r, conf)) {
        return OK;
    }

    request_context *ctx = create_context(r, conf);
    if (ctx) {
        bool request_valid = px_verify_request(ctx, conf);
        apr_table_set(r->subprocess_env, "SCORE", apr_itoa(r->pool, ctx->score));

        if (!request_valid) {
            if (conf->captcha_enabled) {
                rprintf_captcha_blocking_page(r, ctx, conf);
            } else {
                rprintf_blocking_page(r, ctx, conf);
            }
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 2
            ap_set_content_type(r, "text/html");
# endif
            INFO(r->server, "px_handle_request: request blocked. captcha (%d)", conf->captcha_enabled);
            return DONE;
        }
    }
    INFO(r->server, "px_handle_request: request passed");
    return OK;
}

// --------------------------------------------------------------------------------


static void px_hook_child_init(apr_pool_t *p, server_rec *s) {
    curl_global_init(CURL_GLOBAL_ALL);
    px_config *conf = ap_get_module_config(s->module_config, &perimeterx_module);
    RISK_API_URL = apr_pstrcat(p, conf->base_url, RISK_API, NULL);
    CAPTCHA_API_URL = apr_pstrcat(p, conf->base_url, CAPTCHA_API, NULL);
    ACTIVITIES_API_URL = apr_pstrcat(p, conf->base_url, ACTIVITIES_API, NULL);
}

static apr_status_t px_cleanup_pre_config(void *data) {
    ERR_free_strings();
    EVP_cleanup();
    return APR_SUCCESS;
}

static int px_hook_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    apr_pool_cleanup_register(p, NULL, px_cleanup_pre_config, apr_pool_cleanup_null);
    return OK;
}

static px_config *get_config(cmd_parms *cmd, void *config) {
    if (cmd->path) {
        return config;
    }
    return ap_get_module_config(cmd->server->module_config, &perimeterx_module);
}

static const char *set_px_enabled(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->module_enabled = arg ? true : false;
    return NULL;
}

static const char *set_app_id(cmd_parms *cmd, void *config, const char *app_id) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->app_id = app_id;
    return NULL;
}

static const char *set_cookie_key(cmd_parms *cmd, void *config, const char *cookie_key) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->cookie_key = cookie_key;
    return NULL;
}

static const char *set_auth_token(cmd_parms *cmd, void *config, const char *auth_token) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->auth_token = auth_token;
    conf->auth_header = apr_pstrcat(cmd->pool, "Authorization: Bearer ", auth_token, NULL);
    return NULL;
}

static const char *set_captcha_enabled(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    if (arg) {
        conf->block_page_template = CAPTCHA_BLOCKING_PAGE_FMT; // TODO: check for conflict
    }

    conf->captcha_enabled = arg ? true : false;
    return NULL;
}

static const char *set_pagerequest_enabled(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->send_page_activities = arg ? true : false;
    return NULL;
}

static const char *set_blocking_score(cmd_parms *cmd, void *config, const char *blocking_score){
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->blocking_score = atoi(blocking_score);
    return NULL;
}

static const char *set_api_timeout(cmd_parms *cmd, void *config, const char *api_timeout) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->api_timeout = atoi(api_timeout);
    return NULL;
}

static const char *set_ip_headers(cmd_parms *cmd, void *config, const char *ip_header) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->ip_header_keys);
    *entry = ip_header;
    return NULL;
}

static const char *set_curl_pool_size(cmd_parms *cmd, void *config, const char *curl_pool_size) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->curl_pool_size = atoi(curl_pool_size);
    if (conf->curl_pool != NULL) {
        curl_pool_destroy(conf->curl_pool);
    }
    conf->curl_pool = curl_pool_create(cmd->pool, conf->curl_pool_size);
    return NULL;
}

static const char *set_base_url(cmd_parms *cmd, void *config, const char *base_url) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->base_url = base_url;
    return NULL;
}

static const char *set_block_page_filepath(cmd_parms *cmd, void *config, const char *file_path) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    apr_file_t *file = apr_palloc(cmd->pool, sizeof(apr_file_t*));
    apr_status_t status = apr_file_open(&file, file_path, APR_FOPEN_READ, APR_FPROT_OS_DEFAULT, cmd->pool);
    if (status == APR_SUCCESS) {
        char *buffer = apr_palloc(cmd->pool, BLOCK_PAGE_BUF_SIZE * sizeof(char));
        apr_size_t bytes_read;
        apr_file_read_full(file, buffer, 3000, &bytes_read);
        buffer[bytes_read] = 0;
        conf->block_page_template = buffer;
    } else {
        ERROR(cmd->server, "Could not open blocking page in path: %s, using default blocking page", file_path);
    }

    return NULL;
}

static const char *add_route_to_whitelist(cmd_parms *cmd, void *config, const char *route) {
    const char *sep = ";";
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char **entry = apr_array_push(conf->routes_whitelist);
    *entry = route;
    return NULL;
}

static const char *add_useragent_to_whitelist(cmd_parms *cmd, void *config, const char *useragent) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->useragents_whitelist);
    *entry = useragent;
    return NULL;
}

static const char *add_file_extension_whitelist(cmd_parms *cmd, void *config, const char *file_extension) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    if (!conf->custom_file_ext_whitelist) {
        conf->custom_file_ext_whitelist = apr_array_make(cmd->pool, 0, sizeof(char*));
    }
    const char** entry = apr_array_push(conf->custom_file_ext_whitelist);
    *entry = file_extension;
    return NULL;
}

static int px_hook_post_request(request_rec *r) {
    px_config *conf = ap_get_module_config(r->server->module_config, &perimeterx_module);
    return px_handle_request(r, conf);
}

apr_status_t kill_curl_pool(void *data) {
    curl_pool_destroy((curl_pool*)data);
}

static void *create_config(apr_pool_t *p) {
    px_config *conf = apr_pcalloc(p, sizeof(px_config));
    conf->module_enabled = false;
    conf->api_timeout = 0L;
    conf->send_page_activities = false;
    conf->blocking_score = 70;
    conf->captcha_enabled = false;
    conf->module_version = "Apache Module v1.0.6";
    conf->curl_pool_size = 40;
    conf->base_url = DEFAULT_BASE_URL;
    conf->routes_whitelist = apr_array_make(p, 0, sizeof(char*));
    conf->useragents_whitelist = apr_array_make(p, 0, sizeof(char*));
    conf->curl_pool = curl_pool_create(p, conf->curl_pool_size);
    conf->ip_header_keys = apr_array_make(p, 0, sizeof(char*));
    conf->custom_file_ext_whitelist = NULL;
    conf->block_page_template = NULL;

    /*apr_pool_cleanup_register(p, conf->curl_pool, kill_curl_pool, apr_pool_cleanup_null);*/

    return conf;
}

static const command_rec px_directives[] = {
    AP_INIT_FLAG("PXEnabled",
            set_px_enabled,
            NULL,
            OR_ALL,
            "Turn on mod_px"),
    AP_INIT_FLAG("Captcha",
            set_captcha_enabled,
            NULL,
            OR_ALL,
            "Include captcha in the blocking page"),
    AP_INIT_TAKE1("AppID",
            set_app_id,
            NULL,
            OR_ALL,
            "PX Application ID"),
    AP_INIT_TAKE1("CookieKey",
            set_cookie_key,
            NULL,
            OR_ALL,
            "Cookie decryption key"),
    AP_INIT_TAKE1("AuthToken",
            set_auth_token,
            NULL,
            OR_ALL,
            "Risk API auth token"),
    AP_INIT_TAKE1("BlockingScore",
            set_blocking_score,
            NULL,
            OR_ALL,
            "Request with score equal or greater than this will be blocked"),
    AP_INIT_TAKE1("APITimeout",
            set_api_timeout,
            NULL,
            OR_ALL,
            "Set timeout for risk API request"),
    AP_INIT_FLAG("ReportPageRequest",
            set_pagerequest_enabled,
            NULL,
            OR_ALL,
            "Enable page_request activities report"),
    AP_INIT_ITERATE("IPHeader",
            set_ip_headers,
            NULL,
            OR_ALL,
            "This headers will be used to get the request real IP, first header to get valid IP will be usesd"),
    AP_INIT_TAKE1("CurlPoolSize",
            set_curl_pool_size,
            NULL,
            OR_ALL,
            "Determines number of curl active handles"),
    AP_INIT_TAKE1("BaseURL",
            set_base_url,
            NULL,
            OR_ALL,
            "PerimeterX server base URL"),
    AP_INIT_TAKE1("BlockpageLocation",
            set_block_page_filepath,
            NULL,
            OR_ALL,
            "Full path for blocking page location"),
    AP_INIT_ITERATE("PXWhitelistRoutes",
            add_route_to_whitelist,
            NULL,
            OR_ALL,
            "Whitelist by paths - this module will not apply on this path list"),
    AP_INIT_ITERATE("PXWhitelistUserAgents",
            add_useragent_to_whitelist,
            NULL,
            OR_ALL,
            "Whitelist by User-Agents - this module will not apply on these user-agents"),
    AP_INIT_ITERATE("ExtensionWhitelist",
            add_file_extension_whitelist,
            NULL,
            OR_ALL,
            "Whitelist by file extensions - this module will not apply on files with one of these file extensions"),
    { NULL }
};

static void perimeterx_register_hooks(apr_pool_t *pool) {
    ap_hook_post_read_request(px_hook_post_request, NULL, NULL, APR_HOOK_LAST);
    ap_hook_child_init(px_hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(px_hook_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *create_server_config(apr_pool_t *pool, server_rec *s) {
    return create_config(pool);
}

module AP_MODULE_DECLARE_DATA perimeterx_module =  {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_server_config,       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    px_directives,              /* command apr_table_t */
    perimeterx_register_hooks   /* register hooks */
};

