#include "px_enforcer.h"

#include <apr_strings.h>
#include <http_log.h>
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
#include <util_cookies.h>
#endif

#include "px_cookie.h"
#include "px_json.h"
#include "px_utils.h"
#include "curl_pool.h"
#include <apr_thread_pool.h>

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_perimeterx]:" __VA_ARGS__)

static const char *PX_COOKIE = "_px";
static const char *CAPTCHA_COOKIE = "_pxCaptcha";
static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";

static const char *JSON_CONTENT_TYPE = "Content-Type: application/json";
static const char *EXPECT = "Expect:";

static const char* FILE_EXT_WHITELIST[] = {
    ".css", ".bmp", ".tif", ".ttf", ".docx", ".woff2", ".js", ".pict", ".tiff", ".eot", ".xlsx", ".jpg", ".csv",
    ".eps", ".woff", ".xls", ".jpeg", ".doc", ".ejs", ".otf", ".pptx", ".gif", ".pdf", ".swf", ".svg", ".ps",
    ".ico", ".pls", ".midi", ".svgz", ".class", ".png", ".ppt", ".mid", "webp", ".jar" };

typedef struct report_data_t {
    const char *url;
    /*char *activity;*/
    char **activity;
    const char *auth_header;
    long api_timeout;
    server_rec *server;
    /*curl_pool *curl_pool;*/
} report_data;

void thread_pool_stats(apr_thread_pool_t *t, request_context *ctx) {
    INFO(ctx->r->server, "thread count: %ld", apr_thread_pool_threads_count(t));
    INFO(ctx->r->server, "busy count: %ld", apr_thread_pool_busy_count(t));
    INFO(ctx->r->server, "idle count: %ld", apr_thread_pool_idle_count(t));
    INFO(ctx->r->server, "task run count: %ld", apr_thread_pool_tasks_run_count (t));
}

void *APR_THREAD_FUNC send_activity(apr_thread_t *t, void *arg) {
    report_data *rd = (report_data*)arg;
    /*request_context *ctx = (request_context*)arg;*/
    INFO(rd->server, "We are in the thread function worker");
    /*CURL *curl = curl_pool_get_wait(curl_pool);*/
    CURL *curl = curl_easy_init(); // this should be a property of the pool shit

    if (curl == NULL) {
        ERROR(rd->server, "post_request: could not obtain curl handle");
        return ((void*)t);
    }
    /*struct response_t response;*/
    struct curl_slist *headers = NULL;
    long status_code;
    CURLcode res;
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    headers = curl_slist_append(headers, rd->auth_header);
    headers = curl_slist_append(headers, JSON_CONTENT_TYPE);
    headers = curl_slist_append(headers, EXPECT);

    INFO(rd->server, "url: %s", rd->url);
    INFO(rd->server, "auth-token: %s", rd->auth_header);
    INFO(rd->server, "activity: %s", *rd->activity);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, rd->api_timeout);
    curl_easy_setopt(curl, CURLOPT_URL, rd->url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, *rd->activity);
    res = curl_easy_perform(curl);

    INFO(rd->server, "report_data: %ld, %s", rd->api_timeout, *rd->activity);
    /*if (res != CURLE_OK) {*/
        /*size_t len = strlen(errbuf);*/
        /*if (len) {*/
            /*ERROR(rd->server, "post_request failed: %s", errbuf);*/
        /*}*/
        /*else {*/
            /*ERROR(rd->server, "post_request failed: %s", curl_easy_strerror(res));*/
        /*}*/
    /*}*/

    free(*rd->activity);
    curl_slist_free_all(headers);
    return ((void*)t);
}

static char *post_request(const char *url, const char *payload, const char *auth_header, long api_timeout, request_rec *r, curl_pool *curl_pool) {
    CURL *curl = curl_pool_get_wait(curl_pool);

    if (curl == NULL) {
        ERROR(r->server, "post_request: could not obtain curl handle");
        return NULL;
    }
    struct response_t response;
    struct curl_slist *headers = NULL;
    long status_code;
    CURLcode res;
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    response.data = malloc(1);
    response.size = 0;
    response.server = r->server;

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, JSON_CONTENT_TYPE);
    headers = curl_slist_append(headers, EXPECT);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, api_timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &response);
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (status_code == HTTP_OK) {
            curl_pool_put(curl_pool, curl);
            return response.data;
        }
        ERROR(r->server, "post_request: status: %ld, url: %s", status_code, url);
    }
    else {
        size_t len = strlen(errbuf);
        if (len) {
            ERROR(r->server, "post_request failed: %s", errbuf);
        }
        else {
            ERROR(r->server, "post_request failed: %s", curl_easy_strerror(res));
        }
    }
    curl_pool_put(curl_pool, curl);
    free(response.data);
    return NULL;
}

void set_call_reason(request_context *ctx, validation_result_t vr) {
    switch (vr) {
        case NULL_COOKIE:
            ctx->call_reason = NO_COOKIE;
            break;
        case EXPIRED:
            ctx->call_reason = EXPIRED_COOKIE;
            break;
        case DECRYPTION_FAILED:
            ctx->call_reason = COOKIE_DECRYPTION_FAILED;
            break;
        case INVALID:
            ctx->call_reason = COOKIE_VALIDATION_FAILED;
            break;
        default:
            ctx->call_reason = COOKIE_VALIDATION_FAILED;
    }
}

static bool is_sensitive_route(request_rec *r, px_config *conf) {
    apr_array_header_t *sensitive_routes = conf->sensitive_routes;
    for (int i = 0; i < sensitive_routes->nelts; i++) {
        char *route = APR_ARRAY_IDX(sensitive_routes, i, char*);
        if (strcmp(r->uri, route) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_sensitive_route_prefix(request_rec *r, px_config *conf) {
    apr_array_header_t *sensitive_routes_prefix = conf->sensitive_routes_prefix;
    for (int i = 0; i < sensitive_routes_prefix->nelts; i++) {
        char *prefix = APR_ARRAY_IDX(sensitive_routes_prefix, i, char*);
        if (strncmp(r->uri, prefix, strlen(prefix)) == 0) {
            return true;
        }
    }
    return false;
}

static bool enable_block_for_hostname(request_rec *r, apr_array_header_t *domains_list) {
    // domains list not configured, module will be enabled globally and not per domainf
    if (domains_list->nelts == 0) return true;
    const char *req_hostname = r->hostname;
    if (req_hostname == NULL) return true;
    for (int i = 0; i < domains_list->nelts; i++) {
        const char *domain = APR_ARRAY_IDX(domains_list, i, const char*);
        if (strcmp(req_hostname, domain) == 0) {
            return true;
        }
    }
    return false;
}

bool verify_captcha(request_context *ctx, px_config *conf) {
    if (!ctx->px_captcha) {
        return false;
    }

    // preventing reuse of captcha cookie by deleting it
    apr_status_t res = ap_cookie_remove2(ctx->r, CAPTCHA_COOKIE, NULL, ctx->r->headers_out, ctx->r->err_headers_out, NULL);
    if (res != APR_SUCCESS) {
        ERROR(ctx->r->server, "could not remove _pxCatpcha from request");
    }

    char *payload = create_captcha_payload(ctx, conf);
    INFO(ctx->r->server, "verify_captcha: request - (%s)", payload);
    if (!payload) {
        INFO(ctx->r->server, "verify_captcha: failed to format captcha payload. url: (%s)", ctx->full_url);
        return true;
    }

    char *response_str = post_request(conf->captcha_api_url, payload, conf->auth_header, conf->api_timeout, ctx->r, conf->curl_pool);
    free(payload);
    if (!response_str) {
        INFO(ctx->r->server, "verify_captcha: failed to perform captcha validation request. url: (%s)", ctx->full_url);
        return false; // in case we are getting non 200 response
    }

    INFO(ctx->r->server, "verify_captcha: server response (%s)", response_str);
    captcha_response *c = parse_captcha_response(response_str, ctx);
    free(response_str);
    return (c && c->status == 0);
}

static void post_verification(request_context *ctx, px_config *conf, bool request_valid) {
    report_data *rd = (report_data*)apr_palloc(ctx->r->server->process->pool, sizeof(report_data));
    /*report_data *rd = (report_data*)apr_palloc(ctx->r->server->process->pool, sizeof(report_data));*/

    rd->url = conf->activities_api_url;
    rd->server = ctx->r->server;
    rd->api_timeout = conf->api_timeout;

    const char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
    if (strcmp(activity_type, BLOCKED_ACTIVITY_TYPE) == 0 || conf->send_page_activities) {
        char **activity = (char**) apr_palloc(ctx->r->server->process->pool, sizeof(char*));
        *activity = create_activity(activity_type, conf, ctx);
        if (!*activity) {
            ERROR(ctx->r->server, "post_verification: (%s) create activity failed", activity_type);
            return;
        }
        rd->activity = activity;
        rd->auth_header = conf->auth_header;
        apr_thread_pool_t **t = conf->activity_reporter->thread_pool;
        apr_thread_pool_push(*t, send_activity, (void*)rd, 0 ,0);
        thread_pool_stats(*t, ctx);
        /*char *resp = post_request(conf->activities_api_url, activity, conf->auth_header, conf->api_timeout, ctx->r, conf->curl_pool);*/
        /*free(activity);*/
        /*if (resp) {*/
            /*free(resp);*/
        /*} else {*/
            /*ERROR(ctx->r->server, "post_verification: (%s) send failed", activity_type);*/
        /*}*/
    }
}

bool px_should_verify_request(request_rec *r, px_config *conf) {
    if (!conf->module_enabled) {
        return false;
    }

    if (conf->block_page_url && strcmp(r->uri, conf->block_page_url) == 0) {
        return false;
    }

    const char *file_ending = strrchr(r->uri, '.');
    if (file_ending) {
        const apr_array_header_t *file_exts = conf->custom_file_ext_whitelist;
        if (file_exts->nelts > 0) {
            // using custom file extension whitelist
            for (int i = 0; i < file_exts->nelts; i++) {
                const char *file_ext = APR_ARRAY_IDX(file_exts, i, const char*);
                if (strcmp(file_ending, file_ext) == 0) {
                    return false;
                }
            }
        } else {
            // using default whitelist
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

risk_response* risk_api_get(const request_context *ctx, const px_config *conf) {
    char *risk_payload = create_risk_payload(ctx, conf);
    if (!risk_payload) {
        return NULL;
    }
    INFO(ctx->r->server, "risk payload: %s", risk_payload);
    char *risk_response_str = post_request(conf->risk_api_url , risk_payload, conf->auth_header, conf->api_timeout, ctx->r, conf->curl_pool);
    INFO(ctx->r->server, "risk response: %s", risk_response_str);
    free(risk_payload);
    if (!risk_response_str) {
        return NULL;
    }

    INFO(ctx->r->server, "risk_api_get: server response (%s)", risk_response_str);
    risk_response *risk_response = parse_risk_response(risk_response_str, ctx);
    free(risk_response_str);
    return risk_response;
}

int populate_captcha_cookie_data(apr_pool_t *p, const char *captcha_cookie, request_context *ctx) {
    const char *delim = ":";
    char *saveptr;
    char *str = apr_pstrdup(p, captcha_cookie);
    ctx->px_captcha = apr_strtok(str, delim, &saveptr);
    ctx->uuid = apr_strtok(NULL, delim, &saveptr);
    ctx->vid = apr_strtok(NULL, delim, &saveptr);
}

request_context* create_context(request_rec *r, const px_config *conf) {
    request_context *ctx = (request_context*) apr_pcalloc(r->pool, sizeof(request_context));

    const char *px_cookie = NULL;
    const char *px_captcha_cookie = NULL;
    char *captcha_cookie = NULL;
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    apr_status_t status = ap_cookie_read(r, PX_COOKIE, &px_cookie, 0);
    status = ap_cookie_read(r, CAPTCHA_COOKIE, &px_captcha_cookie, 0);
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
            if (strncmp(cookie, CAPTCHA_COOKIE, 10) == 0) {
                apr_pstrdup(r->pool, apr_strtok(cookie, "=", &val_ctx));
                captcha_cookie = apr_pstrdup(r->pool, apr_strtok(NULL, "", &val_ctx));
            } else if (strncmp(cookie, PX_COOKIE, 3) == 0) {
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
    ctx->px_cookie_decrypted = NULL;
    ctx->px_cookie_orig = NULL;
    ctx->uri = r->unparsed_uri;
    ctx->hostname = r->hostname;
    ctx->http_method = r->method;
    ctx->useragent = apr_table_get(r->headers_in, "User-Agent");
    // TODO(barak): full_url is missing the protocol like http:// or https://
    ctx->full_url = apr_pstrcat(r->pool, r->hostname, r->unparsed_uri, NULL);
    ctx->vid = NULL;
    ctx->px_cookie_orig = NULL;

    if (captcha_cookie) {
        populate_captcha_cookie_data(r->pool, captcha_cookie, ctx);
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
    ctx->block_enabled = enable_block_for_hostname(r, conf->enabled_hostnames);
    ctx->r = r;

    INFO(r->server, "create_context: useragent: (%s), px_cookie: (%s), full_url: (%s), hostname: (%s) , http_method: (%s), http_version: (%s), uri: (%s), ip: (%s), block_enabled: (%d)", ctx->useragent, ctx->px_cookie, ctx->full_url, ctx->hostname, ctx->http_method, ctx->http_version, ctx->uri, ctx->ip, ctx->block_enabled);

    return ctx;
}

bool px_verify_request(request_context *ctx, px_config *conf) {

    bool request_valid = true;

    risk_response *risk_response;

    /*apr_thread_create(&t, NULL, worker, (void*)ctx->r->server, ctx->r->pool);*/
    /*apr_thread_yield();*/


    if (conf->captcha_enabled && ctx->px_captcha) {
        if (verify_captcha(ctx, conf)) {
            INFO(ctx->r->server, "verify_captcha: validation status true");
            // clean users cookie on captcha verification
            apr_status_t res = ap_cookie_remove2(ctx->r, PX_COOKIE, NULL, ctx->r->headers_out, ctx->r->err_headers_out, NULL);
            if (res != APR_SUCCESS) {
                ERROR(ctx->r->server, "could not remove _px from request");
            }
            post_verification(ctx, conf, true);
            return request_valid;
        } else {
            INFO(ctx->r->server, "verify_captcha: validation status false, createing risk_api for this request");
            // pxCaptcha is not valid: removing captcha cookie data
            ctx->uuid = NULL;
            ctx->vid = NULL;
            ctx->call_reason = CAPTCHA_FAILED;
            risk_response = risk_api_get(ctx, conf);
            goto handle_response;
        }
    }

    /*INFO(ctx->r->server, "yielding this thread");*/
    /*apr_thread_yield();*/
    validation_result_t vr;
    if (ctx->px_cookie == NULL) {
        vr = NULL_COOKIE;
    } else {
        risk_cookie *c = decode_cookie(ctx->px_cookie, conf->cookie_key, ctx);
        if (c) {
            ctx->score = c->b_val;
            ctx->vid = c->vid;
            ctx->uuid = c->uuid;
            vr = validate_cookie(c, ctx, conf->cookie_key);
        } else {
            ctx->px_cookie_orig = ctx->px_cookie;
            vr = DECRYPTION_FAILED;
        }
    }
    switch (vr) {
        case VALID:
            request_valid = ctx->score < conf->blocking_score;
            if (!request_valid) {
                ctx->block_reason = COOKIE;
            } else if (is_sensitive_route_prefix(ctx->r, conf ) || is_sensitive_route(ctx->r, conf)) {
                ctx->call_reason = SENSITIVE_ROUTE;
                risk_response = risk_api_get(ctx, conf);
                goto handle_response;
            }
            break;
        case EXPIRED:
        case DECRYPTION_FAILED:
        case NULL_COOKIE:
        case INVALID:
            set_call_reason(ctx, vr);
            risk_response = risk_api_get(ctx, conf);
handle_response:
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
