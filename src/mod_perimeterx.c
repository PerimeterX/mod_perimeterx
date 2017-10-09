/*
 * PerimeterX Apache mod
 */
#include <stdio.h>
#include <stdbool.h>

#include <jansson.h>
#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <ap_provider.h>
#include <http_request.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_escape.h>
#include <apr_atomic.h>
#include <apr_portable.h>
#include <apr_signal.h>
#include <apr_base64.h>
#include <apr_time.h>

#include "px_utils.h"
#include "px_types.h"
#include "px_template.h"
#include "px_enforcer.h"
#include "px_json.h"
#include "px_client.h"

module AP_MODULE_DECLARE_DATA perimeterx_module;

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *DEFAULT_BASE_URL = "https://sapi-%s.perimeterx.net";
static const char *RISK_API = "/api/v2/risk";
static const char *CAPTCHA_API = "/api/v2/risk/captcha";
static const char *ACTIVITIES_API = "/api/v1/collector/s2s";
static const char *HEALTH_CHECK_API = "/api/v1/kpi/status";


static const char *CONTENT_TYPE_JSON = "application/json";
static const char *CONTENT_TYPE_HTML = "text/html";

// constants
static const char *PERIMETERX_MODULE_VERSION = "Apache Module v2.8.0-rc.6";
static const char *SCORE_HEADER_NAME = "X-PX-SCORE";
static const char *VID_HEADER_NAME = "X-PX-VID";
static const char *UUID_HEADER_NAME = "X-PX-UUID";
static const char *ACCEPT_HEADER_NAME = "Accept";
static const char *ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
static const char *ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
static const char *ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
static const char *ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";

static const char *CAPTCHA_COOKIE = "_pxCaptcha";
static const int MAX_CURL_POOL_SIZE = 10000;
static const int ERR_BUF_SIZE = 128;

static const char *ERROR_CONFIG_MISSING = "mod_perimeterx: config structure not allocated";
static const char *MAX_CURL_POOL_SIZE_EXCEEDED = "mod_perimeterx: CurlPoolSize can not exceed 10000";
static const char *INVALID_WORKER_NUMBER_QUEUE_SIZE = "mod_perimeterx: invalid number of background activity workers, must be greater than zero";
static const char *INVALID_ACTIVITY_QUEUE_SIZE = "mod_perimeterx: invalid background activity queue size , must be greater than zero";
static const char *ERROR_BASE_URL_BEFORE_APP_ID = "mod_perimeterx: BaseUrl was set before AppId";
static const char *INVALID_MAX_AGE_SIZE = "mod_perimeterx: invalid number for access-control-max-age";

static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";

#ifdef DEBUG
extern const char *BLOCK_REASON_STR[];
extern const char *CALL_REASON_STR[];
#endif // DEBUG

char* create_response(px_config *conf, request_context *ctx) {
    // support for cors headers
    if (conf->apply_cors_by_envvar) {
        const char *value = apr_table_get(ctx->r->subprocess_env, "PX_APPLY_CORS");
        if (!value == NULL) {
            apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_ORIGIN, value);        
            if (conf->cors_allowed_methods) {
                apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_METHODS, conf->cors_allowed_methods);        
            }
            if (conf->cors_allowed_headers) {
                apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_HEADERS, conf->cors_allowed_headers);        
            }
            if (conf->cors_max_age > -1) {
                apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_MAX_AGE, conf->cors_max_age);        
            }
        }
    }

    if (ctx->token_origin == TOKEN_ORIGIN_HEADER) {
        ctx->response_application_json = true;
    } else if (conf->json_response_enabled) {
        const char *accept_header = apr_table_get(ctx->r->headers_in, ACCEPT_HEADER_NAME);
        bool match = accept_header && strstr(accept_header, CONTENT_TYPE_JSON);
        if (match) {
            ctx->response_application_json = true;
            return create_json_response(conf, ctx);
        }
    }

    if (conf->vid_header_enabled && ctx->vid) {
        apr_table_set(ctx->r->headers_out, conf->vid_header_name, ctx->vid);
    }

    if (conf->uuid_header_enabled && ctx->uuid) {
        apr_table_set(ctx->r->headers_out, conf->uuid_header_name, ctx->uuid);
    }

    const char *template = select_template(conf, ctx);

    // render html page with the relevant template
    size_t html_size;
    char *html = NULL;
    int res = render_template(template, &html, ctx, conf, &html_size);
    if (res) {
        // failed to render
        return NULL;
    }

    // formulate server response according to px token type
    if (ctx->token_origin == TOKEN_ORIGIN_HEADER) {
        int expected_encoded_len = apr_base64_encode_len(html_size);
        char *encoded_html = apr_palloc(ctx->r->pool, expected_encoded_len + 1);
        int encoded_len = apr_base64_encode(encoded_html, html, html_size);
        free(html);
        if (encoded_html == 0) {
            return NULL;
        }
        return create_mobile_response(conf, ctx, encoded_html);
    }
    return html;
}


void post_verification(request_context *ctx, px_config *conf, bool request_valid) {
    const char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
    if (strcmp(activity_type, BLOCKED_ACTIVITY_TYPE) == 0 || conf->send_page_activities) {
        char *activity = create_activity(activity_type, conf, ctx);
        if (!activity) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: post_verification: (%s) create activity failed", ctx->app_id, activity_type);
            return;
        }
        if (conf->background_activity_send) {
            apr_queue_push(conf->activity_queue, activity);
        } else {
            post_request(conf->activities_api_url, activity, conf->api_timeout_ms, conf, ctx, NULL, NULL);
            free(activity);
        }
    }
}

int px_handle_request(request_rec *r, px_config *conf) {
    // fail open mode
    if (apr_atomic_read32(&conf->px_errors_count) >= conf->px_errors_threshold) {
        return OK;
    }

    // Decline internal redirects and subrequests 
    if (r->prev) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: px_handle_request: request declined - interal redirect or subrequest", conf->app_id);
	    return DECLINED;
    }

    if (!px_should_verify_request(r, conf)) {
        return OK;
    }

    if (conf->skip_mod_by_envvar) {
        const char *skip_px = apr_table_get(r->subprocess_env, "PX_SKIP_MODULE");
        if  (skip_px != NULL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: px_handle_request: PX_SKIP_MODULE was set on the request", conf->app_id);
            return OK;
        }
    }

    request_context *ctx = create_context(r, conf);
    if (ctx) {
        bool request_valid = px_verify_request(ctx, conf);

        // if request is not valid, and monitor mode is on, toggle request_valid and set pass_reason
        if (conf->monitor_mode && !request_valid) {
            ap_log_error(APLOG_MARK, LOG_ERR, 0, r->server, "[%s]: request should have been block but monitor mode is on", conf->app_id);
            ctx->pass_reason = PASS_REASON_MONITOR_MODE;
            request_valid = true;
        }
        post_verification(ctx, conf, request_valid);
#if DEBUG
        char *aut_test_header = apr_pstrdup(r->pool, (char *) apr_table_get(r->headers_in, PX_AUT_HEADER_KEY));
        if (aut_test_header && strcmp(aut_test_header, PX_AUT_HEADER_VALUE) == 0) {
            const char *ctx_str = json_context(ctx);
            ap_set_content_type(r, CONTENT_TYPE_JSON);
            ap_rprintf(r, "%s", ctx_str);
            free((void*)ctx_str);
            return DONE;
        }
#endif

        if (conf->score_header_enabled) {
            const char *score_str = apr_itoa(r->pool, ctx->score);
            apr_table_set(r->headers_in, conf->score_header_name, score_str);
        }

        ap_log_error(APLOG_MARK, LOG_ERR, 0, r->server, "[%s]: request_valid %d , block_enabled %d ", conf->app_id, request_valid, ctx->block_enabled);

        if (!request_valid && ctx->block_enabled) {
            // redirecting requests to custom block page if exists
            if (conf->block_page_url) {
                const char *redirect_url;
                const char *url_arg = r->args
                    ? apr_pstrcat(r->pool, r->uri, "?", r->args, NULL)
                    : apr_pstrcat(r->pool, r->uri, NULL);
                apr_size_t encoded_url_len = 0;
                if (apr_escape_urlencoded(NULL, url_arg, APR_ESCAPE_STRING, &encoded_url_len) == APR_SUCCESS)   {
                    char *encoded_url = apr_pcalloc(r->pool,encoded_url_len + 1);
                    apr_escape_urlencoded(encoded_url, url_arg, APR_ESCAPE_STRING, NULL);
                    redirect_url = apr_pstrcat(r->pool, conf->block_page_url, "?url=", encoded_url, "&uuid=", ctx->uuid, "&vid=", ctx->vid,  NULL);
                } else {
                    redirect_url = apr_pstrcat(r->pool, conf->block_page_url, "?url=", r->uri, "&uuid=", ctx->uuid, "&vid=", ctx->vid,  NULL);
                }
                apr_table_set(r->headers_out, "Location", redirect_url);
                return HTTP_TEMPORARY_REDIRECT;
            }

            char *response = create_response(conf, ctx);
            if (response) {
                const char *content_type = CONTENT_TYPE_HTML;
                if (ctx->response_application_json) {
                    content_type = CONTENT_TYPE_JSON;
                }
                ap_set_content_type(ctx->r, content_type);
                ctx->r->status = HTTP_FORBIDDEN;
                ap_rwrite(response, strlen(response), ctx->r);
                free(response);
                return DONE;
            }
            // failed to create response
            ap_log_error(APLOG_MARK, LOG_ERR, 0, r->server, "[%s]: Could not create block page with template, passing request", conf->app_id);
        }
    }
    r->status = HTTP_OK;
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: px_handle_request: request passed, score %d, monitor mode %d", ctx->app_id, ctx->score, conf->monitor_mode);
    return OK;
}

// Background thread that wakes up after reacing X timeoutes in interval length Y and checks when service is available again
static void *APR_THREAD_FUNC health_check(apr_thread_t *thd, void *data) {
    health_check_data *hc = (health_check_data*) data;
    px_config *conf = hc->config;

    const char *health_check_url = apr_pstrcat(hc->server->process->pool, hc->config->base_url, HEALTH_CHECK_API, NULL);
    CURL *curl = curl_easy_init();
    CURLcode res;
    while (!conf->should_exit_thread) {
        // wait for condition and reset errors count on internal
        apr_thread_mutex_lock(conf->health_check_cond_mutex);
        while (!conf->should_exit_thread && apr_atomic_read32(&conf->px_errors_count) < conf->px_errors_threshold) {
            if (apr_thread_cond_timedwait(conf->health_check_cond, conf->health_check_cond_mutex, conf->health_check_interval) == APR_TIMEUP) {
                apr_atomic_set32(&conf->px_errors_count, 0);
            }
        }

        apr_thread_mutex_unlock(conf->health_check_cond_mutex);
        if (conf->should_exit_thread) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, hc->server, "health_check: marked to exit");
            break;
        }

        // do health check until success
        CURLcode res = CURLE_AGAIN;
        while (!conf->should_exit_thread && res != CURLE_OK) {
            curl_easy_setopt(curl, CURLOPT_URL, health_check_url);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, conf->api_timeout_ms);
            res = curl_easy_perform(curl);
            if (res != CURLE_OK && res != CURLE_OPERATION_TIMEDOUT) {
                apr_sleep(1000); // TODO(barak): should be configured with nice default
            }
        }
        apr_atomic_set32(&conf->px_errors_count, 0);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, hc->server, "health_check: thread exiting");
    curl_easy_cleanup(curl);
    apr_thread_exit(thd, 0);
    return NULL;
}

static void *APR_THREAD_FUNC background_activity_consumer(apr_thread_t *thd, void *data) {
    activity_consumer_data *consumer_data = (activity_consumer_data*)data;
    px_config *conf = consumer_data->config;
    CURL *curl = curl_easy_init();

    void *v;
    if (!curl) {
        ap_log_error(APLOG_MARK, LOG_ERR, 0, consumer_data->server, "[%s]: could not create curl handle, thread will not run to consume messages", conf->app_id);
        return NULL;
    }

    while (true) {
        apr_status_t rv = apr_queue_pop(conf->activity_queue, &v);
        if (rv == APR_EINTR) {
            continue;
        }
        if (rv == APR_EOF) {
            break;
        }
        if (rv == APR_SUCCESS && v) {
            char *activity = (char *)v;
            post_request_helper(curl, conf->activities_api_url, activity, conf->api_timeout_ms, conf, consumer_data->server, NULL);
            free(activity);
        }
    }

    curl_easy_cleanup(curl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, consumer_data->server,
            "[%s]: activity consumer thread exited", conf->app_id);
    apr_thread_exit(thd, 0);
    ap_log_error(APLOG_MARK, LOG_ERR, 0, consumer_data->server, "[%s]: Sending activity completed", conf->app_id);
    return NULL;
}

// --------------------------------------------------------------------------------
//

static apr_status_t create_health_check(apr_pool_t *p, server_rec *s, px_config *cfg) {
    apr_status_t rv;

    health_check_data *hc_data= (health_check_data*)apr_palloc(p, sizeof(health_check_data));
    cfg->px_errors_count = 0;
    hc_data->server = s;
    hc_data->config = cfg;

    rv = apr_thread_cond_create(&cfg->health_check_cond, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while init health_check thread cond");
        return rv;
    }

    rv = apr_thread_create(&cfg->health_check_thread, NULL, health_check, (void*) hc_data, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while init health_check thread create");
        return rv;
    }

    rv = apr_thread_mutex_create(&cfg->health_check_cond_mutex, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while creating health_check thread mutex");
        return rv;
    }

    return rv;
}

static apr_status_t background_activity_send_init(apr_pool_t *pool, server_rec *s, px_config *cfg) {
    apr_status_t rv;

    rv = apr_queue_create(&cfg->activity_queue, cfg->background_activity_queue_size, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                "[%s]: failed to initialize background activity queue", cfg->app_id);
        return rv;
    }

    activity_consumer_data *consumer_data = apr_palloc(s->process->pool, sizeof(activity_consumer_data));
    consumer_data->server = s;
    consumer_data->config = cfg;

    rv = apr_thread_pool_create(&cfg->activity_thread_pool, 0, cfg->background_activity_workers, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                "[%s]: failed to initialize background activity thread pool", cfg->app_id);
        return rv;
    }

    for (unsigned int i = 0; i < cfg->background_activity_workers; ++i) {
        rv = apr_thread_pool_push(cfg->activity_thread_pool, background_activity_consumer, consumer_data, 0, NULL);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "failed to push background activity consumer");
            return rv;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "finished init background activitys");
    return rv;
}

// free all (apache) unmanaged resources
static apr_status_t px_child_exit(void *data) {
    server_rec *s = (server_rec*)data;
    px_config *cfg = ap_get_module_config(s->module_config, &perimeterx_module);

    // signaling health check thread to exit
    if (cfg->px_health_check) {
        cfg->should_exit_thread = true;
        apr_thread_cond_signal(cfg->health_check_cond);
    }
    // terminate the queue and wake up all idle threads
    if (cfg->activity_queue) {
        apr_status_t rv = apr_queue_term(cfg->activity_queue);
        if (rv != APR_SUCCESS) {
            char buf[ERR_BUF_SIZE];
            char *err = apr_strerror(rv, buf, sizeof(buf));
            ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "px_child_exit: could not terminate the queue - %s", err);
        }
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "px_child_exit: cleanup finished");
}

static apr_status_t px_child_setup(apr_pool_t *p, server_rec *s) {
    apr_status_t rv;

    // init each virtual host
    for (server_rec *vs = s; vs; vs = vs->next) {
        px_config *cfg = ap_get_module_config(vs->module_config, &perimeterx_module);

        rv = apr_pool_create(&cfg->pool, vs->process->pool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "px_hook_child_init: error while trying to init curl_pool");
            return rv;
        }

        cfg->curl_pool = curl_pool_create(cfg->pool, cfg->curl_pool_size);

        if (cfg->background_activity_send) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s,
                    "px_hook_child_init: start init for background_activity_send");
            rv = background_activity_send_init(cfg->pool, vs, cfg);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                        "px_hook_child_init: error while trying to init background_activity_consumer");
                return rv;
            }
        }

        if (cfg->px_health_check) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s,
                    "px_hook_child_init: setting up health_check thread");
            rv = create_health_check(cfg->pool, vs, cfg);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                        "px_hook_child_init: error while trying to init health_check_thread");
                return rv;
            }
        }
        apr_pool_cleanup_register(p, s, px_child_exit, apr_pool_cleanup_null);
    }

    return rv;
}

static void px_hook_child_init(apr_pool_t *p, server_rec *s) {
    apr_status_t rv = px_child_setup(p, s);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "child init failed!");
    }
}

static apr_status_t px_cleanup_pre_config(void *data) {
    ERR_free_strings();
    EVP_cleanup();
    return APR_SUCCESS;
}

static int px_hook_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp) {
    curl_global_init(CURL_GLOBAL_ALL);
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
    if (conf->base_url_is_set){
        return ERROR_BASE_URL_BEFORE_APP_ID;
    }
    conf->app_id = app_id;
    conf->base_url = apr_psprintf(cmd->pool, DEFAULT_BASE_URL, app_id, NULL);
    conf->risk_api_url = apr_pstrcat(cmd->pool, conf->base_url, RISK_API, NULL);
    conf->captcha_api_url = apr_pstrcat(cmd->pool, conf->base_url, CAPTCHA_API, NULL);
    conf->activities_api_url = apr_pstrcat(cmd->pool, conf->base_url, ACTIVITIES_API, NULL);
    return NULL;
}

static const char *set_payload_key(cmd_parms *cmd, void *config, const char *payload_key) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->payload_key = payload_key;
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
    long timeout = atoi(api_timeout) * 1000;
    conf->api_timeout_ms = timeout;
    if (!conf->is_captcha_timeout_set) {
        conf->captcha_timeout = timeout;
    }
    return NULL;
}

static const char *set_api_timeout_ms(cmd_parms *cmd, void *config, const char *api_timeout_ms) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    long timeout = atoi(api_timeout_ms);
    conf->api_timeout_ms = timeout;
    if (!conf->is_captcha_timeout_set) {
        conf->captcha_timeout = timeout;
    }
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
    int pool_size = atoi(curl_pool_size);
    if (pool_size > MAX_CURL_POOL_SIZE) {
        return MAX_CURL_POOL_SIZE_EXCEEDED;
    }
    conf->curl_pool_size = pool_size;
    return NULL;
}

static const char *set_base_url(cmd_parms *cmd, void *config, const char *base_url) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->base_url_is_set = true;
    conf->base_url = base_url;
    conf->risk_api_url = apr_pstrcat(cmd->pool, conf->base_url, RISK_API, NULL);
    conf->captcha_api_url = apr_pstrcat(cmd->pool, conf->base_url, CAPTCHA_API, NULL);
    conf->activities_api_url = apr_pstrcat(cmd->pool, conf->base_url, ACTIVITIES_API, NULL);
    return NULL;
}

static const char *set_skip_mod_by_envvar(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->skip_mod_by_envvar = arg ? true : false;
    return NULL;
}

static const char *set_block_page_url(cmd_parms *cmd, void *config, const char *url) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    conf->block_page_url = url;
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
    const char** entry = apr_array_push(conf->custom_file_ext_whitelist);
    *entry = file_extension;
    return NULL;
}

static const char *add_sensitive_route(cmd_parms *cmd, void *config, const char *route) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->sensitive_routes);
    *entry = route;
    return NULL;
}

static const char *add_sensitive_route_prefix(cmd_parms *cmd, void *config, const char *route_prefix) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->sensitive_routes_prefix);
    *entry = route_prefix;
    return NULL;
}

static const char *add_host_to_list(cmd_parms *cmd, void *config, const char *domain) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->enabled_hostnames);
    *entry = domain;
    return NULL;
}

static const char *set_js_ref(cmd_parms *cmd, void *config, const char *js_ref){
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->js_ref = js_ref;
    return NULL;
}

static const char *set_css_ref(cmd_parms *cmd, void *config, const char *css_ref){
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->css_ref = css_ref;
    return NULL;
}

static const char *set_custom_logo(cmd_parms *cmd, void *config, const char *custom_logo){
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->custom_logo = custom_logo;
    return NULL;
}

static const char *set_background_activity_send(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->background_activity_send = arg ? true : false;
    return NULL;
}

static const char *set_px_health_check(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->px_health_check = arg ? true : false;
    return NULL;
}

static const char *set_max_px_errors_threshold(cmd_parms *cmd, void *config, const char *arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->px_errors_threshold = atoi(arg);
    return NULL;
}

static const char *set_px_errors_count_interval(cmd_parms *cmd, void *config, const char *arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->health_check_interval = atoi(arg) * 1000; // millisecond to microsecond
    return NULL;
}

static const char *set_background_activity_workers(cmd_parms *cmd, void *config, const char *arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    int worker_number = atoi(arg);
    if (worker_number < 1) {
        return INVALID_WORKER_NUMBER_QUEUE_SIZE;
    }
    conf->background_activity_workers = worker_number;
    return NULL;
}

static const char *set_background_activity_queue_size(cmd_parms *cmd, void *config, const char *arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    int queue_size = atoi(arg);
    if (queue_size < 1) {
        return INVALID_ACTIVITY_QUEUE_SIZE;
    }
    conf->background_activity_queue_size = queue_size;
    return NULL;
}

static const char* set_proxy_url(cmd_parms *cmd, void *config, const char *proxy_url) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->proxy_url = proxy_url;
    return NULL;
}

static const char* set_captcha_timeout(cmd_parms *cmd, void *config, const char *captcha_timeout) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->captcha_timeout = atoi(captcha_timeout);
    conf->is_captcha_timeout_set = true;
    return NULL;
}

static const char* set_score_header(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->score_header_enabled = arg ? true : false;
    return NULL;
}

static const char* set_score_header_name(cmd_parms *cmd, void *config, const char *score_header_name) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->score_header_name = score_header_name;
    return NULL;
}

static const char *enable_token_via_header(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->enable_token_via_header = arg ? true : false;
    return NULL;
}

static const char *enable_vid_header(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->vid_header_enabled = arg ? true : false;
    return NULL;
}

static const char *enable_uuid_header(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->uuid_header_enabled = arg ? true : false;
    return NULL;
}

static const char* set_uuid_header_name(cmd_parms *cmd, void *config, const char *uuid_header_name) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->uuid_header_name = uuid_header_name;
    return NULL;
}

static const char* set_vid_header_name(cmd_parms *cmd, void *config, const char *vid_header_name) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->vid_header_name = vid_header_name;
    return NULL;
}

static const char *enable_json_response(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->json_response_enabled = arg ? true : false;
    return NULL;
}

static const char *enable_cors_headers(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->apply_cors_by_envvar = arg ? true : false;
    return NULL;
}

static const char* set_cors_max_age(cmd_parms *cmd, void *config, const char *max_age) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    int max_age = atoi(max_age);
    if (max_age < 1) {
        return INVALID_MAX_AGE_SIZE;
    }
    conf->cors_max_age = max_age;

    return NULL;
}

static const char* set_cors_allowed_methods(cmd_parms *cmd, void *config, const char *allowed_methods) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    conf->cors_allowed_methods = allowed_methods;
    return NULL;
}

static const char* set_cors_allowed_headers(cmd_parms *cmd, void *config, const char *allowed_headers) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    conf->cors_allowed_headers = allowed_headers;
    return NULL;
}

static const char* set_captcha_type(cmd_parms *cmd, void *config, const char *captcha_type) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    if (!strcmp(captcha_type,"funCaptcha")) {
        conf->captcha_type = CAPTCHA_TYPE_FUNCAPTCHA;
    } else { 
        conf->captcha_type = CAPTCHA_TYPE_RECAPTCHA;
    }

    return NULL;
}

static const char *set_monitor_mode(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->monitor_mode = arg ? true : false;
    return NULL;
}

static int px_hook_post_request(request_rec *r) {
    px_config *conf = ap_get_module_config(r->server->module_config, &perimeterx_module);
    return px_handle_request(r, conf);
}

static void *create_config(apr_pool_t *p) {
    px_config *conf = apr_pcalloc(p, sizeof(px_config));
    if (conf) {
        conf->module_enabled = false;
        conf->api_timeout_ms = 1000L;
        conf->captcha_timeout = 1000L;
        conf->send_page_activities = true;
        conf->blocking_score = 101;
        conf->captcha_enabled = true;
        conf->module_version = PERIMETERX_MODULE_VERSION;
        conf->skip_mod_by_envvar = false;
        conf->curl_pool_size = 100;
        conf->base_url = DEFAULT_BASE_URL;
        conf->risk_api_url = apr_pstrcat(p, conf->base_url, RISK_API, NULL);
        conf->captcha_api_url = apr_pstrcat(p, conf->base_url, CAPTCHA_API, NULL);
        conf->activities_api_url = apr_pstrcat(p, conf->base_url, ACTIVITIES_API, NULL);
        conf->auth_token = "";
        conf->auth_header = "";
        conf->routes_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->useragents_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->custom_file_ext_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->ip_header_keys = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_routes = apr_array_make(p, 0, sizeof(char*));
        conf->enabled_hostnames = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_routes_prefix = apr_array_make(p, 0, sizeof(char*));
        conf->background_activity_send = true;
        conf->background_activity_workers = 10;
        conf->background_activity_queue_size = 1000;
        conf->px_errors_threshold = 100;
        conf->health_check_interval = apr_time_sec(60); // 1 minute
        conf->px_health_check = false;
        conf->score_header_name = SCORE_HEADER_NAME;
        conf->vid_header_enabled = false;
        conf->uuid_header_enabled = false;
        conf->uuid_header_name = UUID_HEADER_NAME;
        conf->vid_header_name = VID_HEADER_NAME;
        conf->json_response_enabled = false;
        conf->apply_cors_by_envvar = false;
        conf->cors_allowed_methods = NULL;
        conf->cors_allowed_headers = NULL;
        CONF->CORS_MAX_AGE = -1;
        CONF->CAPTCHA_TYPE = CAPTCHA_TYPE_RECAPTCHA;
        CONF->MONITOR_MODE = FALSE;
        CONF->ENABLE_TOKEN_VIA_HEADER = TRUE;
    }
    RETURN CONF;
}

STATIC CONST COMMAND_REC PX_DIRECTIVES[] = {
    AP_INIT_FLAG("PXENABLED",
            SET_PX_ENABLED,
            NULL,
            OR_ALL,
            "TURN ON MOD_PX"),
    AP_INIT_FLAG("CAPTCHA",
            SET_CAPTCHA_ENABLED,
            NULL,
            OR_ALL,
            "INCLUDE CAPTCHA IN THE BLOCKING PAGE"),
    AP_INIT_TAKE1("APPID",
            SET_APP_ID,
            NULL,
            OR_ALL,
            "PX APPLICATION ID"),
    AP_INIT_TAKE1("COOKIEKEY",
            SET_PAYLOAD_KEY,
            NULL,
            OR_ALL,
            "COOKIE DECRYPTION KEY"),
    AP_INIT_TAKE1("AUTHTOKEN",
            SET_AUTH_TOKEN,
            NULL,
            OR_ALL,
            "RISK API AUTH TOKEN"),
    AP_INIT_TAKE1("CUSTOMLOGO",
            SET_CUSTOM_LOGO,
            NULL,
            OR_ALL,
            "SET CUSTOM LOGO ON BLOCK PAGE"),
    AP_INIT_TAKE1("CSSREF",
            SET_CSS_REF,
            NULL,
            OR_ALL,
            "SET CUSTOM CSS ON BLOCK PAGE"),
    AP_INIT_TAKE1("JSREF",
            SET_JS_REF,
            NULL,
            OR_ALL,
            "SET CUSTOM JAVASCRIPT ON BLOCK PAGE"),
    AP_INIT_TAKE1("BLOCKINGSCORE",
            SET_BLOCKING_SCORE,
            NULL,
            OR_ALL,
            "REQUEST WITH SCORE EQUAL OR GREATER THAN THIS WILL BE BLOCKED"),
    AP_INIT_TAKE1("APITIMEOUT",
            SET_API_TIMEOUT,
            NULL,
            OR_ALL,
            "SET TIMEOUT FOR RISK API REQUEST IN SECONDS"),
    AP_INIT_TAKE1("APITIMEOUTMS",
            SET_API_TIMEOUT_MS,
            NULL,
            OR_ALL,
            "SET TIMEOUT FOR RISK API REQUEST IN MILLISECONDS"),
    AP_INIT_TAKE1("CAPTCHATIMEOUT",
            SET_CAPTCHA_TIMEOUT,
            NULL,
            OR_ALL,
            "SET TIMEOUT FOR CAPTCHA API REQUEST IN MILLISECONDS"),
    AP_INIT_FLAG("REPORTPAGEREQUEST",
            SET_PAGEREQUEST_ENABLED,
            NULL,
            OR_ALL,
            "ENABLE PAGE_REQUEST ACTIVITIES REPORT"),
    AP_INIT_ITERATE("IPHEADER",
            SET_IP_HEADERS,
            NULL,
            OR_ALL,
            "THIS HEADERS WILL BE USED TO GET THE REQUEST REAL IP, FIRST HEADER TO GET VALID IP WILL BE USESD"),
    AP_INIT_TAKE1("CURLPOOLSIZE",
            SET_CURL_POOL_SIZE,
            NULL,
            OR_ALL,
            "DETERMINES NUMBER OF CURL ACTIVE HANDLES"),
    AP_INIT_TAKE1("BASEURL",
            SET_BASE_URL,
            NULL,
            OR_ALL,
            "PERIMETERX SERVER BASE URL"),
    AP_INIT_FLAG("DISABLEMODBYENVVAR",
            SET_SKIP_MOD_BY_ENVVAR,
            NULL,
            OR_ALL,
            "ALLOW TO DISABLE PERIMETERX MODULE BY ENVIRONMENT VARIABLE"),
    AP_INIT_TAKE1("BLOCKPAGEURL",
            SET_BLOCK_PAGE_URL,
            NULL,
            OR_ALL,
            "URL FOR CUSTOM BLOCKING PAGE"),
    AP_INIT_ITERATE("PXWHITELISTROUTES",
            ADD_ROUTE_TO_WHITELIST,
            NULL,
            OR_ALL,
            "WHITELIST BY PATHS - THIS MODULE WILL NOT APPLY ON THIS PATH LIST"),
    AP_INIT_ITERATE("PXWHITELISTUSERAGENTS",
            ADD_USERAGENT_TO_WHITELIST,
            NULL,
            OR_ALL,
            "WHITELIST BY USER-AGENTS - THIS MODULE WILL NOT APPLY ON THESE USER-AGENTS"),
    AP_INIT_ITERATE("EXTENSIONWHITELIST",
            ADD_FILE_EXTENSION_WHITELIST,
            NULL,
            OR_ALL,
            "WHITELIST BY FILE EXTENSIONS - THIS MODULE WILL NOT APPLY ON FILES WITH ONE OF THESE FILE EXTENSIONS"),
    AP_INIT_ITERATE("SENSITIVEROUTES",
            ADD_SENSITIVE_ROUTE,
            NULL,
            OR_ALL,
            "SENSITIVE ROUTES - FOR EACH OF THIS URIS THE MODULE WILL DO A SERVER-TO-SERVER CALL EVEN IF A GOOD COOKIE IS ON THE REQUEST"),
    AP_INIT_ITERATE("SENSITIVEROUTESPREFIX",
            ADD_SENSITIVE_ROUTE_PREFIX,
            NULL,
            OR_ALL,
            "SENSITIVE ROUTES BY PREFIX - FOR EACH OF THIS URIS PREFIX THE MODULE WILL DO A SERVER-TO-SERVER CALL EVEN IF A GOOD COOKIE IS ON THE REQUEST"),
    AP_INIT_ITERATE("ENABLEBLOCKINGBYHOSTNAME",
            ADD_HOST_TO_LIST,
            NULL,
            OR_ALL,
            "ENABLE BLOCKING BY HOSTNAME - LIST OF HOSTNAMES ON WHICH PX MODULE WILL BE ENABLED FOR"),
    AP_INIT_FLAG("BACKGROUNDACTIVITYSEND",
            SET_BACKGROUND_ACTIVITY_SEND,
            NULL,
            OR_ALL,
            "USE BACKGROUND WORKERS TO SEND ACTIVITIES"),
    AP_INIT_TAKE1("BACKGROUNDACTIVITYWORKERS",
            SET_BACKGROUND_ACTIVITY_WORKERS,
            NULL,
            OR_ALL,
            "NUMBER OF BACKGROUND WORKERS TO SEND ACTIVITIES"),
    AP_INIT_TAKE1("BACKGROUNDACTIVITYQUEUESIZE",
            SET_BACKGROUND_ACTIVITY_QUEUE_SIZE,
            NULL,
            OR_ALL,
            "QUEUE SIZE FOR BACKGROUND ACTIVITY SEND"),
    /* THIS SHOULD BE REMOVED IN LATER VERSION, REPLACED BY PXHEALTHCHECK */
    AP_INIT_FLAG("PXSERVICEMONITOR",
            SET_PX_HEALTH_CHECK,
            NULL,
            OR_ALL,
            "BACKGROUND MONITORING ON PERIMETERX SERVICE"),
    AP_INIT_FLAG("PXHEALTHCHECK",
            SET_PX_HEALTH_CHECK,
            NULL,
            OR_ALL,
            "BACKGROUND MONITORING ON PERIMETERX SERVICE"),
    AP_INIT_TAKE1("MAXPXERRORSTHRESHOLD",
            SET_MAX_PX_ERRORS_THRESHOLD,
            NULL,
            OR_ALL,
            "NUMBER OF ERRORS FROM PX SERVERS BEFORE RUNNING IN FAIL OPEN MODE"),
    AP_INIT_TAKE1("PXERRORSCOUNTINTERVAL",
            SET_PX_ERRORS_COUNT_INTERVAL,
            NULL,
            OR_ALL,
            "TIME IN MILLISECONDS UNTIL WE SET THE PX SERVER ERRORS COUNT BACK TO ZERO"),
    AP_INIT_TAKE1("PROXYURL",
            SET_PROXY_URL,
            NULL,
            OR_ALL,
            "PROXY URL FOR OUTGOING PERIMETERX SERVICE API"),
    AP_INIT_FLAG("SCOREHEADER",
            SET_SCORE_HEADER,
            NULL,
            OR_ALL,
            "ALLOW MODULE TO PLACE REQUEST SCORE ON RESPONSE HEADER"),
    AP_INIT_TAKE1("SCOREHEADERNAME",
            SET_SCORE_HEADER_NAME,
            NULL,
            OR_ALL,
            "SET THE NAME OF THE SCORE HEADER"),
    AP_INIT_FLAG("ENABLETOKENVIAHEADER",
            ENABLE_TOKEN_VIA_HEADER,
            NULL,
            OR_ALL,
            "ENABLE HEADER BASED TOKEN SEND"),
    AP_INIT_FLAG("VIDHEADER",
            ENABLE_VID_HEADER,
            NULL,
            OR_ALL,
            "ENABLE MODULE TO PLACE VID ON RESPONSE HEADER"),
    AP_INIT_TAKE1("VIDHEADERNAME",
            SET_VID_HEADER_NAME,
            NULL,
            OR_ALL,
            "SETS THE NAME OF VID RESPONSE HEADER"),
    AP_INIT_TAKE1("UUIDHEADERNAME",
            SET_UUID_HEADER_NAME,
            NULL,
            OR_ALL,
            "SETS THE NAME OF UUID RESPONSE HEADER"),
    AP_INIT_FLAG("UUIDHEADER",
            ENABLE_UUID_HEADER,
            NULL,
            OR_ALL,
            "ENABLE MODULE TO PLACE UUID ON RESPONSE HEADER"),
    AP_INIT_FLAG("ENABLEJSONRESPONSE",
            ENABLE_JSON_RESPONSE,
            NULL,
            OR_ALL,
            "ENABLE MODULE TO RETURN A JSON RESPONSE"),
    AP_INIT_FLAG("PXAPPLYACCESSCONTROLALLOWORIGINBYENVVAR",
            ENABLE_CORS_HEADERS,
            NULL,
            OR_ALL,
            "ENABLE MODULE TO APPY CORS HEADRES ON RESPONSE"),
    AP_INIT_TAKE1("PXAPPLYACCESSCONTROLALLOWEDHEADERS",
            SET_CORS_ALLOWED_HEADERS,
            NULL,
            OR_ALL,
            "SETS THE ALLOWED HEADERS FOR CORS"),
    AP_INIT_TAKE1("PXAPPLYACCESSCONTROLALLOWEDMETHODS",
            SET_CORS_ALLOWED_METHODS,
            NULL,
            OR_ALL,
            "SETS THE ALLOWED METHODS FOR CORS"),
    AP_INIT_TAKE1("PXAPPLYACCESSCONTROLMAXAGE",
            Set_cors_max_age,
            NULL,
            OR_ALL,
            "Sets the max age for CORS headers"),
    AP_INIT_TAKE1("CaptchaType",
            set_captcha_type,
            NULL,
            OR_ALL,
            "Sets the captcha provider"),
    AP_INIT_FLAG("MonitorMode",
            set_monitor_mode,
            NULL,
            OR_ALL,
            "Toggle monitor mode, requests will be inspected but not be blocked"),
    { NULL }
};

static void perimeterx_register_hooks(apr_pool_t *pool) {
    static const char *const asz_pre[] =
    { "mod_setenvif.c", NULL };

    ap_hook_post_read_request(px_hook_post_request, asz_pre, NULL, APR_HOOK_MIDDLE);
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
