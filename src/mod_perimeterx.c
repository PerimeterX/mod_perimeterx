/*
 * PerimeterX Apache mod
 */
#include <stdio.h>
#include <stdbool.h>

#include <jansson.h>
#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
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
#include <apr_thread_rwlock.h>
#include <apr_uri.h>

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
static const char *DEFAULT_REMOTE_CONFIG_URL = "https://px-conf-mgmt.perimeterx.net/api/v1/enforcer";
static const char *RISK_API = "/api/v2/risk";
static const char *CAPTCHA_API = "/api/v2/risk/captcha";
static const char *TELEMETRY_API = "/api/v2/risk/telemetry";
static const char *ACTIVITIES_API = "/api/v1/collector/s2s";
static const char *HEALTH_CHECK_API = "/api/v1/kpi/status";


static const char *CONTENT_TYPE_JSON = "application/json";
static const char *CONTENT_TYPE_HTML = "text/html";

// constants
static const char *PERIMETERX_MODULE_VERSION = "Apache Module v2.8.0-rc.9";
static const char *SCORE_HEADER_NAME = "X-PX-SCORE";
static const char *VID_HEADER_NAME = "X-PX-VID";
static const char *UUID_HEADER_NAME = "X-PX-UUID";
static const char *ACCEPT_HEADER_NAME = "Accept";
static const char *ACCESS_CONTROL_ALLOW_ORIGIN_HEADER_NAME = "Access-Control-Allow-Origin";
static const char *ORIGIN_HEADER_NAME = "Origin";
static const char *ORIGIN_WILDCARD_VALUE = "*";

static const char *CAPTCHA_COOKIE = "_pxCaptcha";
static const int MAX_CURL_POOL_SIZE = 10000;
static const int ERR_BUF_SIZE = 128;

static const char *ERROR_CONFIG_MISSING = "mod_perimeterx: config structure not allocated";
static const char* MAX_CURL_POOL_SIZE_EXCEEDED = "mod_perimeterx: CurlPoolSize can not exceed 10000";
static const char *INVALID_WORKER_NUMBER_QUEUE_SIZE = "mod_perimeterx: invalid number of background activity workers - must be greater than zero";
static const char *INVALID_ACTIVITY_QUEUE_SIZE = "mod_perimeterx: invalid background activity queue size - must be greater than zero";
static const char *ERROR_BASE_URL_BEFORE_APP_ID = "mod_perimeterx: BaseUrl was set before AppId";

static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";
static const char *ENFORCER_TELEMETRY_ACTIVITY_TYPE = "enforcer_telemetry";
static const char *MONITOR_MODE_BLOCK = "blocking";
static const char *UPDATE_REASON_REMOTE_CONFIG = "remote_config";
static const char *UPDATE_REASON_INITIAL_CONFIG = "initial_config";

static const char *LOGGER_DEBUG_FORMAT = "[PerimeterX - DEBUG][%s] - %s";
static const char *LOGGER_ERROR_FORMAT = "[PerimeterX - ERROR][%s] - %s";


#ifdef DEBUG
extern const char *BLOCK_REASON_STR[];
extern const char *CALL_REASON_STR[];
#endif // DEBUG

/*
 * SSL initialization magic copied from mod_auth_cas
 */
#if defined(OPENSSL_THREADS) && APR_HAS_THREADS

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void px_ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (type < ssl_num_locks) {
        if (mode & CRYPTO_LOCK) {
            apr_thread_mutex_lock(ssl_locks[type]);
        } else {
            apr_thread_mutex_unlock(ssl_locks[type]);
        }
    }
}

#ifdef OPENSSL_NO_THREADID
static unsigned long px_ssl_id_callback(void) {
    return (unsigned long) apr_os_thread_current();
}
#else
static void px_ssl_id_callback(CRYPTO_THREADID *id) {
    CRYPTO_THREADID_set_numeric(id, (unsigned long) apr_os_thread_current());
}
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */


char *create_response(px_config *conf, request_context *ctx) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "create_response: response creation started");

    // support for Access-Control-Allow-Origin headers
    if (conf->origin_wildcard_enabled) {
        apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_ORIGIN_HEADER_NAME,ORIGIN_WILDCARD_VALUE);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "create_response: header Access-Control-Allow-Origin: * set on response");
    } else if (conf->origin_envvar_name) {
        const char *origin_envvar_value = apr_table_get(ctx->r->subprocess_env, conf->origin_envvar_name);
        if (origin_envvar_value != NULL) {
            apr_uri_t origin_envvar_uri;
            apr_status_t origin_envvar_parse_result = apr_uri_parse(ctx->r->pool, origin_envvar_value, &origin_envvar_uri);
            if (origin_envvar_parse_result != 0) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "create_response: Origin header was not a valid URI");
            } else {
                // Unparse to ensure there is a real URI
                const char *unparsed_uri = apr_uri_unparse(ctx->r->pool, &origin_envvar_uri, APR_URI_UNP_OMITPATHINFO);
                if (unparsed_uri != NULL) {
                    if (strlen(unparsed_uri) > 0) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, apr_pstrcat(ctx->r->pool, "create_response: unparsed uri ", unparsed_uri, NULL));
                        apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_ORIGIN_HEADER_NAME, unparsed_uri);
                        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, apr_pstrcat(ctx->r->pool, "create_response: header Access-Control-Allow-Origin: ", origin_envvar_value, " set on response", NULL));

                    } else {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "create_response: invalid URI set in envvar");
                    }
                }
            }
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "create_response: envvar NULL skipped setting Access-Control-Allow-Origin header");
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
    if (!request_valid || conf->send_page_activities) {
        const char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
        char *activity = create_activity(activity_type, conf, ctx);
        if (!activity) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "post_verification: ", activity_type, " create activity failed", NULL));
            return;
        }
        if (conf->background_activity_send) {
            apr_queue_push(conf->activity_queue, activity);
        } else {
            post_request(conf->activities_api_url, activity, conf->api_timeout_ms, conf, ctx->r->server, NULL, NULL);
            free(activity);
        }
    }
}

int px_handle_request(request_rec *r, px_config *conf) {
    // fail open mode
    if (apr_atomic_read32(&conf->px_errors_count) >= conf->px_errors_threshold) {
        return DECLINED;
    }

    // Decline internal redirects and subrequests
    if (r->prev) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Request declined - interal redirect or subrequest");
	    return DECLINED;
    }

    if (!px_should_verify_request(r, conf)) {
        return DECLINED;
    }

    if (conf->skip_mod_by_envvar) {
        const char *skip_px = apr_table_get(r->subprocess_env, "PX_SKIP_MODULE");
        if  (skip_px != NULL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Request will not be verified, module is disabled by EnvIf");
            return DECLINED;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Starting request verification");

    request_context *ctx = create_context(r, conf);
    if (ctx) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Request context created successfully");
        bool request_valid = px_verify_request(ctx, conf);

        // if request is not valid, and monitor mode is on, toggle request_valid and set pass_reason
        if (conf->monitor_mode && !request_valid) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Request marked for simulated block");
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
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Could not create block page with template, passing request");
        }
    }
    r->status = HTTP_OK;
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
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, hc->server, LOGGER_DEBUG_FORMAT, conf->app_id, "health_check: marked to exit");
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

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, hc->server, LOGGER_DEBUG_FORMAT, conf->app_id, "health_check: thread exiting");

    curl_easy_cleanup(curl);
    apr_thread_exit(thd, 0);
    return NULL;
}

static void *APR_THREAD_FUNC background_activity_consumer(apr_thread_t *thd, void *data) {
    background_thread_data *consumer_data = (background_thread_data*)data;
    px_config *conf = consumer_data->config;
    CURL *curl = curl_easy_init();

    void *v;
    if (!curl) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, consumer_data->server, LOGGER_DEBUG_FORMAT, conf->app_id, "could not create curl handle, thread will not run to consume messages");
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
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, consumer_data->server, LOGGER_DEBUG_FORMAT, conf->app_id, "activity consumer thread exited");
    apr_thread_exit(thd, 0);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, consumer_data->server, LOGGER_DEBUG_FORMAT, conf->app_id, "Sending activity completed");
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "error while init health_check thread cond");
        return rv;
    }

    rv = apr_thread_create(&cfg->health_check_thread, NULL, health_check, (void*) hc_data, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "error while init health_check thread create");
        return rv;
    }

    rv = apr_thread_mutex_create(&cfg->health_check_cond_mutex, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "error while creating health_check thread mutex");
        return rv;
    }

    return rv;
}

void telemetry_activity_send(server_rec *s, px_config *cfg, const char *update_reason) {
    const char *activity_type = ENFORCER_TELEMETRY_ACTIVITY_TYPE;
    char *activity = config_to_json_string(cfg, update_reason);
    if (!activity) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "[%s]: telemetry_activity_send: create telemetry activity failed", cfg->app_id);
        return;
    }
    post_request(cfg->telemetry_api_url, activity, cfg->api_timeout_ms, cfg, s, NULL, NULL);
    free(activity);
}

static apr_status_t background_activity_send_init(apr_pool_t *pool, server_rec *s, px_config *cfg) {
    apr_status_t rv;

    rv = apr_queue_create(&cfg->activity_queue, cfg->background_activity_queue_size, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "failed to initialize background activity queue");
        return rv;
    }

    background_thread_data *consumer_data = apr_palloc(s->process->pool, sizeof(background_thread_data));
    consumer_data->server = s;
    consumer_data->config = cfg;

    rv = apr_thread_pool_create(&cfg->activity_thread_pool, 0, cfg->background_activity_workers, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "failed to initialize background activity thread pool");
        return rv;
    }

    for (unsigned int i = 0; i < cfg->background_activity_workers; ++i) {
        rv = apr_thread_pool_push(cfg->activity_thread_pool, background_activity_consumer, consumer_data, 0, NULL);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "failed to push background activity consumer");
            return rv;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "finished init background activities");
    return rv;
}

static void *APR_THREAD_FUNC background_remote_config(apr_thread_t *thd, void *data){
    background_thread_data *remote_conf_data = (background_thread_data*) data;
    if (!remote_conf_data){
        return NULL;
    }
    px_config *conf = remote_conf_data->config;

    CURL *curl = curl_easy_init();

    if (!curl) {
        ap_log_error(APLOG_MARK, LOG_ERR, 0, remote_conf_data->server, "[%s] background_remote_config: could not create curl handle, thread will not run to consume messages", conf->app_id);
        return NULL;
    }

    apr_thread_mutex_lock(conf->remote_config_cond_mutex);
    while (!conf->rc_should_exit_thread) {
        apr_pool_t *rc_pool = NULL;
        apr_pool_create(&rc_pool, NULL);

        const char *checksum = NULL;
        if (conf->remote_conf && conf->remote_conf->checksum){
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, remote_conf_data->server, "[%s]: adding checksum %s", conf->app_id, conf->remote_conf->checksum);
            checksum = conf->remote_conf->checksum;
        }

        char *url = apr_pstrcat(rc_pool, conf->remote_config_url, "?checksum=", checksum, NULL) ;

        char *remote_config_str;
        CURLcode status = get_request_helper(curl, url, conf->api_timeout_ms, conf, remote_conf_data->server, &remote_config_str);

        if (status == CURLE_OK) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, remote_conf_data->server, "[%s]: found new configurations", conf->app_id);
            remote_config *remote_conf = parse_remote_config(rc_pool, remote_config_str, conf, remote_conf_data->server);
            if (remote_conf){
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, remote_conf_data->server, "[%s]: parsed remote config succesfully", conf->app_id);
                // Lock mutex for incoming requests
                apr_thread_rwlock_wrlock(conf->remote_config_rw_mutex);
                // ---------------------------------------------------
                // all thread safe operations should be here
                conf->remote_conf = remote_conf;
                conf->module_enabled = conf->remote_conf->module_enabled;
                conf->payload_key = conf->remote_conf->cookie_key;
                conf->blocking_score = conf->remote_conf->blocking_score;
                conf->app_id = conf->remote_conf->app_id;
                conf->monitor_mode = !strcmp(conf->remote_conf->module_mode, MONITOR_MODE_BLOCK) ? false : true;
                conf->api_timeout_ms = conf->remote_conf->risk_timeout;
                conf->ip_header_keys = conf->remote_conf->ip_header_keys;
                conf->sensitive_header_keys = conf->remote_conf->sensitive_header_keys;
                // ---------------------------------------------------
                apr_thread_rwlock_unlock(conf->remote_config_rw_mutex);
                telemetry_activity_send(remote_conf_data->server, conf, UPDATE_REASON_REMOTE_CONFIG);
            }
        } else if (!conf->remote_conf || !conf->remote_conf->checksum) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, remote_conf_data->server, "[%s]: remote configurations: failed to get configuration and no initial remote configuration, disabling module until new config will be found", conf->app_id);
            apr_thread_rwlock_wrlock(conf->remote_config_rw_mutex);
            // all thread safe operations should be here
            conf->module_enabled = false;
            // all thread safe operations should be here
            apr_thread_rwlock_unlock(conf->remote_config_rw_mutex);

        }
        // clear the pool;
        apr_pool_destroy(rc_pool);
        apr_thread_cond_timedwait(conf->remote_config_cond, conf->remote_config_cond_mutex, conf->remote_config_interval_ms);
    }
    //unlock mutex for incoming request
    apr_thread_mutex_unlock(conf->remote_config_cond_mutex);
    // after exit
    curl_easy_cleanup(curl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, remote_conf_data->server, "[%s]: remote configurations thread exited", conf->app_id);
    apr_thread_exit(thd, 0);
    return NULL;
}

// init remote configuration thread
static apr_status_t remote_configuration_init(apr_pool_t *pool, server_rec *s, px_config *cfg) {
    apr_status_t rv;
    background_thread_data *remote_conf_data = apr_palloc(s->process->pool, sizeof(background_thread_data));
    remote_conf_data->server = s;
    remote_conf_data->config = cfg;

    rv = apr_thread_rwlock_create(&cfg->remote_config_rw_mutex, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while creating remote_config read/write thread mutex");
        return rv;
    }

    rv = apr_thread_mutex_create(&cfg->remote_config_cond_mutex, 0, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while creating remote config cond mutex");
        return rv;
    }


    rv = apr_thread_cond_create(&cfg->remote_config_cond, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while init remote_config thread cond");
        return rv;
    }

    rv = apr_thread_create(&cfg->remote_config_thread, NULL, background_remote_config, (void*) remote_conf_data, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "error while init remote_config thread create");
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "finished init remote config thread");
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

    if (cfg->remote_config_enabled) {
        cfg->rc_should_exit_thread = true;
        apr_thread_cond_signal(cfg->remote_config_cond);
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
    apr_status_t rv = APR_SUCCESS;
    // init each virtual host
    for (server_rec *vs = s; vs; vs = vs->next) {
        px_config *cfg = ap_get_module_config(vs->module_config, &perimeterx_module);
        if (!cfg || !cfg->module_enabled) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, LOGGER_DEBUG_FORMAT, cfg->app_id, "Request will not be verified, module is disabled");
            continue;
        }
        // initialize the PerimeterX needed pools and background workers if the PerimeterX module is enabled

        rv = apr_pool_create(&cfg->pool, vs->process->pool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "px_child_setup: error while trying to initialize apr_pool for configuration");
            return rv;
        }

        cfg->curl_pool = curl_pool_create(cfg->pool, cfg->curl_pool_size);

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "px_hook_child_init: start init for telemetry_activity_send");
        telemetry_activity_send(vs, cfg, UPDATE_REASON_INITIAL_CONFIG);

        if (cfg->background_activity_send) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, LOGGER_DEBUG_FORMAT, cfg->app_id, "px_child_setup: start init for background_activity_send");

            rv = background_activity_send_init(cfg->pool, vs, cfg);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "px_child_setup: error while trying to init background_activity_consumer");
                return rv;
            }
        }
      
        if (cfg->remote_config_enabled) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "px_hook_child_init: setting up remote config thread");
            rv = remote_configuration_init(cfg->pool, vs, cfg);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "px_hook_child_init: error while trying to init remote_config_init");
            }
        }

        if (cfg->px_health_check) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, LOGGER_DEBUG_FORMAT, cfg->app_id, "px_child_setup: setting up health_check thread");
            rv = create_health_check(cfg->pool, vs, cfg);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, LOGGER_ERROR_FORMAT, cfg->app_id, "px_child_setup: error while trying to init health_check_thread");
                return rv;
            }
        }
    }
    apr_pool_cleanup_register(p, s, px_child_exit, apr_pool_cleanup_null);
    return rv;
}

static void px_hook_child_init(apr_pool_t *p, server_rec *s) {
    apr_status_t rv = px_child_setup(p, s);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "child init failed!");
    }
}

static apr_status_t px_cleanup_pre_config(void *data) {
#if (defined (OPENSSL_THREADS) && APR_HAS_THREADS)
    if (CRYPTO_get_locking_callback() == px_ssl_locking_callback) {
        CRYPTO_set_locking_callback(NULL);
    }
#ifdef OPENSSL_NO_THREADID
    if (CRYPTO_get_id_callback() == px_ssl_id_callback) {
        CRYPTO_set_id_callback(NULL);
    }
#else
    if (CRYPTO_THREADID_get_callback() == px_ssl_id_callback) {
        CRYPTO_THREADID_set_callback(NULL);
    }
#endif /* OPENSSL_NO_THREADID */
#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */

    curl_global_cleanup();
    EVP_cleanup();

    CRYPTO_cleanup_all_ex_data();

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
    ERR_remove_thread_state(NULL);
#else
    ERR_remove_state(0);
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x00090805f)
    ERR_free_strings();
#endif
    return APR_SUCCESS;
}

static int px_hook_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp) {
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
    (void)CRYPTO_malloc_init();
#else
    OPENSSL_malloc_init();
#endif
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_library_init();

    OpenSSL_add_all_algorithms();
    ERR_clear_error();
    curl_global_init(CURL_GLOBAL_ALL);
    /*OpenSSL_add_all_digests();*/

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS)
    ssl_num_locks = CRYPTO_num_locks();
    ssl_locks = apr_pcalloc(p, ssl_num_locks * sizeof(*ssl_locks));

    for (int i = 0; i < ssl_num_locks; i++) {
        apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT, p);
    }
#ifdef OPENSSL_NO_THREADID
    if (CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
        CRYPTO_set_locking_callback(px_ssl_locking_callback);
        CRYPTO_set_id_callback(px_ssl_id_callback);
    }
#else
    if (CRYPTO_get_locking_callback() == NULL && CRYPTO_THREADID_get_callback() == NULL) {
        CRYPTO_set_locking_callback(px_ssl_locking_callback);
        CRYPTO_THREADID_set_callback(px_ssl_id_callback);
    }
#endif /* OPENSSL_NO_THREADID */
#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */


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
    conf->telemetry_api_url = apr_pstrcat(cmd->pool, conf->base_url, TELEMETRY_API, NULL);
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

static const char* set_origin_envvar(cmd_parms *cmd, void *config, const char *origin_envvar_name) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->origin_envvar_name = origin_envvar_name;
    return NULL;
}


static const char *enable_origin_wildcard(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->origin_wildcard_enabled = arg ? true : false;
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

static const char *set_remote_configuration(cmd_parms *cmd, void *config, int arg) {

    px_config *conf = get_config(cmd, config);
    if (!conf) {

        return ERROR_CONFIG_MISSING;
    }
    conf->remote_config_enabled = arg ? true : false;
    return NULL;
}

static const char* set_remote_config_url(cmd_parms *cmd, void *config, const char *remote_config_url) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    conf->remote_config_url = remote_config_url;
    return NULL;
}

static const char *set_remote_config_interval_ms(cmd_parms *cmd, void *config, const char *interval_ms) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->remote_config_interval_ms = atoi(interval_ms) * 1000;
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

static const char *set_sensitive_headers(cmd_parms *cmd, void *config, const char *sensitive_header) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->sensitive_header_keys);
    *entry = sensitive_header;
    return NULL;
}

static void acquire_read_lock(px_config *conf){
    if (conf->remote_config_enabled){
        apr_thread_rwlock_rdlock(conf->remote_config_rw_mutex);
    }
}

static void release_read_lock(px_config *conf){
    if (conf->remote_config_enabled){
        apr_thread_rwlock_unlock(conf->remote_config_rw_mutex);
    }
}

static int px_hook_post_request(request_rec *r) {
    px_config *conf = ap_get_module_config(r->server->module_config, &perimeterx_module);
    acquire_read_lock(conf);
    int rv = px_handle_request(r, conf);
    release_read_lock(conf);
    return rv;
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
        conf->telemetry_api_url = apr_pstrcat(p, conf->base_url, TELEMETRY_API, NULL);
        conf->auth_token = "";
        conf->auth_header = "";
        conf->routes_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->useragents_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->custom_file_ext_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->ip_header_keys = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_header_keys = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_routes = apr_array_make(p, 0, sizeof(char*));
        conf->enabled_hostnames = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_routes_prefix = apr_array_make(p, 0, sizeof(char*));
        conf->background_activity_send = false;
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
        conf->origin_envvar_name  = NULL;
        conf->origin_wildcard_enabled = false;
        conf->captcha_type = CAPTCHA_TYPE_RECAPTCHA;
        conf->monitor_mode = false;
        conf->enable_token_via_header = true;
        conf->remote_config_enabled = false;
        conf->remote_config_url = DEFAULT_REMOTE_CONFIG_URL;
        conf->remote_config_interval_ms = 5000000L;
    }
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
            set_payload_key,
            NULL,
            OR_ALL,
            "Cookie decryption key"),
    AP_INIT_TAKE1("AuthToken",
            set_auth_token,
            NULL,
            OR_ALL,
            "Risk API auth token"),
    AP_INIT_TAKE1("CustomLogo",
            set_custom_logo,
            NULL,
            OR_ALL,
            "Set custom logo on block page"),
    AP_INIT_TAKE1("CSSRef",
            set_css_ref,
            NULL,
            OR_ALL,
            "Set custom css on block page"),
    AP_INIT_TAKE1("JSRef",
            set_js_ref,
            NULL,
            OR_ALL,
            "Set custom javascript on block page"),
    AP_INIT_TAKE1("BlockingScore",
            set_blocking_score,
            NULL,
            OR_ALL,
            "Request with score equal or greater than this will be blocked"),
    AP_INIT_TAKE1("APITimeout",
            set_api_timeout,
            NULL,
            OR_ALL,
            "Set timeout for risk API request in seconds"),
    AP_INIT_TAKE1("APITimeoutMS",
            set_api_timeout_ms,
            NULL,
            OR_ALL,
            "Set timeout for risk API request in milliseconds"),
    AP_INIT_TAKE1("CaptchaTimeout",
            set_captcha_timeout,
            NULL,
            OR_ALL,
            "Set timeout for captcha API request in milliseconds"),
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
    AP_INIT_FLAG("DisableModByEnvvar",
            set_skip_mod_by_envvar,
            NULL,
            OR_ALL,
            "Allow to disable PerimeterX module by environment variable"),
    AP_INIT_TAKE1("BlockPageURL",
            set_block_page_url,
            NULL,
            OR_ALL,
            "URL for custom blocking page"),
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
    AP_INIT_ITERATE("SensitiveRoutes",
            add_sensitive_route,
            NULL,
            OR_ALL,
            "Sensitive routes - for each of this uris the module will do a server-to-server call even if a good cookie is on the request"),
    AP_INIT_ITERATE("SensitiveRoutesPrefix",
            add_sensitive_route_prefix,
            NULL,
            OR_ALL,
            "Sensitive routes by prefix - for each of this uris prefix the module will do a server-to-server call even if a good cookie is on the request"),
    AP_INIT_ITERATE("EnableBlockingByHostname",
            add_host_to_list,
            NULL,
            OR_ALL,
            "Enable blocking by hostname - list of hostnames on which PX module will be enabled for"),
    AP_INIT_FLAG("BackgroundActivitySend",
            set_background_activity_send,
            NULL,
            OR_ALL,
            "Use background workers to send activities"),
    AP_INIT_TAKE1("BackgroundActivityWorkers",
            set_background_activity_workers,
            NULL,
            OR_ALL,
            "Number of background workers to send activities"),
    AP_INIT_TAKE1("BackgroundActivityQueueSize",
            set_background_activity_queue_size,
            NULL,
            OR_ALL,
            "Queue size for background activity send"),
    /* This should be removed in later version, replaced by PXHealthCheck */
    AP_INIT_FLAG("PXServiceMonitor",
            set_px_health_check,
            NULL,
            OR_ALL,
            "Background monitoring on PerimeterX service"),
    AP_INIT_FLAG("PXHealthCheck",
            set_px_health_check,
            NULL,
            OR_ALL,
            "Background monitoring on PerimeterX service"),
    AP_INIT_TAKE1("MaxPXErrorsThreshold",
            set_max_px_errors_threshold,
            NULL,
            OR_ALL,
            "Number of errors from px servers before running in fail open mode"),
    AP_INIT_TAKE1("PXErrorsCountInterval",
            set_px_errors_count_interval,
            NULL,
            OR_ALL,
            "Time in milliseconds until we set the px server errors count back to zero"),
    AP_INIT_TAKE1("ProxyURL",
            set_proxy_url,
            NULL,
            OR_ALL,
            "Proxy URL for outgoing PerimeterX service API"),
    AP_INIT_FLAG("ScoreHeader",
            set_score_header,
            NULL,
            OR_ALL,
            "Allow module to place request score on response header"),
    AP_INIT_TAKE1("ScoreHeaderName",
            set_score_header_name,
            NULL,
            OR_ALL,
            "Set the name of the score header"),
    AP_INIT_FLAG("EnableTokenViaHeader",
            enable_token_via_header,
            NULL,
            OR_ALL,
            "Enable header based token send"),
    AP_INIT_FLAG("VidHeader",
            enable_vid_header,
            NULL,
            OR_ALL,
            "Enable module to place vid on response header"),
    AP_INIT_TAKE1("VidHeaderName",
            set_vid_header_name,
            NULL,
            OR_ALL,
            "Sets the name of vid response header"),
    AP_INIT_TAKE1("UuidHeaderName",
            set_uuid_header_name,
            NULL,
            OR_ALL,
            "Sets the name of uuid response header"),
    AP_INIT_FLAG("UuidHeader",
            enable_uuid_header,
            NULL,
            OR_ALL,
            "Enable module to place uuid on response header"),
    AP_INIT_FLAG("EnableJsonResponse",
            enable_json_response,
            NULL,
            OR_ALL,
            "Enable module to return a json response"),
    AP_INIT_TAKE1("PXApplyAccessControlAllowOriginByEnvVar",
            set_origin_envvar,
            NULL,
            OR_ALL,
            "Enable Access-Control-Allow-Origin: <origin> from defined environmental variable on blocked responses"),
    AP_INIT_FLAG("EnableAccessControlAllowOriginWildcard",
            enable_origin_wildcard,
            NULL,
            OR_ALL,
            "Enable Access-Control-Allow-Origin: * header on blocked responses"),
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
    AP_INIT_FLAG("EnableRemoteConfiguration",
            set_remote_configuration,
            NULL,
            OR_ALL,
            "Toggle remote configuration on/off"),
    AP_INIT_TAKE1("RemoteConfigurationUrl",
            set_remote_config_url,
            NULL,
            OR_ALL,
            "Sets the URL for the remote configurations"),
      AP_INIT_TAKE1("RemoteConfigurationIntervalMS",
            set_remote_config_interval_ms,
            NULL,
            OR_ALL,
            "Set timeout for risk API request in milliseconds"),
      AP_INIT_ITERATE("SensitiveHeader",
            set_sensitive_headers,
            NULL,
            OR_ALL,
            "Sets a value for a sensitive header which will be filtered and not be reported back"),
    { NULL }
};

static void perimeterx_register_hooks(apr_pool_t *pool) {
    static const char *const asz_pre[] = { "mod_setenvif.c", NULL };

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
