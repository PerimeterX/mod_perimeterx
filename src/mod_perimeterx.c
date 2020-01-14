/*
 * PerimeterX Apache mod
 */
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>

#include <jansson.h>
#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <ap_config.h>
#include <ap_provider.h>
#include <apr_strings.h>
#include <apr_atomic.h>
#include <apr_portable.h>
#include <apr_signal.h>
#include <apr_base64.h>
#include <apr_time.h>
#include <apr_uri.h>

#include "px_utils.h"
#include "px_types.h"
#include "px_template.h"
#include "px_enforcer.h"
#include "px_json.h"
#include "px_client.h"
#include "background_activity.h"

module AP_MODULE_DECLARE_DATA perimeterx_module;

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *DEFAULT_BASE_URL = "https://sapi-%s.perimeterx.net";
static const char *RISK_API = "/api/v2/risk";
static const char *CAPTCHA_API = "/api/v2/risk/captcha";
static const char *ACTIVITIES_API = "/api/v1/collector/s2s";
static const char *HEALTH_CHECK_API = "/api/v1/kpi/status";
static const char *CONFIGURATION_SERVER_URL = "https://px-conf.perimeterx.net";
static const char *REMOTE_CONFIGURATIONS_PATH = "/api/v1/enforcer";
static const char *TELEMETRY_API = "/api/v2/risk/telemetry";

static const char *CONTENT_TYPE_JSON = "application/json";
static const char *CONTENT_TYPE_HTML = "text/html";

// constants
static const char *PERIMETERX_MODULE_VERSION = "Apache Module v3.1.1";
static const char *SCORE_HEADER_NAME = "X-PX-SCORE";
static const char *VID_HEADER_NAME = "X-PX-VID";
static const char *UUID_HEADER_NAME = "X-PX-UUID";
static const char *ACCEPT_HEADER_NAME = "Accept";
static const char *ACCESS_CONTROL_ALLOW_ORIGIN_HEADER_NAME = "Access-Control-Allow-Origin";
static const char *ORIGIN_WILDCARD_VALUE = "*";
static const char *HEADER_DELIMETER = ":";

static const int MAX_CURL_POOL_SIZE = 10000;
static const int ERR_BUF_SIZE = 128;

static const char *ERROR_CONFIG_MISSING = "mod_perimeterx: config structure not allocated";
static const char* MAX_CURL_POOL_SIZE_EXCEEDED = "mod_perimeterx: CurlPoolSize can not exceed 10000";
static const char *INVALID_WORKER_NUMBER_QUEUE_SIZE = "mod_perimeterx: invalid number of background activity workers - must be greater than zero";
static const char *INVALID_ACTIVITY_QUEUE_SIZE = "mod_perimeterx: invalid background activity queue size - must be greater than zero";
static const char *ERROR_BASE_URL_BEFORE_APP_ID = "mod_perimeterx: BaseUrl was set before AppId";
static const char *ERROR_SHORT_APP_ID = "mod_perimeterx: AppId must be longer than 2 chars";

static const char *BLOCKED_ACTIVITY_TYPE = "block";
static const char *PAGE_REQUESTED_ACTIVITY_TYPE = "page_requested";
static const char *UPDATE_REASON_REMOTE_CONFIG = "remote_config";
static const char *UPDATE_REASON_INITIAL_CONFIG = "initial_config";

static void set_app_id_helper(apr_pool_t *pool, px_config *conf, const char *app_id);

#ifdef DEBUG
extern const char *BLOCK_REASON_STR[];
extern const char *CALL_REASON_STR[];
#endif // DEBUG

/*
 * SSL initialization magic copied from mod_auth_cas
 */
#if defined(OPENSSL_THREADS) && APR_HAS_THREADS && (OPENSSL_VERSION_NUMBER < 0x10100000L)

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void px_ssl_locking_callback(int mode, int type, UNUSED const char *file, UNUSED int line) {
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


static char *create_response(px_config *conf, request_context *ctx) {
    px_log_debug("response creation started");

    // support for Access-Control-Allow-Origin headers
    if (conf->origin_wildcard_enabled) {
        apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_ORIGIN_HEADER_NAME,ORIGIN_WILDCARD_VALUE);
        px_log_debug("header Access-Control-Allow-Origin: * set on response");
    } else if (conf->origin_envvar_name) {
        const char *origin_envvar_value = apr_table_get(ctx->r->subprocess_env, conf->origin_envvar_name);
        if (origin_envvar_value != NULL) {
            apr_uri_t origin_envvar_uri;
            apr_status_t origin_envvar_parse_result = apr_uri_parse(ctx->r->pool, origin_envvar_value, &origin_envvar_uri);
            if (origin_envvar_parse_result != 0) {
                px_log_debug("Origin header was not a valid URI");
            } else {
                // Unparse to ensure there is a real URI
                const char *unparsed_uri = apr_uri_unparse(ctx->r->pool, &origin_envvar_uri, APR_URI_UNP_OMITPATHINFO);
                if (unparsed_uri != NULL) {
                    if (strlen(unparsed_uri) > 0) {
                        px_log_debug_fmt("unparsed uri %s", unparsed_uri);
                        apr_table_set(ctx->r->headers_out, ACCESS_CONTROL_ALLOW_ORIGIN_HEADER_NAME, unparsed_uri);
                        px_log_debug_fmt("header Access-Control-Allow-Origin: %s set on response", origin_envvar_value);
                    } else {
                        px_log_debug("invalid URI set in envvar");
                    }
                }
            }
        } else {
            px_log_debug("envvar NULL skipped setting Access-Control-Allow-Origin header");
        }
    }

    if (ctx->token_origin == TOKEN_ORIGIN_HEADER) {
        ctx->response_application_json = true;
    } else if (conf->json_response_enabled) {
        const char *accept_header = apr_table_get(ctx->r->headers_in, ACCEPT_HEADER_NAME);
        bool match = accept_header && strstr(accept_header, CONTENT_TYPE_JSON);
        if (match) {
            ctx->response_application_json = true;
            return create_json_response(ctx);
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
        apr_base64_encode(encoded_html, html, html_size);
        free(html);
        if (!encoded_html) {
            return NULL;
        }
        return create_mobile_response(ctx, encoded_html);
    }
    return html;
}

static void post_verification(request_context *ctx, bool request_valid) {
    px_config *conf = ctx->conf;
    if (!request_valid || conf->send_page_activities) {
        const char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
        char *activity = create_activity(activity_type, ctx);
        if (!activity) {
            px_log_debug_fmt("%s create activity failed", activity_type);
            return;
        }

        if (conf->background_activity_send) {
            apr_queue_push(conf->background_activity_queue, activity);
            // notify background activity thread that we have a new task
            background_activity_wakeup(conf->background_activity_wakeup_fds);
        } else {
            post_request(conf->activities_api_url, activity, conf->connect_timeout_ms, conf->api_timeout_ms, conf, ctx, NULL, NULL);
            free(activity);
        }
    }
}

static void redirect_copy_headers_out(request_rec *r, const redirect_response *res) {
    apr_array_header_t *response_headers = res->response_headers;
    if (response_headers && response_headers->nelts > 0) {
        apr_table_clear(r->headers_out);
        for (int i = 0; i < response_headers->nelts; i++) {
            char *header = APR_ARRAY_IDX(response_headers, i, char*);
            char *value = NULL;
            char *key = apr_strtok(header, HEADER_DELIMETER, &value);
            apr_table_set(r->headers_out, key, &value[1]);
        }
    } else if (res->predefined && res->response_content_type) {
        apr_table_set(r->headers_out, "Content-Type", res->response_content_type);
    }
}

static int px_handle_request(request_rec *r, px_config *conf) {
    // Decline if module is disabled or not properly configured
    if (!conf || !conf->module_enabled || !conf->app_id) {
        return DECLINED;
    }

    // fail open mode
    if (apr_atomic_read32(&conf->px_errors_count) >= conf->px_errors_threshold) {
        return DECLINED;
    }

    // Decline internal redirects and subrequests
    if (r->prev) {
        px_log_debug("Request declined - internal redirect or subrequest");
        return DECLINED;
    }

    const redirect_response *redirect_res = NULL;
    // Redirect client
    if (conf->client_path_prefix && strncmp(conf->client_path_prefix, r->parsed_uri.path, strlen(conf->client_path_prefix)) == 0) {
        redirect_res = redirect_client(r, conf);
        r->status = redirect_res->http_code;
        redirect_copy_headers_out(r, redirect_res);
        if (redirect_res->content_size) {
            ap_rwrite(redirect_res->content, redirect_res->content_size, r);
        }
        return DONE;
    }

    // Redirect XHR
    if (conf->xhr_path_prefix && strncmp(conf->xhr_path_prefix, r->parsed_uri.path, strlen(conf->xhr_path_prefix)) == 0) {
        redirect_res = redirect_xhr(r, conf);
        r->status = redirect_res->http_code;
        redirect_copy_headers_out(r, redirect_res);
        if (redirect_res->content_size) {
            ap_rwrite(redirect_res->content, redirect_res->content_size, r);
        }
        return DONE;
    }

    if (!px_should_verify_request(r, conf)) {
        return DECLINED;
    }

    if (conf->skip_mod_by_envvar) {
        const char *skip_px = apr_table_get(r->subprocess_env, "PX_SKIP_MODULE");
        if  (skip_px != NULL) {
            px_log_debug("Request will not be verified, module is disabled by EnvIf");
            return DECLINED;
        }
    }

    px_log_debug("Starting request verification");

    request_context *ctx = create_context(r, conf);
    if (ctx) {
        px_log_debug("Request context created successfully");
        bool request_valid = px_verify_request(ctx);

        // if request is not valid, and monitor mode is on, toggle request_valid and set pass_reason
        if (conf->monitor_mode && !request_valid) {
            px_log_debug("Request marked for simulated block");
            ctx->pass_reason = PASS_REASON_MONITOR_MODE;
            request_valid = true;
        }
        post_verification(ctx, request_valid);
#if DEBUG
        const char *PX_AUT_HEADER_KEY = getenv("PX_AUT_HEADER_KEY");
        const char *PX_AUT_HEADER_VALUE = getenv("PX_AUT_HEADER_VALUE");
        if (PX_AUT_HEADER_KEY && PX_AUT_HEADER_VALUE) {
            char *aut_test_header = apr_pstrdup(r->pool, (char *) apr_table_get(r->headers_in, PX_AUT_HEADER_KEY));
            if (aut_test_header && strcmp(aut_test_header, PX_AUT_HEADER_VALUE) == 0) {
                const char *ctx_str = json_context(ctx);
                ap_set_content_type(r, CONTENT_TYPE_JSON);
                ap_rprintf(r, "%s", ctx_str);
                free((void*)ctx_str);
                return DONE;
            }
        }
#endif

        if (conf->score_header_enabled) {
            const char *score_str = apr_itoa(r->pool, ctx->score);
            apr_table_set(r->headers_in, conf->score_header_name, score_str);
        }

        if (!request_valid && ctx->block_enabled) {
            // redirecting requests to custom block page if exists
            // do not send block_page for mobile requests
            if (conf->block_page_url && ctx->token_origin != TOKEN_ORIGIN_HEADER) {
                const char *url_arg = r->args ? apr_pstrcat(r->pool, r->uri, "?", r->args, NULL) : r->uri;
                const char *url = pescape_urlencoded(r->pool, url_arg);
                const char *redirect_url = apr_pstrcat(r->pool, conf->block_page_url, "?url=", url, "&uuid=", ctx->uuid, "&vid=", ctx->vid,  NULL);
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
            px_log_debug("Could not create block page with template, passing request");
        }
    }
    r->status = HTTP_OK;
    return OK;
}

// Background thread that wakes up after reacing X timeoutes in interval length Y and checks when service is available again
static void *APR_THREAD_FUNC health_check(apr_thread_t *thd, void *data) {
    thread_data *hc = (thread_data*) data;
    px_config *conf = hc->conf;
    apr_pool_t *pool;
    apr_status_t rv;

    // thread-owned pool
    rv = apr_pool_create(&pool, NULL);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, hc->server, "error while trying to initialize apr_pool");
        return NULL;
    }

    const char *health_check_url = apr_pstrcat(pool, conf->base_url, HEALTH_CHECK_API, NULL);
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
            px_log_debug_thd("marked to exit");
            break;
        }

        // do health check until success
        res = CURLE_AGAIN;
        while (!conf->should_exit_thread && res != CURLE_OK) {
            curl_easy_setopt(curl, CURLOPT_URL, health_check_url);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, conf->connect_timeout_ms);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, conf->api_timeout_ms);
            res = curl_easy_perform(curl);
            if (res != CURLE_OK && res != CURLE_OPERATION_TIMEDOUT) {
                apr_sleep(1000); // TODO(barak): should be configured with nice default
            }
        }
        apr_atomic_set32(&conf->px_errors_count, 0);
    }

    px_log_debug_thd("thread exiting");

    curl_easy_cleanup(curl);
    apr_thread_exit(thd, 0);
    return NULL;
}

static void telemetry_activity_send(CURL *telemetry_curl, server_rec *s, px_config *conf, const char *update_reason) {
    char *activity = config_to_json_string(conf, update_reason);
    if (!activity) {
        px_log_error("create telemetry activity failed");
        return;
    }
    post_request_helper(telemetry_curl, conf->telemetry_api_url, activity, conf->api_timeout_ms, conf->api_timeout_ms, conf, s, NULL);
    free(activity);
}

static void update_debug_mode(px_config *conf, int px_debug) {

    // disabling previously enabled debugMode
    if (conf->px_debug && !px_debug) {
        px_log_debug("disabling debug logging");
        conf->px_debug = px_debug;
        conf->log_level_debug = APLOG_DEBUG;
        return;
    }

    // update log_level_debug
    if (px_debug) {
        if (conf->server && !APLOGdebug(conf->server)) {
            conf->log_level_debug = conf->log_level_err;
        } else {
            conf->log_level_debug = APLOG_DEBUG;
        }
    } else {
        conf->log_level_debug = APLOG_DEBUG;
    }

    // no changes
    if (conf->px_debug == px_debug) {
        return;
    }

    // enabling debugMode
    conf->px_debug = px_debug;
    px_log_debug("enabling debug logging");
}

// periodically check for remote configuration changes
static void *APR_THREAD_FUNC remote_config(apr_thread_t *thd, void *data) {
    thread_data *th_data = (thread_data*) data;
    px_config *conf = th_data->conf;
    bool startup = true;

    apr_pool_t *pool;
    apr_status_t rv;
    rv = apr_pool_create(&pool, conf->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, th_data->server, "error while trying to initialize apr_pool");
        return NULL;
    }

    CURL *curl = curl_easy_init();
    CURL *telemetry_curl = curl_easy_init();
    CURLcode res;
    long status_code;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, conf->auth_header);
    headers = curl_slist_append(headers, CONTENT_TYPE_JSON);

    while (!conf->should_exit_thread) {
        char errbuf[CURL_ERROR_SIZE];
        struct response_t response;
        const char *url;

        // immediately request the remote config upon startup
        if (!startup) {
            // Sleep for the specified number of micro-seconds
            apr_sleep(conf->remote_config_interval_ms);
        } else {
            startup = false;
        }

        response.data = apr_pcalloc(pool, 1);
        response.size = 0;
        response.server = th_data->server;
        response.pool = pool;

        if (conf->checksum) {
            url = apr_psprintf(pool, "%s?checksum=%s", conf->remote_config_url, conf->checksum);
        } else {
            url = conf->remote_config_url;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, conf->connect_timeout_ms);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, conf->api_timeout_ms);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_pool_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
        if (conf->proxy_url) {
            curl_easy_setopt(curl, CURLOPT_PROXY, conf->proxy_url);
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            px_log_error_thd_fmt("request failed: %s (%d)", errbuf, res);
            continue;
        }

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (status_code == 204) {
            // px_log_debug_thd("Configuration was not changed");
            continue;
        }

        if (status_code != HTTP_OK) {
            px_log_error_thd_fmt("request failed: %s (%ld)", errbuf, status_code);
            continue;
        }

        json_error_t j_error;
        json_t *j = json_loads(response.data, 0, &j_error);
        if (!j) {
            px_log_error_thd_fmt("failed to parse json: %s", j_error.text);
            continue;
        }

        // parse JSON
        const char *checksum_tmp = NULL;
        int px_enabled = 1;
        const char *cookie_secret = NULL;
        const char *px_appId = NULL;
        int blocking_score = 0;
        int px_debug = 0;
        const char *module_mode = NULL;
        int connect_timeout = 0;
        int api_timeout = 0;
        int first_party_enabled = 0;
        int reverse_xhr_enabled = 0;
        if (json_unpack_ex(j, &j_error, 0, "{s:b, s:s, s:i, s:s, s:s, s:i, s:i, s:b, s:s, s:b, s:b}",
                "moduleEnabled", &px_enabled,
                "cookieKey", &cookie_secret,
                "blockingScore", &blocking_score,
                "appId", &px_appId,
                "moduleMode", &module_mode,

                "connectTimeout", &connect_timeout,
                "riskTimeout", &api_timeout,

                "debugMode", &px_debug,
                "checksum", &checksum_tmp,
                "firstPartyEnabled", &first_party_enabled,
                "firstPartyXhrEnabled", &reverse_xhr_enabled)) {
            px_log_error_thd_fmt("failed to parse json response: %s\n", j_error.text);
            json_decref(j);
            continue;
        }

        px_log_debug_thd_fmt("applying new configuration (module_enabled: %d)", px_enabled);

        // all good, acquire rw lock and update configuration data
        // NOTE: do not call px_log functions while in locked state
        apr_thread_rwlock_wrlock(conf->remote_config_lock);

        conf->module_enabled = px_enabled;
        conf->payload_key = apr_pstrdup(pool, cookie_secret);
        conf->blocking_score = blocking_score;
        set_app_id_helper(pool, conf, apr_pstrdup(pool, px_appId));
        if (module_mode) {
            conf->monitor_mode = strcmp(module_mode, "monitoring") == 0;
        }
        // it comes in milliseconds
        conf->connect_timeout_ms = connect_timeout;
        conf->api_timeout_ms = api_timeout;

        conf->checksum = apr_pstrdup(pool, checksum_tmp);

        conf->first_party_enabled = first_party_enabled;
        conf->first_party_xhr_enabled = reverse_xhr_enabled;

        json_t *j_hdrs = json_object_get(j, "ipHeaders");
        if (j_hdrs && json_array_size(j_hdrs)) {

            apr_array_clear(conf->ip_header_keys);

            for (size_t i = 0; i< json_array_size(j_hdrs); i++) {
                const char *str;
                json_t *obj_txt;

                obj_txt = json_array_get(j_hdrs, i);
                if (!obj_txt || !json_is_string(obj_txt)) {
                    continue;
                }
                str = json_string_value(obj_txt);
                const char** entry = apr_array_push(conf->ip_header_keys);
                *entry = apr_pstrdup(pool, str);
            }
        }

        j_hdrs = json_object_get(j, "sensitiveHeaders");
        if (j_hdrs && json_array_size(j_hdrs)) {

            apr_array_clear(conf->sensitive_header_keys);

            for (size_t i = 0; i< json_array_size(j_hdrs); i++) {
                const char *str;
                json_t *obj_txt;

                obj_txt = json_array_get(j_hdrs, i);
                if (!obj_txt || !json_is_string(obj_txt)) {
                    continue;
                }
                str = json_string_value(obj_txt);
                const char** entry = apr_array_push(conf->sensitive_header_keys);
                *entry = apr_pstrdup(pool, str);
            }
        }

        // release the lock
        apr_thread_rwlock_unlock(conf->remote_config_lock);

        if (conf->px_debug != px_debug) {
            update_debug_mode(conf, px_debug);
        }

        json_decref(j);

        telemetry_activity_send(telemetry_curl, th_data->server, conf, UPDATE_REASON_REMOTE_CONFIG);
    }

    px_log_debug_thd("thread exiting");

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_easy_cleanup(telemetry_curl);
    apr_thread_exit(thd, 0);
    return NULL;
}

// --------------------------------------------------------------------------------
//

static apr_status_t create_health_check(apr_pool_t *p, server_rec *s, px_config *conf) {
    apr_status_t rv;

    thread_data *hc_data = (thread_data*)apr_palloc(p, sizeof(thread_data));
    conf->px_errors_count = 0;
    hc_data->server = s;
    hc_data->conf = conf;

    rv = apr_thread_cond_create(&conf->health_check_cond, p);
    if (rv != APR_SUCCESS) {
        px_log_error("error while init health_check thread cond");
        return rv;
    }

    rv = apr_thread_mutex_create(&conf->health_check_cond_mutex, 0, p);
    if (rv != APR_SUCCESS) {
        px_log_error("error while creating health_check thread mutex");
        return rv;
    }

    rv = apr_thread_create(&conf->health_check_thread, NULL, health_check, (void*) hc_data, p);
    if (rv != APR_SUCCESS) {
        px_log_error("error while init health_check thread create");
        return rv;
    }

    return rv;
}

static apr_status_t create_remote_config(apr_pool_t *p, server_rec *s, px_config *conf) {
    apr_status_t rv;
    thread_data *th_data= (thread_data*)apr_palloc(p, sizeof(thread_data));
    th_data->server = s;
    th_data->conf = conf;

    rv = apr_thread_rwlock_create(&conf->remote_config_lock, p);
    if (rv != APR_SUCCESS) {
        px_log_error("error while creating remote config rwlocks");
        return rv;
    }

    rv = apr_thread_create(&conf->remote_config_thread, NULL, remote_config, (void*)th_data, p);
    if (rv != APR_SUCCESS) {
        px_log_error("error while init remote config thread");
        return rv;
    }

    return rv;
}

// free all (apache) unmanaged resources
static apr_status_t px_child_exit(void *data) {
    server_rec *s = (server_rec*)data;
    apr_status_t rv = APR_SUCCESS;

    for (server_rec *vs = s; vs; vs = vs->next) {
        px_config *conf = ap_get_module_config(vs->module_config, &perimeterx_module);

        conf->should_exit_thread = true;

        // signaling health check thread to exit
        if (conf->px_health_check) {
            apr_thread_cond_signal(conf->health_check_cond);
            apr_status_t status;
            apr_thread_join(&status, conf->health_check_thread);
        }

        // wait for remote config thread to exit
        if (conf->remote_config_thread) {
            apr_status_t status;
            apr_thread_join(&status, conf->remote_config_thread);
        }

        // terminate the queue and wake up all idle threads
        if (conf->background_activity_queue) {
            rv = apr_queue_term(conf->background_activity_queue);
            if (rv != APR_SUCCESS) {
                char buf[ERR_BUF_SIZE];
                char *err = apr_strerror(rv, buf, sizeof(buf));
                px_log_error_fmt("could not terminate the queue - %s", err);
            }
        }

        if (conf->background_activity_thread) {
            apr_thread_join(&rv, conf->background_activity_thread);
        }

        px_log_debug("cleanup finished");
    }

    return rv;
}

static apr_status_t background_activity_init(px_config *conf, server_rec *s) {
    background_activity_data *thd_data = apr_pcalloc(conf->pool, sizeof(background_activity_data));
    apr_status_t rv;

    thd_data->conf = conf;
    thd_data->server = s;

    // setup wakeup pipe
    if (pipe(conf->background_activity_wakeup_fds)) {
        px_log_error("error calling pipe()");
        return APR_EINVAL;
    }

    rv = apr_queue_create(&conf->background_activity_queue, conf->background_activity_queue_size, conf->pool);
    if (rv != APR_SUCCESS) {
        px_log_error_fmt("error calling apr_queue_create(), queue size: %d", conf->background_activity_queue_size);
        return rv;
    }

    rv = apr_thread_create(&conf->background_activity_thread, NULL, background_activity, thd_data, conf->pool);
    if (rv) {
        px_log_error("error calling apr_thread_create()");
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t px_child_setup(apr_pool_t *p, server_rec *s) {
    apr_status_t rv = APR_SUCCESS;
    // init each virtual host
    for (server_rec *vs = s; vs; vs = vs->next) {

        px_config *conf = ap_get_module_config(vs->module_config, &perimeterx_module);
        if (!conf) {
            continue;
        }
        if (!conf->module_enabled) {
            px_log_debug("Request will not be verified, module is disabled or not properly configured");
            continue;
        }

        conf->server = vs;

        // update debugMode for each vhost
        // TODO: move to merge_svr_conf() func
        update_debug_mode(conf, conf->px_debug);

        // initialize the PerimeterX needed pools and background workers if the PerimeterX module is enabled
        rv = apr_pool_create(&conf->pool, vs->process->pool);
        if (rv != APR_SUCCESS) {
            px_log_error("error while trying to initialize apr_pool for configuration");
            return rv;
        }

        conf->curl_pool = curl_pool_create(conf->pool, conf->curl_pool_size, false);
        conf->redirect_curl_pool = curl_pool_create(conf->pool, conf->redirect_curl_pool_size, true);

        if (conf->background_activity_send) {
            px_log_debug("start init for background_activity_send");

            rv = background_activity_init(conf, s);
            if (rv != APR_SUCCESS) {
                px_log_error("error while trying to init background_activity");
                return rv;
            }
        }

        if (conf->px_health_check) {
            px_log_debug("setting up health_check thread");

            rv = create_health_check(conf->pool, vs, conf);
            if (rv != APR_SUCCESS) {
                px_log_error("error while trying to init health_check_thread");
                return rv;
            }
        }

        // send the initial telemetry request
        CURL *telemetry_curl = curl_easy_init();
        telemetry_activity_send(telemetry_curl, s, conf, UPDATE_REASON_INITIAL_CONFIG);
        px_log_debug("start init for telemetry_activity_send");
        curl_easy_cleanup(telemetry_curl);

        // launch remote_config thread
        if (conf->remote_config_enabled && !conf->remote_config_thread) {
            px_log_debug("setting up remote_config thread");

            rv = create_remote_config(conf->pool, vs, conf);
            if (rv != APR_SUCCESS) {
                px_log_error("error while trying to init remote_config_thread");
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

static apr_status_t px_cleanup_pre_config(UNUSED void *data) {
#if (defined (OPENSSL_THREADS) && APR_HAS_THREADS) &&  (OPENSSL_VERSION_NUMBER < 0x10100000L)
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

#if (OPENSSL_VERSION_NUMBER >= 0x1000000fL) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ERR_remove_thread_state(NULL);
#elif (OPENSSL_VERSION_NUMBER < 0x1000000fL)
    ERR_remove_state(0);
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x00090805f)
    ERR_free_strings();
#endif
    return APR_SUCCESS;
}

static int px_hook_pre_config(apr_pool_t *p, UNUSED apr_pool_t *plog, UNUSED apr_pool_t *ptemp) {
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
    (void)CRYPTO_malloc_init();
#else
    OPENSSL_malloc_init();
#endif
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_library_init();

    OpenSSL_add_all_algorithms();
    curl_global_init(CURL_GLOBAL_ALL);
    /*OpenSSL_add_all_digests();*/

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
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

static void set_app_id_helper(apr_pool_t *pool, px_config *conf, const char *app_id) {
    conf->app_id = app_id;
    conf->base_url = apr_psprintf(pool, DEFAULT_BASE_URL, app_id, NULL);
    conf->risk_api_url = apr_pstrcat(pool, conf->base_url, RISK_API, NULL);
    conf->captcha_api_url = apr_pstrcat(pool, conf->base_url, CAPTCHA_API, NULL);
    conf->activities_api_url = apr_pstrcat(pool, conf->base_url, ACTIVITIES_API, NULL);
    const char *reverse_prefix =  &app_id[2];
    conf->xhr_path_prefix = apr_psprintf(pool, "/%s/xhr", reverse_prefix);
    conf->client_path_prefix = apr_psprintf(pool, "/%s/init.js", reverse_prefix);
    conf->client_exteral_path = apr_psprintf(pool, "//client.perimeterx.net/%s/main.min.js", app_id);
    conf->collector_base_uri = apr_psprintf(pool, "https://collector-%s.perimeterx.net", app_id);
    conf->telemetry_api_url = apr_pstrcat(pool, conf->base_url, TELEMETRY_API, NULL);
}

static const char *set_app_id(cmd_parms *cmd, void *config, const char *app_id) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    if (conf->base_url_is_set) {
        return ERROR_BASE_URL_BEFORE_APP_ID;
    }
    if (strlen(app_id) < 3) {
        return ERROR_SHORT_APP_ID;
    }
    set_app_id_helper(cmd->pool, conf, app_id);
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

static const char *set_connect_timeout_ms(cmd_parms *cmd, void *config, const char *connect_timeout_ms) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    long timeout = atoi(connect_timeout_ms);
    conf->connect_timeout_ms = timeout;
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

static const char *set_redirect_curl_pool_size(cmd_parms *cmd, void *config, const char *curl_pool_size) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    int pool_size = atoi(curl_pool_size);
    if (pool_size > MAX_CURL_POOL_SIZE) {
        return MAX_CURL_POOL_SIZE_EXCEEDED;
    }
    conf->redirect_curl_pool_size = pool_size;
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

static const char *set_monitor_mode(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->monitor_mode = arg ? true : false;
    return NULL;
}

static const char *enable_captcha_subdomain(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->captcha_subdomain = arg ? true : false;
    return NULL;
}

static const char *enable_first_party(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->first_party_enabled = arg ? true : false;
    return NULL;
}

static const char *enable_first_party_xhr(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->first_party_xhr_enabled = arg ? true : false;
    return NULL;
}

static const char* set_collector_base_url(cmd_parms *cmd, void *config, const char *arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    conf->collector_base_uri = arg;
    return NULL;
}

static const char* set_client_base_url(cmd_parms *cmd, void *config, const char *arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    conf->client_base_uri = arg;
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

static const char *set_sensitive_headers(cmd_parms *cmd, void *config, const char *sensitive_header) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    const char** entry = apr_array_push(conf->sensitive_header_keys);
    *entry = sensitive_header;
    return NULL;
}

static const char *set_debug_mode(cmd_parms *cmd, void *config, int arg) {

    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    update_debug_mode(conf, arg);
    return NULL;
}

static const char* add_custom_parameters(cmd_parms *cmd, void *config, const char *param) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }

    // simple state machine for parsing raw list of words: word or "word" or ""
    char *tmp_param = apr_pstrdup(cmd->pool, param);
    enum s {SPACE, WORD, STRING} state = SPACE;
    char *p;
    char c;
    char *str_start;
    for (p = tmp_param; *p != '\0'; p++) {
        c = *p;
        switch (state) {
            case SPACE:
                if (isspace(c)) {
                    continue;
                }
                if (c == '"') {
                    state = STRING;
                    str_start = p + 1;
                    continue;
                }

                state = WORD;
                str_start = p;
                continue;
            case STRING:
                if (c == '"') {
                    *p = '\0';
                    state = SPACE;
                    const char** entry = apr_array_push(conf->custom_parameters);
                    *entry = str_start;
                    continue;
                }
                continue;
            case WORD:
                if (isspace(c)) {
                    *p = '\0';
                    state = SPACE;
                    const char** entry = apr_array_push(conf->custom_parameters);
                    *entry = str_start;
                    continue;
                }
                continue;
        }
    }

    return NULL;
}



static int px_hook_post_request(request_rec *r) {
    px_config *conf = ap_get_module_config(r->server->module_config, &perimeterx_module);

    // process without locking if remote config disabled
    if (!conf->remote_config_enabled) {
        return px_handle_request(r, conf);
    }

#ifdef DEBUG
    apr_time_t start = apr_time_now();
#endif

    int res;
    // only blocks while configuration is refreshing
    apr_thread_rwlock_rdlock(conf->remote_config_lock);

    // if checksum is set: we've received remote configuration at least once
    if (conf->checksum) {
        res = px_handle_request(r, conf);
    } else {
        // we still haven't got the required remote configuration, do not process this request with mod_perimeterx
        res = DECLINED;
    }

    apr_thread_rwlock_unlock(conf->remote_config_lock);

#ifdef DEBUG
    apr_time_t finish = apr_time_now();
    if (finish > start) {
        px_log_debug_fmt("Request processing time: %ld ms (result: %d)", apr_time_as_msec(finish) - apr_time_as_msec(start), res);
    }
#endif

    return res;
}

static void *create_config(apr_pool_t *p, server_rec *s) {
    px_config *conf = apr_pcalloc(p, sizeof(px_config));
    if (conf) {
        conf->server = s;
        conf->pool = NULL;
        conf->curl_pool = NULL;
        conf->redirect_curl_pool = NULL;
        conf->module_enabled = false;
        conf->api_timeout_ms = 1000L;
        conf->captcha_timeout = 1000L;
        conf->connect_timeout_ms = 1000L;
        conf->send_page_activities = true;
        conf->blocking_score = 100;
        conf->captcha_enabled = true;
        conf->module_version = PERIMETERX_MODULE_VERSION;
        conf->skip_mod_by_envvar = false;
        conf->curl_pool_size = 100;
        conf->redirect_curl_pool_size = 40;
        conf->base_url = DEFAULT_BASE_URL;
        conf->risk_api_url = apr_pstrcat(p, conf->base_url, RISK_API, NULL);
        conf->captcha_api_url = apr_pstrcat(p, conf->base_url, CAPTCHA_API, NULL);
        conf->activities_api_url = apr_pstrcat(p, conf->base_url, ACTIVITIES_API, NULL);
        conf->app_id = NULL;
        conf->payload_key = NULL;
        conf->auth_token = NULL;
        conf->auth_header = NULL;
        conf->client_path_prefix = NULL;
        conf->xhr_path_prefix = NULL;
        conf->routes_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->useragents_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->custom_file_ext_whitelist = apr_array_make(p, 0, sizeof(char*));
        conf->ip_header_keys = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_routes = apr_array_make(p, 0, sizeof(char*));
        conf->enabled_hostnames = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_routes_prefix = apr_array_make(p, 0, sizeof(char*));
        conf->sensitive_header_keys = apr_array_make(p, 0, sizeof(char*));
        conf->background_activity_send = false;
        conf->background_activity_workers = 10;
        conf->background_activity_queue_size = 1000;
        conf->px_errors_threshold = 100;
        conf->health_check_interval = apr_time_from_sec(60); // 1 minute
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
        conf->monitor_mode = true;
        conf->enable_token_via_header = true;
        conf->captcha_subdomain = false;
        conf->first_party_enabled = true;
        conf->first_party_xhr_enabled = true;
        conf->client_base_uri = "https://client.perimeterx.net";
        conf->remote_config_thread = NULL;
        conf->health_check_thread = NULL;
        conf->remote_config_enabled = false;
        conf->remote_config_url = apr_pstrcat(p, CONFIGURATION_SERVER_URL, REMOTE_CONFIGURATIONS_PATH, NULL);
        conf->remote_config_interval_ms = apr_time_from_sec(5);
        conf->background_activity_thread = NULL;
        conf->background_activity_queue = NULL;
        conf->telemetry_api_url = apr_pstrcat(p, conf->base_url, TELEMETRY_API, NULL);
        conf->checksum = NULL;
        conf->px_debug = FALSE;
        conf->log_level_err = APLOG_ERR;
        conf->log_level_debug = APLOG_DEBUG;
        conf->custom_parameters = apr_array_make(p, 0, sizeof(char*));
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
    AP_INIT_TAKE1("ConnectTimeoutMS",
            set_connect_timeout_ms,
            NULL,
            OR_ALL,
            "Set timeout for the connect phase in milliseconds"),
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
        AP_INIT_TAKE1("RedirectCurlPoolSize",
            set_redirect_curl_pool_size,
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
            "Set the name of vid response header"),
    AP_INIT_TAKE1("UuidHeaderName",
            set_uuid_header_name,
            NULL,
            OR_ALL,
            "Set the name of uuid response header"),
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
            "Set the captcha provider"),
    AP_INIT_FLAG("MonitorMode",
            set_monitor_mode,
            NULL,
            OR_ALL,
            "Toggle monitor mode, requests will be inspected but not be blocked"),
    AP_INIT_FLAG("CaptchaSubdomain",
            enable_captcha_subdomain,
            NULL,
            OR_ALL,
            "Flags that _pxCaptcha can be signed is a subdomain"),
    AP_INIT_FLAG("FirstPartyEnabled",
            enable_first_party,
            NULL,
            OR_ALL,
            "Toggles first party mode"),
    AP_INIT_FLAG("FirstPartyXhrEnabled",
            enable_first_party_xhr,
            NULL,
            OR_ALL,
            "Toggles first party xhr"),
    AP_INIT_TAKE1("ClientBaseUrl",
            set_client_base_url,
            NULL,
            OR_ALL,
            "Set base url which client request will be redirected to"),
    AP_INIT_TAKE1("CollectorBaseUrl",
            set_collector_base_url,
            NULL,
            OR_ALL,
            "Set base url which client activity requersts will be redirected to"),
    AP_INIT_FLAG("EnableRemoteConfiguration",
            set_remote_configuration,
            NULL,
            OR_ALL,
            "Toggle remote configuration on/off"),
    AP_INIT_TAKE1("RemoteConfigurationUrl",
            set_remote_config_url,
            NULL,
            OR_ALL,
            "Set the URL for the remote configurations"),
    AP_INIT_TAKE1("RemoteConfigurationIntervalMS",
            set_remote_config_interval_ms,
            NULL,
            OR_ALL,
            "Set remote configuration re-check time in milliseconds"),
      AP_INIT_ITERATE("SensitiveHeader",
            set_sensitive_headers,
            NULL,
            OR_ALL,
            "Set a value for a sensitive header which will be filtered and not be reported back"),
    AP_INIT_FLAG("EnableDebugMode",
            set_debug_mode,
            NULL,
            OR_ALL,
            "Toggle debug logging mode"),
    AP_INIT_RAW_ARGS("px_custom_parameters",
            add_custom_parameters,
            NULL,
            OR_ALL,
            "Set the list of headers for custom parameters"),
    { NULL }
};

static void perimeterx_register_hooks(UNUSED apr_pool_t *pool) {
    static const char *const asz_pre[] = { "mod_setenvif.c", NULL };

    ap_hook_post_read_request(px_hook_post_request, asz_pre, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(px_hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(px_hook_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *create_server_config(apr_pool_t *pool, server_rec *s) {
    return create_config(pool, s);
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
