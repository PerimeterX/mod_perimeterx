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

#include "px_utils.h"
#include "px_types.h"
#include "px_template.h"
#include "px_enforcer.h"
#include "px_json.h"

module AP_MODULE_DECLARE_DATA perimeterx_module;

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *DEFAULT_BASE_URL = "https://sapi-%s.perimeterx.net";
static const char *RISK_API = "/api/v2/risk";
static const char *CAPTCHA_API = "/api/v1/risk/captcha";
static const char *ACTIVITIES_API = "/api/v1/collector/s2s";
static const char *HEALTH_CHECK_API = "/api/v1/kpi/status";

static const char *CONTENT_TYPE_JSON = "application/json";
static const char *CONTENT_TYPE_HTML = "text/html";

// constants
//
static const char *CAPTCHA_COOKIE = "_pxCaptcha";
static const int MAX_CURL_POOL_SIZE = 10000;

static const char *ERROR_CONFIG_MISSING = "mod_perimeterx: config structure not allocated";
static const char* MAX_CURL_POOL_SIZE_EXCEEDED = "mod_perimeterx: CurlPoolSize can not exceed 10000";
static const char *INVALID_WORKER_NUMBER_QUEUE_SIZE = "mod_perimeterx: invalid number of background activity workers, must be greater than zero";
static const char *INVALID_ACTIVITY_QUEUE_SIZE = "mod_perimeterx: invalid background activity queue size , must be greater than zero";

static const char *block_tpl = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{# cssRef }} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\" /> {{/ cssRef }} </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Access to this page has been denied.</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> You have been blocked because we believe you are using automation tools to browse the website. </p> <p> Please note that Javascript and Cookies must be enabled on your browser to access the website. </p> <p> If you think you have been blocked by mistake, please contact the website administrator with the reference ID below. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> ( function (){ window._pxAppId = '{{appId}}'; var p = document.getElementsByTagName(\"script\")[0], s = document.createElement(\"script\"); s.async = 1; s.src = '//client.perimeterx.net/{{appId}}/main.min.js'; p.parentNode.insertBefore(s, p); } () ); </script> <!-- Custom Script --> {{# jsRef }} <script src=\"{{jsRef}}\"></script> {{/ jsRef }} </body> </html> ";

static const char *captcha_tpl = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{#cssRef}} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\" /> {{/cssRef}} <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script> </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> Please click \"I am not a robot\" to continue </p> <div class=\"g-recaptcha\" data-sitekey=\"6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b\" data-callback=\"handleCaptcha\" data-theme=\"dark\"> </div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> ( function (){ window._pxAppId = '{{appId}}'; var p = document.getElementsByTagName(\"script\")[0], s = document.createElement(\"script\"); s.async = 1; s.src = '//client.perimeterx.net/{{appId}}/main.min.js'; p.parentNode.insertBefore(s, p); } () ); </script> <!-- Captcha --> <script> window.px_vid = '{{vid}}'; function handleCaptcha(response){ var vid = '{{vid}}'; var uuid = '{{uuid}}'; var name = \"_pxCaptcha\"; var expiryUtc = new Date(Date.now()+1000*10).toUTCString(); var cookieParts = [ name, \"=\", response+\":\"+uuid+\":\"+vid, \"; expires=\", expiryUtc, \"; path=/\" ]; document.cookie = cookieParts.join(\"\"); location.reload(); } </script> <!-- Custom Script --> {{#jsRef}} <script src=\"{{jsRef}}\"></script> {{/jsRef}} </body> </html>";

const static char *mobile_captcha_tpl = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{#cssRef}} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\" /> {{/cssRef}} <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script> </head>\r\n <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> Please click \"I am not a robot\" to continue </p> <div class=\"g-recaptcha\" data-sitekey=\"6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b\" data-callback=\"handleCaptcha\" data-theme=\"dark\"> </div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> ( function (){ window._pxAppId = '{{appId}}'; var p = document.getElementsByTagName(\"script\")[0], s = document.createElement(\"script\"); s.async = 1; s.src = '//client.perimeterx.net/{{appId}}/main.min.js'; p.parentNode.insertBefore(s, p); } () ); </script> <!-- Captcha --> <script> function captchaSolved(res) { window.location.href = '/px/captcha_callback?status=' + res.status; } function handleCaptcha(response) { var appId = '{{appId}}'; var vid = '{{vid}}'; var uuid = '{{uuid}}'; var collectorUrl = '{{hostUrl}}'; var req = new XMLHttpRequest(); req.open('POST', collectorUrl + '/api/v1/collector/captcha'); req.setRequestHeader('Content-Type', 'application/json'); req.addEventListener('error', function() { captchaSolved({ status: 1 }); }); req.addEventListener('cancel', function() { captchaSolved({ status: 2 }); }); req.addEventListener('load', function() { if (req.status == 200) { try { var responseJSON = JSON.parse(req.responseText); return captchaSolved(responseJSON); } catch (ex) {} } captchaSolved({ status: 3 }); }); req.send(JSON.stringify({ appId: appId, uuid: uuid, vid: vid, pxCaptcha: response, hostname: window.location.hostname, request: { url: window.location.href } })); } </script> <!-- Custom Script --> {{#jsRef}} <script src=\"{{jsRef}}\"></script> {{/jsRef}} </body> </html>";

#ifdef DEBUG
extern const char *BLOCK_REASON_STR[];
extern const char *CALL_REASON_STR[];
#endif // DEBUG

char* create_response(px_config *conf, request_context *ctx) {
    char *response;
    size_t html_size;
    char *html = NULL;

    // which template to use in response
    const char *template = block_tpl;
    if (ctx->action == ACTION_CAPTCHA) {
        template = ctx->token_origin == TOKEN_ORIGIN_COOKIE ? captcha_tpl : mobile_captcha_tpl;
    }

    // render html page with the relevant template
    int res = render_template(template, &html, ctx, conf, &html_size);
    if (res) {
        // failed to render
        return NULL;
    }

    // formulate server response according to type px token
    if (ctx->token_origin == TOKEN_ORIGIN_HEADER) {
        int expected_encoded_len = apr_base64_encode_len(html_size);
        char *encoded_html = apr_palloc(ctx->r->pool, expected_encoded_len + 1);
        int encoded_len = apr_base64_encode(encoded_html, html, html_size);
        free(html);
        if (encoded_html == 0) {
            return NULL;
        }
        response = create_mobile_response(conf, ctx, encoded_html);
    } else {
        response = html;
    }

    return response;
}

int px_handle_request(request_rec *r, px_config *conf) {
    // fail open mode
    if (conf->px_errors_count >= conf->px_errors_threshold) {
        return OK;
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
            apr_table_set(r->headers_out, conf->score_header_name, score_str);
        }

        if (!request_valid && ctx->block_enabled) {
            if (r->method && strcmp(r->method, "POST") == 0) {
                return HTTP_FORBIDDEN;
            }
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
                const char *content_type = ctx->token_origin == TOKEN_ORIGIN_COOKIE ? CONTENT_TYPE_HTML : CONTENT_TYPE_JSON;
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
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s]: px_handle_request: request passed", ctx->app_id);
    return OK;
}

// Background thread that wakes up after reacing X timeoutes in interval length Y and checks when service is available again
static void *APR_THREAD_FUNC health_check(apr_thread_t *thd, void *data) {
    health_check_data *hc = (health_check_data*) data;
    px_config *conf = hc->config;

    const char *health_check_url = apr_pstrcat(hc->server->process->pool, hc->config->base_url, HEALTH_CHECK_API, NULL);
    CURL *curl = curl_easy_init();
    CURLcode res;
    while (1) {
        // wait for condition and reset errors count on internal
        apr_thread_mutex_lock(conf->health_check_cond_mutex);
        while (apr_atomic_read32(&conf->px_errors_count) < conf->px_errors_threshold) {
            if (apr_thread_cond_timedwait(conf->health_check_cond, conf->health_check_cond_mutex, conf->health_check_interval) == APR_TIMEUP) {
                apr_atomic_set32(&conf->px_errors_count, 0);
            }
        }
        apr_thread_mutex_unlock(conf->health_check_cond_mutex);

        // do health check until success
        CURLcode res = CURLE_AGAIN;
        while (res != CURLE_OK) {
            curl_easy_setopt(curl, CURLOPT_URL, health_check_url);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, conf->api_timeout_ms);
            res = curl_easy_perform(curl);
            if (res != CURLE_OK && res != CURLE_OPERATION_TIMEDOUT) {
                apr_sleep(1000); // TODO(barak): should be configured with nice default
            }
        }
        apr_atomic_set32(&conf->px_errors_count, 0);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, hc->server, "health_check thread exiting");
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
        if (rv == APR_EINTR)
            continue;
        if (rv == APR_EOF)
            break;
        if (rv == APR_SUCCESS && v) {
            char *activity = (char *)v;
            post_request_helper(curl, conf->activities_api_url, activity, conf->api_timeout_ms, conf, consumer_data->server, NULL);
            free(activity);
        }
    }
    curl_easy_cleanup(curl);
    apr_thread_exit(thd, 0);
    return NULL;
}

// --------------------------------------------------------------------------------
//
static apr_status_t destroy_thread_pool(void *t) {
    apr_thread_pool_t *thread_pool = (apr_thread_pool_t*)t;
    apr_thread_pool_destroy(thread_pool);
    return APR_SUCCESS;
}

static apr_status_t destroy_activity_queue(void *q) {
    apr_queue_t *queue = (apr_queue_t*)q;
    apr_queue_term(queue);
    return APR_SUCCESS;
}

static apr_status_t destroy_curl_pool(void *c) {
    curl_pool *cp = (curl_pool*)c;
    curl_pool_destroy(cp);
    return APR_SUCCESS;
}

static apr_status_t create_service_monitor(server_rec *s, px_config *cfg) {
    health_check_data *hc_data= (health_check_data*)apr_palloc(s->process->pool, sizeof(health_check_data));
    cfg->px_errors_count = 0;
    hc_data->server = s;
    hc_data->config = cfg;
    apr_status_t rv;
    rv = apr_thread_cond_create(&cfg->health_check_cond, s->process->pool);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "error while init health_check thread cond");
        exit(1);
    }
    rv = apr_thread_create(&cfg->health_check_thread, NULL, health_check, (void*) hc_data, s->process->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "error while init health_check thread create");
        exit(1);
    }
    rv = apr_thread_mutex_create(&cfg->health_check_cond_mutex, 0, s->process->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "error while creating health_check thread mutex");
        exit(1);
    }
}

static void background_activity_send_init(server_rec *s, px_config *cfg) {
    apr_status_t rv = apr_queue_create(&cfg->activity_queue, cfg->background_activity_queue_size, s->process->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "[%s]: failed to initialize background activity queue", cfg->app_id);
        exit(1);
    }
    activity_consumer_data *consumer_data = apr_palloc(s->process->pool, sizeof(activity_consumer_data));
    consumer_data->server = s;
    consumer_data->config = cfg;
    rv = apr_thread_pool_create(&cfg->activity_thread_pool, 0, cfg->background_activity_workers, s->process->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "[%s]: failed to initialize background activity thread pool", cfg->app_id);
        exit(1);
    }
    for (unsigned int i = 0; i < cfg->background_activity_workers; ++i) {
        rv = apr_thread_pool_push(cfg->activity_thread_pool, background_activity_consumer, consumer_data, 0, NULL);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "failed to push background activity consumer");
        }
    }
}

static void px_hook_child_init(apr_pool_t *p, server_rec *s) {
    curl_global_init(CURL_GLOBAL_ALL);
    // init each virtual host
    for (server_rec *vs = s; vs; vs = vs->next) {
        px_config *cfg = ap_get_module_config(vs->module_config, &perimeterx_module);
        cfg->curl_pool = curl_pool_create(vs->process->pool, cfg->curl_pool_size);
        if (cfg->background_activity_send) {
            background_activity_send_init(vs, cfg);
        }
        if (cfg->px_service_monitor) {
            create_service_monitor(vs, cfg);
        }
        apr_pool_cleanup_register(vs->process->pool, cfg->activity_queue, destroy_activity_queue, apr_pool_cleanup_null);
        apr_pool_cleanup_register(vs->process->pool, cfg->activity_thread_pool, destroy_thread_pool, apr_pool_cleanup_null);
        apr_pool_cleanup_register(vs->process->pool, cfg->curl_pool, destroy_curl_pool, apr_pool_cleanup_null);
    }
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
    conf->base_url = apr_psprintf(cmd->pool, DEFAULT_BASE_URL, app_id, NULL);
    conf->risk_api_url = apr_pstrcat(cmd->pool, conf->base_url, RISK_API, NULL);
    conf->captcha_api_url = apr_pstrcat(cmd->pool, conf->base_url, CAPTCHA_API, NULL);
    conf->activities_api_url = apr_pstrcat(cmd->pool, conf->base_url, ACTIVITIES_API, NULL);
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

static const char *set_px_service_monitor(cmd_parms *cmd, void *config, int arg) {
    px_config *conf = get_config(cmd, config);
    if (!conf) {
        return ERROR_CONFIG_MISSING;
    }
    conf->px_service_monitor = arg ? true : false;
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
        conf->blocking_score = 70;
        conf->captcha_enabled = true;
        conf->module_version = "Apache Module v2.3.2-RC";
        conf->skip_mod_by_envvar = false;
        conf->curl_pool_size = 40;
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
        conf->background_activity_send = false;
        conf->background_activity_workers = 10;
        conf->background_activity_queue_size = 1000;
        conf->px_errors_threshold = 100;
        conf->health_check_interval = 60000000; // 1 minute
        conf->px_service_monitor = false;
        conf->score_header_name = "X-PX-SCORE";
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
            set_cookie_key,
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
    AP_INIT_FLAG("PXServiceMonitor",
            set_px_service_monitor,
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
