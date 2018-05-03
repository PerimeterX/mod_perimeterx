#include "px_client.h"
#include <apr_strings.h>
#include <util_cookies.h>

#include "curl_pool.h"
#include "px_utils.h"
#include "px_types.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *VID_OPT1 = "_pxvid";
static const char *VID_OPT2 = "pxvid";
static const char *CLIENT_URI = "/%s/main.min.js";
static const char EMPTY_GIF[] = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b };
static const redirect_response DEFAULT_JS_RESPONSE = {
    .predefined = true,
    .content = "",
    .content_size = 0,
    .response_content_type = "application/javascript",
};
static const redirect_response DEFAULT_XHR_RESPONSE = {
    .predefined = true,
    .content = "{}",
    .content_size = 2,
    .response_content_type =  "application/json",
};
static const redirect_response DEFAULT_GIF_RESPONSE = {
    .predefined = true,
    .content = EMPTY_GIF,
    .content_size = sizeof(EMPTY_GIF)/sizeof(*EMPTY_GIF),
    .response_content_type = "image/gif",
};

CURLcode post_request(const char *url, const char *payload, long connect_timeout, long timeout, px_config *conf, const request_context *ctx, char **response_data, double *request_rtt) {
    CURL *curl = curl_pool_get_wait(conf->curl_pool);
    if (curl == NULL) {
        px_log_error("could not obtain curl handle");
        return CURLE_FAILED_INIT;
    }
    CURLcode status = post_request_helper(curl, url, payload, connect_timeout, timeout, conf, ctx->r->server, response_data);
    if (request_rtt && (CURLE_OK != curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, request_rtt))) {
        *request_rtt = 0;
    }
    curl_pool_put(conf->curl_pool, curl);

    px_log_debug_fmt("payload %s", payload);
    return status;
}

static CURLcode forward_to_perimeterx(request_rec *r, px_config *conf, redirect_response *res, const char *base_url, const char *uri, const char *vid) {
    CURL *curl = curl_pool_get_wait(conf->redirect_curl_pool);
    if (curl == NULL) {
        px_log_error("could not obtain curl handle");
        return CURLE_FAILED_INIT;
    }
    px_log_debug("redirecting request");
    CURLcode status = redirect_helper(curl, base_url, uri, vid, conf, r, &res->content, &res->response_headers, &res->content_size);
     // Return curl to pool
    curl_pool_put(conf->redirect_curl_pool, curl);
    return status;
}

const redirect_response *redirect_client(request_rec *r, px_config *conf) {
    const redirect_response *default_res = &DEFAULT_JS_RESPONSE;
    if (!conf->first_party_enabled) {
        px_log_debug("first party is disabled");
        return default_res;
    }

    redirect_response *redirect_res = apr_pcalloc(r->pool, sizeof(redirect_response));
    const char *client_uri = apr_psprintf(r->pool, CLIENT_URI, conf->app_id);
    px_log_debug_fmt("forwarding request from %s to %s%s", r->parsed_uri.path, conf->client_base_uri, client_uri);
    CURLcode status = forward_to_perimeterx(r, conf, redirect_res, conf->client_base_uri, client_uri, NULL);
    redirect_res->response_content_type = default_res->response_content_type;
    if (status != CURLE_OK) {
        px_log_debug_fmt("response returned none 200 response, CURLcode[%d]", status);
        return default_res;
    }
    return redirect_res;
};

const redirect_response *redirect_xhr(request_rec *r, px_config *conf) {
    const redirect_response *default_res = &DEFAULT_XHR_RESPONSE;
    const char *file_ending = strrchr(r->uri, '.');
    if (file_ending && strcmp(file_ending, ".gif") == 0) {
        default_res = &DEFAULT_GIF_RESPONSE;
    }
    // Handle xhr/client feature turned off
    if (!conf->first_party_enabled || !conf->first_party_xhr_enabled) {
        return default_res;
    }

    int cut_prefix_size = strlen(conf->xhr_path_prefix);
    const char *xhr_url = &r->unparsed_uri[cut_prefix_size];
    px_log_debug_fmt("forwarding request from %s to %s%s", r->unparsed_uri, conf->collector_base_uri,xhr_url);

    // Copy VID
    const char *vid = NULL;
    ap_cookie_read(r, VID_OPT1, &vid, 0);
    if (!vid) {
      ap_cookie_read(r, VID_OPT2, &vid, 0);
    }
    redirect_response *redirect_res = apr_pcalloc(r->pool, sizeof(redirect_response));
    redirect_res->response_content_type = default_res->response_content_type;
    // Attach VID to request as cookie
    CURLcode status = forward_to_perimeterx(r, conf, redirect_res, conf->collector_base_uri, xhr_url, vid);
    if (status != CURLE_OK) {
        px_log_debug_fmt("response returned none 200 response, CURLcode[%d]", status);
        return default_res;
    }
    return redirect_res;
};

const redirect_response *redirect_captcha(request_rec *r, px_config *conf) {
    const redirect_response *default_res = &DEFAULT_JS_RESPONSE;
    if (!conf->first_party_enabled) {
        px_log_debug("first party is disabled");
        return default_res;
    }

    redirect_response *redirect_res = apr_pcalloc(r->pool, sizeof(redirect_response));
    // Get the template without the final '/'
    const char *block_uri = &r->unparsed_uri[strlen(conf->captcha_path_prefix)];

    const char *block_base_url = apr_pstrcat(r->pool, "https:", conf->captcha_exteral_path, NULL);
    px_log_debug_fmt("forwarding request from %s to %s%s", r->parsed_uri.path, block_base_url, block_uri);

    CURLcode status = forward_to_perimeterx(r, conf, redirect_res, block_base_url, block_uri, NULL);
    redirect_res->response_content_type = default_res->response_content_type;
    if (status != CURLE_OK) {
        px_log_debug_fmt("response returned none 200 response, CURLcode[%d]", status);
        return default_res;
    }
    return redirect_res;
}
