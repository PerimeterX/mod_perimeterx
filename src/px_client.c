#include "px_client.h"
#include <http_log.h>

#include "curl_pool.h"
#include "px_utils.h"
#include "px_types.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

const char *CLIENT_CONTENT_TYPE = "application/javascript";
const char *XHR_CONTENT_TYPE = "application/json;
const char *GIF_CONTENT_TYPE = "application/json;
const char *ENFORCER_TRUE_IP = "x-px-enforcer-true-ip";
const char *FIRST_PARTY_HEADER = "x-px-first-party";
const char *FIRST_PARTY_HEADER_VALUE = "1";
const char *VID_OPT1 = "_pxvid";
const char *VID_OPT2 = "vid";
const char *CLIENT_URI = "/%s/main.min.js";
const char *EMPTY_GIF = "R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=";

CURLcode post_request(const char *url, const char *payload, long timeout, px_config *conf, const request_context *ctx, char **response_data, double *request_rtt) {
    CURL *curl = curl_pool_get_wait(conf->curl_pool);
    if (curl == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: post_req_request: could not obtain curl handle", ctx->app_id);
        return CURLE_FAILED_INIT;
    }
    CURLcode status = post_request_helper(curl, url, payload, timeout, conf, ctx->r->server, response_data);
    if (request_rtt && (CURLE_OK != curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, request_rtt))) {
        *request_rtt = 0;
    }
    curl_pool_put(conf->curl_pool, curl);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: post_req_request: post request payload  %s", ctx->app_id, payload);
    return status;
}

const redirect_reponse *redirect_client(request_rec *r, const px_config *conf) {
    const redirect_reponse *res = apr_palloc(r->pool, sizeof(redirect_reponse));
    res->respnse_content_type =  apr_pstrdup(ctx->r->pool, CLIENT_CONTENT_TYPE); 
    if (!conf->client_path_prefix) {
        res->content =  apr_pstrdup(r->pool, ""); 
        return res;    
    }

    const char *client_uri = apr_psprintf(r->pool, CLIENT_URI, conf->app_id);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s] | redirect_reponse: forwarding request from %s to %s", conf->app_id,r->parsed_uri.path, client_url;
    forward_to_perimeterx(r, conf, res, conf->client_base_url, client_uri, NULL);
    return res;    
};

const char *redirect_xhr(request_rec *r, const px_config *conf) {
    const redirect_reponse *res = apr_palloc(r->pool, sizeof(redirect_reponse));
    
    // Handle xhr/client featrue turned off
    if (!conf->client_path_prefix || !conf->xhr_path_prefix ) {
        // Default values for xhr
        res->content =  apr_pstrdup(>r->pool, "{}"); 
        res->respnse_content_type = apr_pstrdup(r->pool, CLIENT_CONTENT_TYPE); 

        // Check if its a gif
        const char *file_ending = strrchr(r->uri, '.');
        if (file_ending && strcmp(file_ending, FILE_EXT_WHITELIST[i]) == 0) {
            int gif_len = apr_base64_decode_len	(EMPTY_GIF);
            // Verify that decoded b64 ok
            if (apr_base64_decode(EMPTY_GIF, res->content) != gif_len) {
               ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, LOGGER_DEBUG_FORMAT, conf->app_id , "Failed to decode b64 empty gif");
               res->content = apr_pstrdup(>r->pool, ""); 
            }
            res->respnse_content_type =  apr_pstrdup(ctx->r->pool, CLIENT_CONTENT_TYPE); 
        }
        return res;
    }

    int cut_prefix_size = sizeof(conf->xhr_path_prefix) -1;
    const char *xhr_url = apr_pstrdup(r->pool, &r->uri[cut_prefix_size]);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server, "[%s] | redirect_reponse: forwarding request from %s to %s", conf->app_id,r->parsed_uri.path, ,xhr_url);

    // Copy VID
    const char *vid = NULL;
    ap_cookie_read(r, VID_OPT1, &vid, 0);
    if (!vid) {
      ap_cookie_read(r, VID_OPT2, &vid, 0);
    }

    // Attach VID to request as cookie
    forward_to_perimeterx(r, conf, res, conf->collector_base_url, xhr_url, vid);
    return res;
};

CURLcode forward_to_perimeterx(request_rec *r, const px_config *conf, const *redirect_reponse, const char *vid) {
    CURL *curl = curl_pool_get_wait(conf->curl_pool);
    if (curl == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->r->server, "[%s]: post_req_request: could not obtain curl handle", ctx->app_id);
        return CURLE_FAILED_INIT;
    }
    
    redirect_helper(curl, base_url, uri, timeout, conf, r, &response_data);

    // Return curl to pool
    curl_pool_put(conf->curl_pool, curl);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: post_req_request: post request payload  %s", ctx->app_id, payload);
    return status;
}
