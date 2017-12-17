#include "px_client.h"
#include <http_log.h>

#include "curl_pool.h"
#include "px_utils.h"
#include "px_types.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

CURLcode post_request(const char *url, const char *payload, long timeout, px_config *conf, const server_rec *s, char **response_data, double *request_rtt) {
    CURL *curl = curl_pool_get_wait(conf->curl_pool);
    if (curl == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "[%s]: post_req_request: could not obtain curl handle", conf->app_id);
        return CURLE_FAILED_INIT;
    }
    CURLcode status = post_request_helper(curl, url, payload, timeout, conf, s, response_data);
    if (request_rtt && (CURLE_OK != curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, request_rtt))) {
        *request_rtt = 0;
    }
    curl_pool_put(conf->curl_pool, curl);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "[%s]: post_req_request: post request payload  %s", conf->app_id, payload);
    return status;
}
