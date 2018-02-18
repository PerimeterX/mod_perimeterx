#ifndef PX_UTILS_H
#define PX_UTILS_H

#include <http_protocol.h>
#include <apr_pools.h>

#include "px_types.h"

const char *get_request_ip(const request_rec *r, const px_config *conf);
const char *pescape_urlencoded(apr_pool_t *p, const char *str);
int extract_payload_from_header(apr_pool_t *pool, apr_table_t *headers, const char **payload3, const char **payload1);
CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long timeout, px_config *conf, server_rec *server, char **response_data);
CURLcode redirect_helper(CURL* curl, const char *base_url, const char *uri, const char *vid, px_config *conf, request_rec *r, char **response_data,  apr_array_header_t **response_headers);
#endif
