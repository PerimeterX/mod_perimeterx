#ifndef PX_UTILS_H
#define PX_UTILS_H

#include <http_protocol.h>
#include <apr_pools.h>

#include "px_types.h"

struct response_t {
    char* data;
    size_t size;
    server_rec *server;
    const char *app_id;
};

size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream);
const char *get_request_ip(const request_rec *r, const px_config *conf);
int extract_payload_from_header(apr_pool_t *pool, apr_table_t *headers, const char **payload);
CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long timeout, px_config *conf, server_rec *server, char **response_data);

#endif
