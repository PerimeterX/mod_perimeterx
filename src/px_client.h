#ifndef PX_CLIENT_H
#define PX_CLIENT_H

#include "px_types.h"

CURLcode post_request(const char *url, const char *payload, long timeout, px_config *conf, const server_rec *s, char **response_data, double *request_rtt);
#endif
