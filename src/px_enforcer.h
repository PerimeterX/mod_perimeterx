#ifndef PX_ENFORCER_H
#define PX_ENFORCER_H

#include "px_types.h"

request_context* create_context(request_rec *r, const px_config *conf);
bool px_should_verify_request(request_rec *r, px_config *conf);
bool px_verify_request(request_context *ctx, px_config *conf);

#endif
