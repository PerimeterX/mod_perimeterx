#ifndef PX_COOKIE_H
#define PX_COOKIE_H

#include "px_types.h"

risk_cookie *decode_cookie(const char *px_cookie, const char *cookie_key, request_context *r_ctx);
validation_result_t validate_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key);

#endif
