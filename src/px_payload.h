#ifndef PX_PAYLOAD_H
#define PX_PAYLOAD_H

#include "px_types.h"

risk_payload *decode_payload(const char *px_payload, const char *payload_key, request_context *r_ctx);
validation_result_t validate_payload(const risk_payload *payload, request_context *ctx, const char *payload_key);

#endif
