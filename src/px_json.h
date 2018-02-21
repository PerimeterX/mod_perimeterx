#ifndef PX_JSON_H
#define PX_JSON_H

#include "px_types.h"
const char *captcha_type_str(captcha_type_t captcha_type);
char *create_activity(const char *activity_type, const px_config *conf, const request_context *ctx);
char *create_risk_payload(const request_context *ctx, const px_config *conf);
char *create_captcha_payload(const request_context *ctx, const px_config *conf);
char *create_mobile_response(px_config *cfg, request_context *ctx, const char *compiled_html);
char *create_json_response(px_config *cfg, request_context *ctx);
const char *get_call_reason_string(call_reason_t call_reason);

captcha_response *parse_captcha_response(const char* captcha_response_str, const request_context *ctx);
risk_response* parse_risk_response(const char* risk_response_str, const request_context *ctx);

#ifdef DEBUG
const char* context_to_json_string(request_context *ctx);
#endif

#endif
