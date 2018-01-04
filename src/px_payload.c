#include "px_payload.h"

#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <jansson.h>
#include <apr_base64.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <http_log.h>

static const char *LOGGER_DEBUG_FORMAT = "[PerimeterX - DEBUG][%s] - %s";
static const char *LOGGER_ERROR_FORMAT = "[PerimeterX - ERROR][%s] - %s";

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;
#define IV_LEN (16)
#define COOKIE_KEY_LEN  (32)
#define HASH_LEN (65)

static const char *SIGNING_NOFIELDS[] = { NULL };
static const char *COOKIE_DELIMITER = ":";

static unsigned char *decode_base64(const char *s, int *len, apr_pool_t *p) {
    if (!s) {
        return NULL;
    }
    int l = strlen(s);
    int buffsize = apr_base64_decode_len(s) + 1;
    unsigned char *o = (unsigned char*)apr_palloc(p, buffsize);
    BIO *bio = BIO_new_mem_buf((void*)s, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bio, o, l);
    BIO_free_all(b64);
    o[*len + 1] = '\0';
    return o;
}

static risk_payload *parse_risk_payload3(const char *raw_payload, request_context *ctx) {
    json_error_t error;
    json_t *j_payload = json_loads(raw_payload, 0, &error);
    if (!j_payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "payload data (v3): parse failed with error. raw_payload ", raw_payload, " text ", error.text, NULL));
        return NULL;
    }

    const char *vid;
    const char *uuid;
    int score;
    json_int_t ts;
    const char *action;
    if (json_unpack(j_payload, "{s:s,s:s,s:i,s:I,s:s}",
                "v", &vid,
                "u", &uuid,
                "s", &score,
                "t", &ts,
                "a", &action)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "payload data (v3): unpack json failed. raw_payload: ", raw_payload, NULL));
        json_decref(j_payload);
        return NULL;
    }

    risk_payload *payload = (risk_payload*)apr_palloc(ctx->r->pool, sizeof(risk_payload));
    if (!payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "payload data (v3): failed to allocate risk payload struct. raw_payload: ", raw_payload, NULL));
        json_decref(j_payload);
        return NULL;
    }

    char buf[30] = {0};
    snprintf(buf, sizeof(buf), "%"JSON_INTEGER_FORMAT, ts);
    payload->timestamp = apr_pstrdup(ctx->r->pool, buf);
    payload->ts = ts;
    payload->uuid = apr_pstrdup(ctx->r->pool, uuid);
    payload->vid = apr_pstrdup(ctx->r->pool, vid);
    payload->score = score;
    payload->action = apr_pstrdup(ctx->r->pool, action);

    json_decref(j_payload);
    return payload;
}

static risk_payload *parse_risk_payload1(const char *raw_payload, request_context *ctx) {
    json_error_t error;
    json_t *j_payload = json_loads(raw_payload, 0, &error);
    if (!j_payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "payload data (v1): parse failed with error. raw_payload ", raw_payload, " text ", error.text, NULL));
        return NULL;
    }

    int a_val, b_val;
    char *hash, *uuid, *vid;
    json_int_t ts;
    if (json_unpack(j_payload, "{s:s,s:s,s:{s:i,s:i},s:I,s:s}",
                "v", &vid,
                "u", &uuid,
                "s",
                "a", &a_val,
                "b", &b_val,
                "t", &ts,
                "h", &hash)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "payload data (v1): unpack json failed. raw_payload: ", raw_payload, NULL));
        json_decref(j_payload);
        return NULL;
    }

    risk_payload *payload = (risk_payload*)apr_palloc(ctx->r->pool, sizeof(risk_payload));
    if (!payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "payload data (v1): failed to allocate risk payload struct. raw_payload: ", raw_payload, NULL));
        json_decref(j_payload);
        return NULL;
    }

    char buf[30] = {0};
    snprintf(buf, sizeof(buf), "%"JSON_INTEGER_FORMAT, ts);
    payload->timestamp = apr_pstrdup(ctx->r->pool, buf);
    payload->ts = ts;
    payload->hash = apr_pstrdup(ctx->r->pool, hash);
    payload->uuid = apr_pstrdup(ctx->r->pool, uuid);
    payload->vid = apr_pstrdup(ctx->r->pool, vid);
    payload->a_val = a_val;
    payload->b_val = b_val;
    payload->score = b_val;
    payload->a = apr_psprintf(ctx->r->pool, "%d", a_val);
    payload->b = apr_psprintf(ctx->r->pool, "%d", b_val);
    payload->action = "c";

    json_decref(j_payload);
    return payload;
}

risk_payload *parse_risk_payload(const char *raw_payload, request_context *ctx) {
    risk_payload *rp = NULL;
    switch (ctx->px_payload_version) {
        case 1:
            rp = parse_risk_payload1(raw_payload, ctx);
            if (rp) {
                ctx->px_payload_hmac = rp->hash;
            }
            break;
        case 3:
            rp = parse_risk_payload3(raw_payload, ctx);
            break;
    }
    return rp;
}

static void digest_payload1(const risk_payload*payload, request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);

    HMAC_Init_ex(&hmac, payload_key, strlen(payload_key), EVP_sha256(), NULL);

    if (payload->timestamp) {
        HMAC_Update(&hmac, payload->timestamp, strlen(payload->timestamp));
    }
    if (payload->a) {
        HMAC_Update(&hmac, payload->a, strlen(payload->a));
    }
    if (payload->b) {
        HMAC_Update(&hmac, payload->b, strlen(payload->b));
    }
    if (payload->uuid) {
        HMAC_Update(&hmac, payload->uuid, strlen(payload->uuid));
    }
    if (payload->vid) {
        HMAC_Update(&hmac, payload->vid, strlen(payload->vid));
    }

    while (*signing_fields) {
        HMAC_Update(&hmac, *signing_fields, strlen(*signing_fields));
        signing_fields++;
    }

    int len = buffer_len / 2;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    for (int i = 0; i < len; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
}

static void digest_payload3(const risk_payload *payload, request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, payload_key, strlen(payload_key), EVP_sha256(), NULL);
    const char *d = strchr(ctx->px_payload, ':');
    if (d) {
        d += 1; // point after :
        HMAC_Update(&hmac, d, strlen(d));
    }
    while (*signing_fields) {
        HMAC_Update(&hmac, *signing_fields, strlen(*signing_fields));
        signing_fields++;
    }

    int len = buffer_len / 2;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);
    for (int i = 0; i < len; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
}

void digest_payload(const risk_payload *payload, request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
    if (ctx->px_payload_version == 3) {
        digest_payload3(payload, ctx, payload_key, signing_fields, buffer, buffer_len);
    } else { 
	digest_payload1(payload, ctx, payload_key, signing_fields, buffer, buffer_len);
    }
}

risk_payload *decode_payload(const char *px_payload, const char *payload_key, request_context *r_ctx) {
    char *px_payload_cpy = apr_pstrdup(r_ctx->r->pool, px_payload);
    char* saveptr;
    // extract hmac from payload for v3
    if (r_ctx->px_payload_version == 3) {
        const char *payload_hmac = apr_strtok(px_payload_cpy, delimieter, &saveptr);
        if (payload_hmac == NULL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: stoping payload decryption: no valid hmac for v3");
            return NULL;
        }
        r_ctx->px_payload_hmac = apr_pstrdup(r_ctx->r->pool, payload_hmac);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, apr_pstrcat(r_ctx->r->pool, "decode_payload: hmac for v3 is ", r_ctx->px_payload_hmac, NULL));
        px_payload_cpy = NULL;
    }
    const char* encoded_salt = apr_strtok(px_payload_cpy, delimieter, &saveptr);
    if (encoded_salt == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: stoping payload decryption: no valid salt in payload", r_ctx->app_id);
        return NULL;
    }
    const char* iterations_str = apr_strtok(NULL, delimieter, &saveptr);
    if (iterations_str == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: no valid iterations in payload");
        return NULL;
    }
    int iterations = atoi(iterations_str);
    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, apr_pstrcat(r_ctx->r->pool, "decode_payload: number of iterations is illegal - ", iterations, NULL));
        return NULL;
    }
    const char* encoded_payload = apr_strtok(NULL, delimieter, &saveptr);
    if (encoded_payload == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: stoping payload decryption: no valid encoded_payload in payload");
        return NULL;
    }
    // decode payload
    int payload_len = 0;
    unsigned char *payload = decode_base64(encoded_payload, &payload_len, r_ctx->r->pool);
    if (!payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: failed to base64 decode payload");
        return NULL;
    }

    // decode salt
    int salt_len = 0;
    unsigned char *salt = decode_base64(encoded_salt, &salt_len, r_ctx->r->pool);
    if (!salt) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: failed to base64 decode salt");
        return NULL;
    }

    // pbkdf2
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(r_ctx->r->pool, IV_LEN + COOKIE_KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(payload_key, strlen(payload_key), salt, salt_len, iterations, EVP_sha256(),  IV_LEN + COOKIE_KEY_LEN, pbdk2_out) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: PKCS5_PBKDF2_HMAC_SHA256 failed", r_ctx->app_id);
        return NULL;
    }
    const unsigned char key[COOKIE_KEY_LEN];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    unsigned char iv[IV_LEN];
    memcpy(&iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: decryption failed in: Init");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_pcalloc(r_ctx->r->pool, payload_len + 1);
    int len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: decryption failed in: Update");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        ERR_print_errors_fp(stderr);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, LOGGER_DEBUG_FORMAT, r_ctx->app_id, "decode_payload: decryption failed in: Final");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    EVP_CIPHER_CTX_free(ctx);

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';
    r_ctx->px_payload_decrypted = dpayload;

    // parse payload string to risk struct
    risk_payload *c = parse_risk_payload((const char*)dpayload, r_ctx);
    return c;
}

validation_result_t validate_payload(const risk_payload *payload, request_context *ctx, const char *payload_key) {
    if (payload == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "validate_payload: no _px payload");
        return VALIDATION_RESULT_NULL_PAYLOAD;
    }

    if (ctx->px_payload_hmac == NULL || strlen(ctx->px_payload_hmac) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "validate_payload: no hash");
        return VALIDATION_RESULT_NO_SIGNING;
    }

   	apr_int64_t now = apr_time_from_msec(apr_time_now());
    if (now > payload->ts) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_payload: payload expired", ctx->app_id);
        return VALIDATION_RESULT_EXPIRED;
    }

    char signature[HASH_LEN];
    const char *signing_fields_ua[] = { ctx->useragent, NULL };
    const char **signing_fields = (ctx->token_origin == TOKEN_ORIGIN_COOKIE) ? signing_fields_ua : SIGNING_NOFIELDS;
    digest_payload(payload, ctx, payload_key, signing_fields, signature, HASH_LEN);

    if (memcmp(signature, ctx->px_payload_hmac, 64) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Cookie HMAC validation failed, value: ", ctx->px_payload_decrypted, " user-agent: ", ctx->useragent, NULL));
        return VALIDATION_RESULT_INVALID;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "Cookie evaluation ended successfully, risk score: ", apr_itoa(ctx->r->pool, ctx->score), NULL));
    return VALIDATION_RESULT_VALID;
}

