#include "px_payload.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <jansson.h>

#include <apr_tables.h>
#include <apr_strings.h>
#include <http_log.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;
static const int HASH_LEN = 65;

static const char *signing_nofields[] = { NULL };

int decode_base64(const char *s, unsigned char **o, int *len, apr_pool_t *p) {
    if (!s) {
        return -1;
    }
    int l = strlen(s);
    *o = (unsigned char*)apr_palloc(p, (l * 3 + 1));
    BIO *bio = BIO_new_mem_buf((void*)s, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bio, *o, l);
    BIO_free_all(b64);
    return 0;
}

risk_payload *parse_risk_payload(const char *raw_payload, request_context *ctx) {
    json_error_t error;
    json_t *j_payload = json_loads(raw_payload, 0, &error);
    if (!j_payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: payload data: parse failed with error. raw_payload (%s), text (%s)", ctx->app_id, raw_payload, error.text);
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: payload data: unpack json failed. raw_payload: (%s)", ctx->app_id, raw_payload);
        json_decref(j_payload);
        return NULL;
    }

    risk_payload *payload = (risk_payload*)apr_palloc(ctx->r->pool, sizeof(risk_payload));
    if (!payload) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: payload data: failed to allocate risk payload struct. raw_payload: (%s)", ctx->app_id, raw_payload);
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
    payload->a = apr_psprintf(ctx->r->pool, "%d", a_val);
    payload->b = apr_psprintf(ctx->r->pool, "%d", b_val);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: payload data: timestamp %s, vid %s, uuid %s hash %s scores: a %s b %s", ctx->app_id, payload->timestamp, payload->vid, payload->uuid, payload->hash, payload->a, payload->b);
    json_decref(j_payload);
    return payload;
}

void digest_payload(const risk_payload*payload, request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
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

risk_payload *decode_payload(const char *px_payload, const char *payload_key, request_context *r_ctx) {
    char *px_payload_cpy = apr_pstrdup(r_ctx->r->pool, px_payload);
    // parse payload
    char* saveptr;
    const char* delimieter = ":";
    const char* encoded_salt = strtok_r(px_payload_cpy, delimieter, &saveptr);
    if (encoded_salt == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: stoping payload decryption: no valid salt in payload", r_ctx->app_id);
        return NULL;
    }
    const char* iterations_str = strtok_r(NULL, delimieter, &saveptr);
    if (iterations_str == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: no valid iterations in payload", r_ctx->app_id);
        return NULL;
    }
    apr_int64_t iterations = apr_atoi64(iterations_str);
    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: number of iterations is illegal - %"APR_INT64_T_FMT, r_ctx->app_id, iterations);
        return NULL;
    }
    const char* encoded_payload = strtok_r(NULL, delimieter, &saveptr);
    if (encoded_payload == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: stoping payload decryption: no valid encoded_payload in payload", r_ctx->app_id);
        return NULL;
    }

    // decode payload
    unsigned char *payload;
    int payload_len;
    decode_base64(encoded_payload, &payload, &payload_len, r_ctx->r->pool);

    // decode salt
    unsigned char *salt;
    int salt_len;
    decode_base64(encoded_salt, &salt, &salt_len, r_ctx->r->pool);

    // pbkdf2
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(r_ctx->r->pool, IV_LEN + KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(payload_key, strlen(payload_key), salt, salt_len, iterations, EVP_sha256(),  IV_LEN + KEY_LEN, pbdk2_out) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: PKCS5_PBKDF2_HMAC_SHA256 failed", r_ctx->app_id);
        return NULL;
    }
    const unsigned char key[KEY_LEN];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    const unsigned char iv[IV_LEN];
    memcpy((void*)iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: decryption failed in: Init", r_ctx->app_id);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_palloc(r_ctx->r->pool, payload_len);
    int len;
    int dpayload_len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: decryption failed in: Update", r_ctx->app_id);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_payload: decryption failed in: Final", r_ctx->app_id);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';

    // parse payload string to risk struct
    risk_payload *c = parse_risk_payload((const char*)dpayload, r_ctx);
    r_ctx->px_payload_decrypted = dpayload;

    // clean memory
    EVP_CIPHER_CTX_free(ctx);
    return c;
}

validation_result_t validate_payload(const risk_payload *payload, request_context *ctx, const char *payload_key) {
    if (payload == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_payload: no _px payload", ctx->app_id);
        return VALIDATION_RESULT_NULL_PAYLOAD;
    }

    if (payload->hash == NULL || strlen(payload->hash) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_payload: no hash", ctx->app_id);
    if (currenttime > cookie->ts) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server,
                "[%s]: validate_cookie: cookie expired", ctx->app_id);
    if (currenttime > payload->ts) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_payload: payload expired", ctx->app_id);
        return VALIDATION_RESULT_EXPIRED;
    }

    char signature[HASH_LEN];
    const char *signing_fields_ua[] = { ctx->useragent, NULL };
    const char **signing_fields = (ctx->token_origin == TOKEN_ORIGIN_COOKIE) ? signing_fields_ua : signing_nofields;
    digest_payload(payload, ctx, payload_key, signing_fields, signature, HASH_LEN);

    if (memcmp(signature, payload->hash, 64) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_payload: invalid signature", ctx->app_id);
        return VALIDATION_RESULT_INVALID;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_payload: valid", ctx->app_id);
    return VALIDATION_RESULT_VALID;
}
