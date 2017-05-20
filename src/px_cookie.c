#include "px_cookie.h"

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

static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;
static const int HASH_LEN = 65;

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

risk_cookie *parse_risk_cookie(const char *raw_cookie, request_context *ctx) {
    json_error_t error;
    json_t *j_cookie = json_loads(raw_cookie, 0, &error);
    if (!j_cookie) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: cookie data: parse failed with error. raw_cookie (%s), text (%s)", ctx->app_id, raw_cookie, error.text);
        return NULL;
    }

    int a_val, b_val;
    char *hash, *uuid, *vid;
    json_int_t ts;
    if (json_unpack(j_cookie, "{s:s,s:s,s:{s:i,s:i},s:I,s:s}",
                "v", &vid,
                "u", &uuid,
                "s",
                "a", &a_val,
                "b", &b_val,
                "t", &ts,
                "h", &hash)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: cookie data: unpack json failed. raw_cookie: (%s)", ctx->app_id, raw_cookie);
        json_decref(j_cookie);
        return NULL;
    }

    risk_cookie *cookie = (risk_cookie*)apr_palloc(ctx->r->pool, sizeof(risk_cookie));
    if (!cookie) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: cookie data: failed to allocate risk cookie struct. raw_cookie: (%s)", ctx->app_id, raw_cookie);
        json_decref(j_cookie);
        return NULL;
    }

    char buf[30] = {0};
    snprintf(buf, sizeof(buf), "%"JSON_INTEGER_FORMAT, ts);
    cookie->timestamp = apr_pstrdup(ctx->r->pool, buf);
    cookie->ts = ts;
    cookie->hash = apr_pstrdup(ctx->r->pool, hash);
    cookie->uuid = apr_pstrdup(ctx->r->pool, uuid);
    cookie->vid = apr_pstrdup(ctx->r->pool, vid);
    cookie->a_val = a_val;
    cookie->b_val = b_val;
    cookie->a = apr_psprintf(ctx->r->pool, "%d", a_val);
    cookie->b = apr_psprintf(ctx->r->pool, "%d", b_val);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: cookie data: timestamp %s, vid %s, uuid %s hash %s scores: a %s b %s", ctx->app_id, cookie->timestamp, cookie->vid, cookie->uuid, cookie->hash, cookie->a, cookie->b);
    json_decref(j_cookie);
    return cookie;
}

void digest_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key, const char **signing_fields, int sign_fields_size, char *buffer, int buffer_len) {
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);

    HMAC_Init_ex(&hmac, cookie_key, strlen(cookie_key), EVP_sha256(), NULL);

    if (cookie->timestamp) {
        HMAC_Update(&hmac, cookie->timestamp, strlen(cookie->timestamp));
    }
    if (cookie->a) {
        HMAC_Update(&hmac, cookie->a, strlen(cookie->a));
    }
    if (cookie->b) {
        HMAC_Update(&hmac, cookie->b, strlen(cookie->b));
    }
    if (cookie->uuid) {
        HMAC_Update(&hmac, cookie->uuid, strlen(cookie->uuid));
    }
    if (cookie->vid) {
        HMAC_Update(&hmac, cookie->vid, strlen(cookie->vid));
    }

    for (int i = 0; i < sign_fields_size; i++) {
        HMAC_Update(&hmac, signing_fields[i], strlen(signing_fields[i]));
    }

    int len = buffer_len / 2;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    for (int i = 0; i < len; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
}

risk_cookie *decode_cookie(const char *px_cookie, const char *cookie_key, request_context *r_ctx) {
    char *px_cookie_cpy = apr_pstrdup(r_ctx->r->pool, px_cookie);
    // parse cookie
    char* saveptr;
    const char* delimieter = ":";
    const char* encoded_salt = strtok_r(px_cookie_cpy, delimieter, &saveptr);
    if (encoded_salt == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: stoping cookie decryption: no valid salt in cookie", r_ctx->app_id);
        return NULL;
    }
    const char* iterations_str = strtok_r(NULL, delimieter, &saveptr);
    if (iterations_str == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: no valid iterations in cookie", r_ctx->app_id);
        return NULL;
    }
    apr_int64_t iterations = apr_atoi64(iterations_str);
    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: number of iterations is illegal - %"APR_INT64_T_FMT, r_ctx->app_id, iterations);
        return NULL;
    }
    const char* encoded_payload = strtok_r(NULL, delimieter, &saveptr);
    if (encoded_payload == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: stoping cookie decryption: no valid encoded_payload in cookie", r_ctx->app_id);
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
    if (PKCS5_PBKDF2_HMAC(cookie_key, strlen(cookie_key), salt, salt_len, iterations, EVP_sha256(),  IV_LEN + KEY_LEN, pbdk2_out) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: PKCS5_PBKDF2_HMAC_SHA256 failed", r_ctx->app_id);
        return NULL;
    }
    const unsigned char key[KEY_LEN];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    const unsigned char iv[IV_LEN];
    memcpy((void*)iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: decryption failed in: Init", r_ctx->app_id);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_palloc(r_ctx->r->pool, payload_len);
    int len;
    int dpayload_len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: decryption failed in: Update", r_ctx->app_id);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r_ctx->r->server, "[%s]: decode_cookie: decryption failed in: Final", r_ctx->app_id);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';

    // parse cookie string to risk struct
    risk_cookie *c = parse_risk_cookie((const char*)dpayload, r_ctx);
    r_ctx->px_cookie_decrypted = dpayload;

    // clean memory
    EVP_CIPHER_CTX_free(ctx);
    return c;
}

validation_result_t validate_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key) {
    if (cookie == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_cookie: no _px cookie", ctx->app_id);
        return VALIDATION_RESULT_NULL_COOKIE;
    }

    if (cookie->hash == NULL || strlen(cookie->hash) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_cookie: no hash", ctx->app_id);
        return VALIDATION_RESULT_NO_SIGNING;
    }

    struct timeval te;
    gettimeofday(&te, NULL);
    long long currenttime = te.tv_sec * 1000LL + te.tv_usec / 1000;
    if (currenttime > cookie->ts) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_cookie: cookie expired", ctx->app_id);
        return VALIDATION_RESULT_EXPIRED;
    }

    char signature[HASH_LEN];
    const char *signing_fields[] = { ctx->useragent } ;
    digest_cookie(cookie, ctx, cookie_key, signing_fields, sizeof(signing_fields)/sizeof(*signing_fields), signature, HASH_LEN);

    if (memcmp(signature, cookie->hash, 64) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_cookie: invalid signature", ctx->app_id);
        return VALIDATION_RESULT_INVALID;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: validate_cookie: valid", ctx->app_id);
    return VALIDATION_RESULT_VALID;
}
