#include "px_payload.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>

#include <jansson.h>
#include <apr_base64.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include "px_utils.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;
static const int HASH_LEN = 65;

static const char *SIGNING_NOFIELDS[] = { NULL };
static const char *COOKIE_DELIMITER = ":";

static unsigned char *decode_base64(const char *s, int *len, apr_pool_t *p) {
    if (!s) {
        return NULL;
    }
    int buffsize = apr_base64_decode_len(s) + 1;
    unsigned char *o = (unsigned char*)apr_palloc(p, buffsize);
    *len = apr_base64_decode((char*)o, s);
    return o;
}

static risk_payload *parse_risk_payload3(const char *raw_payload, request_context *ctx) {
    px_config *conf = ctx->conf;
    json_error_t error;
    json_t *j_payload = json_loads(raw_payload, 0, &error);
    if (!j_payload) {
        px_log_debug_fmt("parse failed with error. raw_payload %s test %s", raw_payload, error.text);
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
        px_log_debug_fmt("unpack json failed. raw_payload: %s", raw_payload);
        json_decref(j_payload);
        return NULL;
    }

    risk_payload *payload = (risk_payload*)apr_palloc(ctx->r->pool, sizeof(risk_payload));
    if (!payload) {
        px_log_debug_fmt("failed to allocate risk payload struct. raw_payload: %s", raw_payload);
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
    px_config *conf = ctx->conf;
    json_error_t error;
    json_t *j_payload = json_loads(raw_payload, 0, &error);
    if (!j_payload) {
        px_log_debug_fmt("parse failed with error. raw_payload %s test %s", raw_payload, error.text);
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
        px_log_debug_fmt("unpack json failed. raw_payload: %s", raw_payload);
        json_decref(j_payload);
        return NULL;
    }

    risk_payload *payload = (risk_payload*)apr_palloc(ctx->r->pool, sizeof(risk_payload));
    if (!payload) {
        px_log_debug_fmt("failed to allocate risk payload struct. raw_payload: %s", raw_payload);
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

static risk_payload *parse_risk_payload(const char *raw_payload, request_context *ctx) {
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
        default: {
            px_config *conf = ctx->conf;
            px_log_debug_fmt("unknown payload version: %d", ctx->px_payload_version);
        }
    }
    return rp;
}

static int digest_payload1(const risk_payload *payload, UNUSED request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
    unsigned char hash[32];

    HMAC_CTX *hmac = HMAC_CTX_new();

    if (!HMAC_Init_ex(hmac, payload_key, strlen(payload_key), EVP_sha256(), NULL)) {
        return 0;
    }

    if (payload->timestamp) {
        if (!HMAC_Update(hmac,(unsigned char*) payload->timestamp, strlen(payload->timestamp))) {
            return 0;
        }
    }
    if (payload->a) {
        if (!HMAC_Update(hmac, (unsigned char*) payload->a, strlen(payload->a))) {
            return 0;
        }
    }
    if (payload->b) {
        if (!HMAC_Update(hmac,(unsigned char*) payload->b, strlen(payload->b))) {
            return 0;
        }
    }
    if (payload->uuid) {
        if (!HMAC_Update(hmac, (unsigned char*) payload->uuid, strlen(payload->uuid))) {
            return 0;
        }
    }
    if (payload->vid) {
        if (!HMAC_Update(hmac, (unsigned char*) payload->vid, strlen(payload->vid))) {
            return 0;
        }
    }

    while (*signing_fields) {
        if (!HMAC_Update(hmac, (unsigned char*) *signing_fields, strlen(*signing_fields))) {
            return 0;
        }
        signing_fields++;
    }

    unsigned int len = buffer_len / 2;
    if (!HMAC_Final(hmac, hash, &len)) {
        return 0;
    }
    HMAC_CTX_free(hmac);

    for (unsigned int i = 0; i < len; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }

    return 1;
}

static int digest_payload3(UNUSED const risk_payload *payload, request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
    unsigned char hash[32];

    HMAC_CTX *hmac = HMAC_CTX_new();
    if (!HMAC_Init_ex(hmac, payload_key, strlen(payload_key), EVP_sha256(), NULL)) {
        return 0;
    }
    const char *d = strchr(ctx->px_payload, ':');
    if (d) {
        d += 1; // point after :
        if (!HMAC_Update(hmac, (unsigned char*)d, strlen(d))) {
            return 0;
        }
    }
    while (*signing_fields) {
        if (!HMAC_Update(hmac, (unsigned char*) *signing_fields, strlen(*signing_fields))) {
            return 0;
        }
        signing_fields++;
    }

    unsigned int len = buffer_len / 2;
    if (!HMAC_Final(hmac, hash, &len)) {
        return 0;
    }
    HMAC_CTX_free(hmac);

    for (unsigned int i = 0; i < len; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }

    return 1;
}

// create digest for payload, return 1 for success or 0 if an error occurred.
static int digest_payload(const risk_payload *payload, request_context *ctx, const char *payload_key, const char **signing_fields, char *buffer, int buffer_len) {
    if (ctx->px_payload_version == 3) {
        return digest_payload3(payload, ctx, payload_key, signing_fields, buffer, buffer_len);
    }
    return digest_payload1(payload, ctx, payload_key, signing_fields, buffer, buffer_len);
}

risk_payload *decode_payload(const char *px_payload, const char *payload_key, request_context *r_ctx) {
    px_config *conf = r_ctx->conf;
    char *px_payload_cpy = apr_pstrdup(r_ctx->r->pool, px_payload);
    char* saveptr;
    // extract hmac from payload for v3
    if (r_ctx->px_payload_version == 3) {
        char *payload_hmac = apr_strtok(px_payload_cpy, COOKIE_DELIMITER, &saveptr);
        if (payload_hmac == NULL) {
            px_log_debug("stoping payload decryption: no valid hmac for v3");
            return NULL;
        }
        r_ctx->px_payload_hmac = apr_pstrdup(r_ctx->r->pool, payload_hmac);
        px_log_debug_fmt("decode_payload: hmac for v3 is %s", r_ctx->px_payload_hmac);
        px_payload_cpy = NULL;
    }
    const char* encoded_salt = apr_strtok(px_payload_cpy, COOKIE_DELIMITER, &saveptr);
    if (encoded_salt == NULL) {
        px_log_debug("stoping payload decryption: no valid salt in payload");
        return NULL;
    }
    const char* iterations_str = apr_strtok(NULL, COOKIE_DELIMITER, &saveptr);
    if (iterations_str == NULL) {
        px_log_debug("no valid iterations in payload");
        return NULL;
    }
    int iterations = atoi(iterations_str);
    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        px_log_debug_fmt("number of iterations is illegal - %d", iterations);
        return NULL;
    }
    const char* encoded_payload = apr_strtok(NULL, COOKIE_DELIMITER, &saveptr);
    if (encoded_payload == NULL) {
        px_log_debug("stoping payload decryption: no valid encoded_payload in payload");
        return NULL;
    }
    // decode payload
    int payload_len = 0;
    unsigned char *payload = decode_base64(encoded_payload, &payload_len, r_ctx->r->pool);
    if (!payload) {
        px_log_debug("failed to base64 decode payload");
        return NULL;
    }

    // decode salt
    int salt_len = 0;
    unsigned char *salt = decode_base64(encoded_salt, &salt_len, r_ctx->r->pool);
    if (!salt) {
        px_log_debug("failed to base64 decode salt");
        return NULL;
    }

    // pbkdf2
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(r_ctx->r->pool, IV_LEN + KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(payload_key, strlen(payload_key), salt, salt_len, iterations, EVP_sha256(),  IV_LEN + KEY_LEN, pbdk2_out) == 0) {
        px_log_debug("PKCS5_PBKDF2_HMAC_SHA256 failed");
        return NULL;
    }
    unsigned char key[KEY_LEN];
    memcpy(&key, pbdk2_out, sizeof(key));

    unsigned char iv[IV_LEN];
    memcpy(&iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        px_log_debug("decryption failed in: Init");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_pcalloc(r_ctx->r->pool, payload_len + 1);
    int len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        px_log_debug("decryption failed in: Update");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        //ERR_print_errors_fp(stderr);
        px_log_debug("decryption failed in: Final");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    EVP_CIPHER_CTX_free(ctx);

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';
    r_ctx->px_payload_decrypted = (char *)dpayload;

    // parse payload string to risk struct
    risk_payload *c = parse_risk_payload(r_ctx->px_payload_decrypted, r_ctx);
    return c;
}

validation_result_t validate_payload(const risk_payload *payload, request_context *ctx, const char *payload_key) {
    px_config *conf = ctx->conf;
    if (payload == NULL) {
        px_log_debug("no _px payload");
        return VALIDATION_RESULT_NULL_PAYLOAD;
    }

    if (ctx->px_payload_hmac == NULL || strlen(ctx->px_payload_hmac) == 0) {
        px_log_debug("no hash");
        return VALIDATION_RESULT_NO_SIGNING;
    }

    struct timeval te;
    gettimeofday(&te, NULL);
    long long currenttime = te.tv_sec * 1000LL + te.tv_usec / 1000;
    if (currenttime > payload->ts) {
        long long age = currenttime - payload->ts;
        px_log_debug_fmt("Cookie TTL is expired, value: %s age: %lld", ctx->px_payload_decrypted, age);
        return VALIDATION_RESULT_EXPIRED;
    }

    char signature[HASH_LEN];
    const char *signing_fields_ua[] = { ctx->useragent, NULL };
    const char **signing_fields = (ctx->token_origin == TOKEN_ORIGIN_COOKIE) ? signing_fields_ua : SIGNING_NOFIELDS;
    if (!digest_payload(payload, ctx, payload_key, signing_fields, signature, HASH_LEN)) {
        px_log_debug_fmt("Cookie HMAC validation failed, value: %s user-agent: %s", ctx->px_payload_decrypted, ctx->useragent);
        return VALIDATION_RESULT_INVALID;
    }

    if (memcmp(signature, ctx->px_payload_hmac, 64) != 0) {
        px_log_debug_fmt("Cookie HMAC validation failed, value: %s user-agent: %s", ctx->px_payload_decrypted, ctx->useragent);
        return VALIDATION_RESULT_INVALID;
    }

    px_log_debug_fmt("Cookie evaluation ended successfully, risk score: %d", ctx->score);
    return VALIDATION_RESULT_VALID;
}
