#ifndef CURL_POOL_H
#define CURL_POOL_H

#include <stdbool.h>

#include <curl/curl.h>
#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

typedef struct curl_pool_t {
    apr_thread_mutex_t *mutex;
    apr_thread_cond_t *cond;
    int size;
    int used;
    CURL** data;
} curl_pool;

curl_pool *curl_pool_create(apr_pool_t *p, int size);
void curl_pool_destroy(curl_pool *pool);
CURL *curl_pool_get(curl_pool *pool);
CURL *curl_pool_get_wait(curl_pool *pool);
CURL *curl_pool_get_timedwait(curl_pool *pool, apr_interval_time_t timeout);
int curl_pool_put(curl_pool *pool, CURL *curl);

#endif /* CURL_POOL_H */
