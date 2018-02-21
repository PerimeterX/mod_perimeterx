#include "curl_pool.h"

static apr_status_t curl_pool_destroy(void *arg) {
    curl_pool *pool = (curl_pool*)arg;
    for (int i = 0; i < pool->size; ++i) {
        if (pool->data[i]) {
            curl_easy_cleanup(pool->data[i]);
            pool->data[i] = NULL;
        }
    }
    return APR_SUCCESS;
}

curl_pool *curl_pool_create(apr_pool_t *p, int size, bool reset) {
    curl_pool *pool = (curl_pool *)apr_pcalloc(p, sizeof(curl_pool));
    apr_thread_mutex_create(&pool->mutex, APR_THREAD_MUTEX_NESTED, p);
    apr_thread_cond_create(&pool->cond, p);
    pool->size = size;
    pool->used = 0;
    pool->data = (CURL **)apr_pcalloc(p, sizeof(CURL*) * size);
    pool->reset = reset;
    for (int i = 0; i < pool->size; ++i) {
        pool->data[i] = curl_easy_init();
    }
    apr_pool_cleanup_register(p, pool, curl_pool_destroy, apr_pool_cleanup_null);
    return pool;
}

CURL *curl_pool_get(curl_pool *pool) {
    CURL *c = NULL;
    apr_thread_mutex_lock(pool->mutex);
    if (pool->used < pool->size) {
        for (int i = 0; i < pool->size && c == NULL; ++i) {
            c = pool->data[i];
            if  (c) {
                pool->data[i] = NULL;
                pool->used += 1;
            }
        }
    }
    apr_thread_mutex_unlock(pool->mutex);
    return c;
}

CURL *curl_pool_get_wait(curl_pool *pool) {
    apr_thread_mutex_lock(pool->mutex);
    CURL *c = NULL;
    bool found = false;
    while (!found) {
        if (pool->used < pool->size) {
            for (int i = 0; i < pool->size && c == NULL; ++i) {
                c = pool->data[i];
                if  (c) {

                    pool->data[i] = NULL;
                    pool->used += 1;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            apr_thread_cond_wait(pool->cond, pool->mutex);
        }
    }
    apr_thread_mutex_unlock(pool->mutex);
    return c;
}

CURL *curl_pool_get_timedwait(curl_pool *pool, apr_interval_time_t timeout) {
    CURL *c = NULL;
    apr_thread_mutex_lock(pool->mutex);
    bool found = false;
    while (!found) {
        if (pool->used < pool->size) {
            for (int i = 0; i < pool->size && c == NULL; ++i) {
                c = pool->data[i];
                if  (c) {
                    pool->data[i] = NULL;
                    pool->used += 1;
                    found = true;
                    break;
                }
            }
        }
        if (!found && (apr_thread_cond_timedwait(pool->cond, pool->mutex, timeout) == APR_TIMEUP)) {
            break;
        }
    }
    apr_thread_mutex_unlock(pool->mutex);
    return c;
}

int curl_pool_put(curl_pool *pool, CURL *curl) {
    bool extra = true;
    apr_thread_mutex_lock(pool->mutex);
    if (pool->used > 0) {
        // find free spot
        int i = 0;
        while (i < pool->size && pool->data[i]) {
            ++i;
        }
        // put it back to pool
        if (i < pool->size) {
            pool->data[i] = curl;
            extra = false;
            pool->used -= 1;
            if (pool->reset) {
                curl_easy_reset(curl);
            }

            apr_thread_cond_signal(pool->cond);
        }
    }
    apr_thread_mutex_unlock(pool->mutex);
    // if we have extra, release it
    if (extra) {
        curl_easy_cleanup(curl);
        return 1;
    }
    return 0;
}

