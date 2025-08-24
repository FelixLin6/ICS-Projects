/*
    Cache implemented with a doubly linked list. A mutex is used for correctness
   when running multiple threads concurrently. Url requets are used as keys for
   the cache. Evicts cache entres through an almost-LRU policy.
*/

#include "cache.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// Linked list node of cache. Contains the url made to request an object, the
// object, and the size of the object.
struct entry {
    char *url;
    char *obj;
    size_t size;

    struct entry *prev;
    struct entry *next;
};

// Struct for the cache linked list. Includes head, tail pointers, how much data
// is already in the cache (used) and a mutex lokck.
static struct {
    entry_t *head;
    entry_t *tail;
    size_t used;
    pthread_mutex_t lock;
} cache;

// Cache implemetation helper for removing a cache node
static void detach(entry_t *e) {
    if (e == NULL)
        return;
    if (e->prev)
        e->prev->next = e->next;
    if (e->next)
        e->next->prev = e->prev;
    if (cache.head == e)
        cache.head = e->next;
    if (cache.tail == e)
        cache.tail = e->prev;
    e->prev = NULL;
    e->next = NULL;
}

// Cache implemetation helper for adding a cache node to the head of the cache
static void push(entry_t *e) {
    e->next = cache.head;
    e->prev = NULL;
    if (cache.head)
        cache.head->prev = e;
    cache.head = e;
    if (!cache.tail)
        cache.tail = e;
}

// Given the size of a to-be-inserted cache entry, evict by LRU if there isn't
// enough space.
static void evict(size_t need) {
    while (need + cache.used > MAX_CACHE_SIZE && cache.tail) {
        entry_t *cand = cache.tail;
        detach(cand);
        cache.used -= cand->size;
        free_entry(cand);
    }
}

void init_cache(void) {
    cache.head = NULL;
    cache.tail = NULL;
    cache.used = 0;
    pthread_mutex_init(&cache.lock, NULL);
}

void free_entry(entry_t *e) {
    free(e->url);
    free(e->obj);
    free(e);
}

void free_cache(void) {
    pthread_mutex_lock(&cache.lock);
    entry_t *curr = cache.head;
    while (curr) {
        entry_t *next = curr->next;
        free_entry(curr);
        curr = next;
    }
    pthread_mutex_unlock(&cache.lock);
    pthread_mutex_destroy(&cache.lock);
}

// Look for an entry for a request in the cache. Returns whether the object was
// in cache. If it was, object will now hold a pointer to the objected
// associated with the url request
bool get(const char *url, char **object, size_t *size) {
    bool hit = false;
    pthread_mutex_lock(&cache.lock);
    for (entry_t *e = cache.head; e; e = e->next) {
        if (strcmp(e->url, url) == 0) {
            detach(e);
            push(e);

            *object = malloc(e->size);
            if (*object)
                memcpy(*object, e->obj, e->size);
            *size = e->size;
            hit = true;
            break;
        }
    }
    pthread_mutex_unlock(&cache.lock);
    return hit;
}

// Adds a new url-obj pair entry to the head of the cache. Insert at the head of
// the cache to support LRU eviction -- but evict only when theres not enough
// space left in the cache.
void put(const char *url, const char *object, size_t size) {
    if (size > MAX_OBJECT_SIZE)
        return;

    pthread_mutex_lock(&cache.lock);

    for (entry_t *e = cache.head; e; e = e->next) {
        if (strcmp(e->url, url) == 0) {
            detach(e);
            push(e);
            pthread_mutex_unlock(&cache.lock);
            return;
        }
    }

    pthread_mutex_unlock(&cache.lock);

    entry_t *e = malloc(sizeof(*e));
    if (e == NULL)
        return;

    e->url = strdup(url);
    e->obj = malloc(size);
    if (!e->url || !e->obj) {
        free_entry(e);
        return;
    }
    memcpy(e->obj, object, size);
    e->size = size;
    e->prev = NULL;
    e->next = NULL;

    pthread_mutex_lock(&cache.lock);
    evict(size);

    push(e);
    cache.used += size;
    pthread_mutex_unlock(&cache.lock);
}
