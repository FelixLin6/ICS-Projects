#ifndef CACHE_H
#define CACHE_H

#include <stdbool.h>
#include <stddef.h>

#ifndef MAX_CACHE_SIZE
#define MAX_CACHE_SIZE (1024 * 1024)
#endif
#ifndef MAX_OBJECT_SIZE
#define MAX_OBJECT_SIZE (100 * 1024)
#endif

struct entry;

typedef struct entry entry_t;

void init_cache(void);

void free_cache(void);

void free_entry(entry_t *e);

bool get(const char *url, char **object, size_t *size);

void put(const char *url, const char *object, size_t size);

#endif
