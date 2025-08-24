/**
 * @file csim.c
 * @brief Contains a cache simulator that will simulate cache operations
 * on a cache with specified dimensions, then outputs effciency-related stats
 * including cache hits, misses, evictions, etc
 *
 * Main calls upon a parser, feeding it argc and argv. The parser will then
 * parse cache dimensions and the name of the trace file containing the sequence
 * of cache operations to be simulated -- from the commandline.
 *
 * The parser will enforce the following requirements on argument/behavior of
 * csim:
 * 1. Required flags in the commandline argument: s, b, E, and t
 * 2. If s and b are nonnegative realistically sized numbers, E is positive
 * 3. t is a file path that exists in the directory
 * 4. if -v is included csim articulates its cache operation traces step-by-step
 * 5. if -h is included or one or more required arguments were not provided,
 * csim prints usage manual to standard output
 * 6. csim prints final cache stats at the end.
 *
 * @author Felix Lin <felixl@andrew.cmu.edu>
 */

#include "cachelab.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LINELEN 30

// struct for storing cache dimensions and which file to be traced
typedef struct {
    unsigned long s;
    unsigned long b;
    unsigned long E;
    char tracefile[100];
} cache_t;

// Function that prints usage manual for csim when lacking arguments or -h
void printh(char *filename) {
    printf("Usage: %s [-v] -s <s> -E <E> -b <b> -t <trace>\n", filename);
    printf("       %s -h\n", filename);
    printf(" -h         Print this help message and exit\n");
    printf(
        " -v         Verbose mode: report effects of each memory operation\n");
    printf(" -s <s>     Number of set index bits (there are 2**s sets)\n");
    printf(" -b <b>     Number of block bits (there are 2**b blocks)\n");
    printf(" -E <E>     Number of lines per set ( associativity )\n");
    printf(" -t <trace> File name of the memory trace to process\n");
}

// Given commandline string, pointer to a struct for storing cache info, and
// pointer to boolean to store whether verbose mode is enabled, extracts
// requirement options from the commandline string and their arguments, enforces
// argument values conform to requirements, then stores arguments into the
// struct and whether verbose into the boolean.
int parse_cache(int argc, char **argv, cache_t *cache, bool *verbose) {
    bool s = false, E = false, b = false, t = false;
    char *end;

    for (int opt = getopt(argc, argv, "s:E:b:t:vh"); opt != -1;
         opt = getopt(argc, argv, "s:E:b:t:vh")) {
        switch (opt) {
        case 's':
            cache->s = strtoul(optarg, &end, 10);
            s = true;
            break;
        case 'E':
            cache->E = strtoul(optarg, &end, 10);
            E = true;
            break;
        case 'b':
            cache->b = strtoul(optarg, &end, 10);
            b = true;
            break;
        case 't':
            strncpy(cache->tracefile, optarg, sizeof(cache->tracefile) - 1);
            t = true;
            break;
        case 'v':
            *verbose = true;
            break;
        case 'h':
            printh(argv[0]);
            return 0;
        default:
            fprintf(stderr, "Unrecognized option '-%c'", opt);
            printh(argv[0]);
            return 1;
        }
    }

    if (!(s && E && b && t)) {
        fprintf(stderr, "Mandatory arguments missing or zero.\n");
        printh(argv[0]);
        return 1;
    }

    if (cache->s > 63 || cache->b > 63 || cache->s + cache->b > 63) {
        fprintf(stderr, "Error: s + b is too large (s = %lu, b = %lu)\n",
                cache->s, cache->b);
        return 1;
    }

    return 0;
}

// Struct for one line in cache
typedef struct {
    int valid;
    int dirty;
    unsigned long lru;
    unsigned long tag;
} line_t;

// Struct for one set in cache, including a pointer to line(s) in that set
typedef struct {
    line_t *lines;
} set_t;

// Given struct containting cache dimensions, pointer to the first set in a
// cache, an effiency-stats-tracking struct, boolean denoting whether verbose is
// enabled, char for the cache operation, the address of operation, and size of
// memory being operated on at addresse, conducts one load or a store operation
// based on LRU replacement policy.
void operate(cache_t *cache_info, set_t *cache, csim_stats_t *stats,
             bool verbose, char op, unsigned long addr, unsigned long size) {

    // Extract cache dimensions
    unsigned long s = cache_info->s;
    unsigned long b = cache_info->b;
    unsigned long E = cache_info->E;
    unsigned long tag = addr >> (s + b);

    // Find the correct set
    set_t *set = &cache[(addr >> b) & ((1UL << s) - 1)];

    bool hit = false;
    unsigned long evict = 0;
    unsigned long oldest_block = 0;
    bool open = false;
    unsigned long opening = 0;

    // Given we're in the correct set, loop through all entries (lines) in a set
    for (unsigned long i = 0; i < E; i++) {
        if (set->lines[i].valid) {
            if (set->lines[i].tag == tag) {
                hit = true;
                set->lines[i].lru = 0;
                if (op == 'S')
                    set->lines[i].dirty = 1;
            } else {
                // if not the line with our target tag, increment its LRU -- how
                // many opertions it has stayed in the cache for
                set->lines[i].lru++;
            }

            // If this is the oldest block we've seen so far in the loop, make
            // it the candidate for eviction
            if (set->lines[i].lru > oldest_block) {
                oldest_block = set->lines[i].lru;
                evict = i;
            }
        }

        // Since valid bit was 0, it hasnt been used yet; Thus, this line is
        // open and no need for eviction
        else if (!open) {
            open = true;
            opening = i;
        }
    }

    if (hit) {
        stats->hits++;
        if (verbose)
            printf("%c %lx,%lu hit\n", op, addr, size);
        return;
    }

    stats->misses++;
    if (verbose)
        printf("%c %lx,%lu miss", op, addr, size);

    unsigned long dest;
    if (open) {
        dest = opening;
    } else {
        stats->evictions++;
        // If about-to-be-evicted block is dirty, there are 2^b dirty bytes
        // about to be evicted, add it to stats tracker
        if (set->lines[evict].dirty)
            stats->dirty_evictions += (1UL << b);
        dest = evict;
        if (verbose)
            printf(" eviction");
    }
    if (verbose)
        printf("\n");

    set->lines[dest].valid = 1;
    set->lines[dest].tag = tag;
    // Reset LRU age since it was just moved into cache
    set->lines[dest].lru = 0;
    // Block would only be dirty if we brought it into cache to modify it -- 'S'
    if (op == 'S')
        set->lines[dest].dirty = 1;
    else {
        set->lines[dest].dirty = 0;
    }
    return;
}

// Given one line of trace from tracefile, parse the operator, address, and size
// from the string while checking argument value requirements
//
// Also given, struct for cache dimensions, the pointer to start of sets in
// cache, struct for cache stats, and whether verbose, but we are merely feeding
// these arguments into operate() along with the parsed op, addr, and size
int process_line(cache_t *cache_info, const char *linebuf, set_t *cache,
                 csim_stats_t *stats, bool verbose) {
    char tmp[LINELEN];
    strncpy(tmp, linebuf, LINELEN - 1);
    tmp[LINELEN - 1] = '\0';
    char *end;

    char *tok = strtok(tmp, " ");
    if (tok == NULL || (tok[0] != 'L' && tok[0] != 'S')) {
        fprintf(stderr, "Invalid operator: '%c'\n", tok[0]);
        return 1;
    }

    char op = tok[0];
    char *operands = strtok(NULL, " ");
    if (operands == NULL) {
        fprintf(stderr, "Missing operands\n");
        return 1;
    }

    char *addr_tok = strtok(operands, ",");
    char *size_tok = strtok(NULL, ",");

    if (!addr_tok) {
        fprintf(stderr, "Missing address/Space between addr and size\n");
        return 1;
    } else if (!size_tok) {
        fprintf(stderr, "Missing size/Space between addr and size\n");
        return 1;
    }

    unsigned long addr = strtoul(addr_tok, &end, 16);
    unsigned long size = strtoul(size_tok, &end, 10);

    if (size == 0) {
        fprintf(stderr, "Invalid size: %lu\n", size);
        return 1;
    }

    operate(cache_info, cache, stats, verbose, op, addr, size);
    return 0;
}

// First allocates a cache with s sets, then allocates E -- associativtiy --
// lines for each set. (all elements are 0-initialized)
set_t *alloc(unsigned long s, unsigned long E) {
    unsigned long S = 1UL << s;
    set_t *res = calloc(S, sizeof(set_t));
    if (!res) {
        fprintf(stderr, "Allocation failed for cache\n");
        exit(1);
    }
    for (unsigned long i = 0; i < S; i++) {
        res[i].lines = calloc(E, sizeof(line_t));
        if (!res[i].lines) {
            fprintf(stderr, "Allocation failed for set %lu\n", i);
            exit(1);
        }
    }
    return res;
}

// Given cache_info containting cache dimensions and location of trace file,
// opens trace file and feeds the file along with cache_info and other arguments
// into process_line, in a line-by-line manner. What is considered a "line"
// depends on the length of a line specified by the macro-defined constant
// LINELEN.
int process_trace(cache_t *cache_info, const char *tracefile, set_t *cache,
                  csim_stats_t *stats, bool verbose) {
    FILE *f = fopen(tracefile, "r");
    if (f == NULL) {
        fprintf(stderr, "Error opening trace file [%s]\n", tracefile);
        return 1;
    }

    char linebuf[LINELEN];
    int parse_error = 0;
    int line_number = 1;
    while (fgets(linebuf, LINELEN, f)) {
        if (linebuf[0] == '\n' || linebuf[0] == '\0')
            continue;
        if (strlen(linebuf) > LINELEN - 1) {
            fprintf(stderr, "Line %d too long\n", line_number);
            parse_error++;
        }
        if (process_line(cache_info, linebuf, cache, stats, verbose)) {
            fprintf(stderr, "Invalid operation on line %d\n", line_number);
            parse_error++;
        }
        line_number++;
    }

    // By this point, all cache operations in trace file has finished. Going
    // though each line in each set and sum the bytes of all lines marked dirty
    stats->dirty_bytes = 0;
    unsigned long S = 1UL << cache_info->s;
    for (unsigned long i = 0; i < S; i++) {
        for (unsigned long j = 0; j < cache_info->E; j++) {
            if (cache[i].lines[j].valid && cache[i].lines[j].dirty) {
                stats->dirty_bytes += (1UL << cache_info->b);
            }
        }
    }

    fclose(f);
    return parse_error;
}

// Frees a cache set-by-set, then frees the struct holding the sets
void free_cache(set_t *sets, unsigned long s) {
    unsigned long S = 1UL << s;
    for (unsigned long i = 0; i < S; i++) {
        free(sets[i].lines);
    }
    free(sets);
}

// Initializes struct for cache dimensions and info, the calls allocation of
// cache, and initializes stat-tracking struct, calls process trace and prints
// the resulting stats.
int main(int argc, char **argv) {
    cache_t cache = {0};
    bool verbose = false;
    if (parse_cache(argc, argv, &cache, &verbose))
        return 1;

    printf("s=%lu, E=%lu, b=%lu, tracefile=%s\n", cache.s, cache.E, cache.b,
           cache.tracefile);
    if (verbose)
        printf("(verbose enabled)\n");

    set_t *c = alloc(cache.s, cache.E);
    csim_stats_t stats = {0};

    if (process_trace(&cache, cache.tracefile, c, &stats, verbose))
        return 1;

    printSummary(&stats);
    free_cache(c, cache.s);

    return 0;
}
