/**
 * @file mm.c
 * @brief A 64-bit struct-based implicit free list memory allocator
 *
 * 15-213: Introduction to Computer Systems
 *
 * A memory allocator that manages free blocks with an explicit free segregated
 *list (each doubly linked) and a singly linked list for exceptionally small
 *"miniblocks" (2 words). Finds a fit for a requested memory size via better-fit
 *-- where it uses best-fit for the first segregated list class that fits, then
 *first-fit for the larger classes. The minimum size for a regular block is 32
 *bytes (4 words). Allocated blocks and miniblocks are footerless. Free blocks
 *neighboring each other are coalesced together.
 *
 *************************************************************************
 *
 * ADVICE FOR STUDENTS.
 * - Step 0: Please read the writeup!
 * - Step 1: Write your heap checker.
 * - Step 2: Write contracts / debugging assert statements.
 * - Good luck, and have fun!
 *
 *************************************************************************
 *
 * @author Felix Lin <felixl@andrew.cmu.edu>
 */

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

/* Do not change the following! */

#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* def DRIVER */

/* You can change anything from here onward */

/*
 *****************************************************************************
 * If DEBUG is defined (such as when running mdriver-dbg), these macros      *
 * are enabled. You can use them to print debugging output and to check      *
 * contracts only in debug mode.                                             *
 *                                                                           *
 * Only debugging macros with names beginning "dbg_" are allowed.            *
 * You may not define any other macros having arguments.                     *
 *****************************************************************************
 */
#ifdef DEBUG
/* When DEBUG is defined, these form aliases to useful functions */
#define dbg_requires(expr) assert(expr)
#define dbg_assert(expr) assert(expr)
#define dbg_ensures(expr) assert(expr)
#define dbg_printf(...) ((void)printf(__VA_ARGS__))
#define dbg_printheap(...) print_heap(__VA_ARGS__)
#else
/* When DEBUG is not defined, these should emit no code whatsoever,
 * not even from evaluation of argument expressions.  However,
 * argument expressions should still be syntax-checked and should
 * count as uses of any variables involved.  This used to use a
 * straightforward hack involving sizeof(), but that can sometimes
 * provoke warnings about misuse of sizeof().  I _hope_ that this
 * newer, less straightforward hack will be more robust.
 * Hat tip to Stack Overflow poster chqrlie (see
 * https://stackoverflow.com/questions/72647780).
 */
#define dbg_discard_expr_(...) ((void)((0) && printf(__VA_ARGS__)))
#define dbg_requires(expr) dbg_discard_expr_("%d", !(expr))
#define dbg_assert(expr) dbg_discard_expr_("%d", !(expr))
#define dbg_ensures(expr) dbg_discard_expr_("%d", !(expr))
#define dbg_printf(...) dbg_discard_expr_(__VA_ARGS__)
#define dbg_printheap(...) ((void)((0) && print_heap(__VA_ARGS__)))
#endif

#define SEG_LEN 14

/* Basic constants */

typedef uint64_t word_t; // 8 bytes

/** @brief Word and header size (bytes) */
static const size_t wsize = sizeof(word_t); // 8 bytes

/** @brief Double word size (bytes) */
static const size_t dsize = 2 * wsize; // 16 bytes

/** @brief Minimum block size (bytes) */
static const size_t min_block_size = 2 * dsize; // 32 bytes (4 words)
static const size_t miniblock_size = dsize;

/**
 * The amount of memory first allocated into a free block when a heap is
 * initialized
 */
static const size_t chunksize = (1 << 12);

/**
 * A mask that isolates the allocation bit when &-ed with a block's header
 */
static const word_t alloc_mask = 0x1;

/**
 * A mask that isolates the prev-allocated bit when &-ed with a block's header
 */
static const word_t pa_mask = 0x2;

/**
 * A mask that isolates the prev-miniblock bit when &-ed with a block's header
 */
static const word_t pm_mask = 0x4;

/**
 * A mask that isolates the size bits when &-ed with a block's header
 */
static const word_t size_mask = ~(word_t)0xF;

/** @brief Represents the header and payload of one block in the heap */
typedef struct block {
    /** @brief Header contains size + allocation flag */
    word_t header;

    /**
     * @brief A pointer to the block payload.
     *
     * WARNING: A zero-length array must be the last element in a struct, so
     * there should not be any struct fields after it. For this lab, we will
     * allow you to include a zero-length array in a union, as long as the
     * union is the last field in its containing struct. However, this is
     * compiler-specific behavior and should be avoided in general.
     *
     * WARNING: DO NOT cast this pointer to/from other types! Instead, you
     * should use a union to alias this zero-length array with another struct,
     * in order to store additional types of data in the payload memory.
     */
    union {
        struct {
            struct block *prev;
            struct block *next;
        };
        struct block *next_mini;
        char payload[0];
    };

} block_t;

/* Global variables */

/** @brief Pointer to first block in the heap */
static block_t *heap_start = NULL;

/** @brief Pointer to an array of pointers to seglists of different size classes
 */
static block_t *seg_list[SEG_LEN] = {NULL};

/** @brief Pointer to the head of the miniblock singly linked list */
static block_t *minis = NULL;

/*
 *****************************************************************************
 * The functions below are short wrapper functions to perform                *
 * bit manipulation, pointer arithmetic, and other helper operations.        *
 *                                                                           *
 * We've given you the function header comments for the functions below      *
 * to help you understand how this baseline code works.                      *
 *                                                                           *
 * Note that these function header comments are short since the functions    *
 * they are describing are short as well; you will need to provide           *
 * adequate details for the functions that you write yourself!               *
 *****************************************************************************
 */

/*
 * ---------------------------------------------------------------------------
 *                        BEGIN SHORT HELPER FUNCTIONS
 * ---------------------------------------------------------------------------
 */

/*
 * Gets the prev-alloacted bit from a header
 */
static bool extract_pa(word_t header) {
    return (header & pa_mask) != 0;
}

/*
 * Sets the prev-alloacted bit for a block
 */
static void set_pa(block_t *block, bool pa) {
    if (pa)
        block->header |= pa_mask;
    else
        block->header &= (~pa_mask);
}

/*
 * Gets the prev-miniblock bit from a header
 */
static bool extract_pm(word_t header) {
    return (header & pm_mask) != 0;
}

/*
 * Sets the prev-miniblock bit for a block
 */
static void set_pm(block_t *block, bool pm) {
    if (pm)
        block->header |= pm_mask;
    else
        block->header &= (~pm_mask);
}

/**
 * @brief Returns the maximum of two integers.
 * @param[in] x
 * @param[in] y
 * @return `x` if `x > y`, and `y` otherwise.
 */
static size_t max(size_t x, size_t y) {
    return (x > y) ? x : y;
}

/**
 * @brief Rounds `size` up to next multiple of n
 * @param[in] size
 * @param[in] n
 * @return The size after rounding up
 */
static size_t round_up(size_t size, size_t n) {
    return n * ((size + (n - 1)) / n);
}

/**
 * @brief Packs the `size`, `alloc`, 'pa', and 'pm' of a block into a word
 * suitable for use as a packed value.
 *
 * The allocation status is packed into the lowest bit of the word.
 * Then pa into the second lowest, then pm third lowest
 *
 * @param[in] size The size of the block being represented
 * @param[in] alloc True if the block is allocated
 * @param[in] pa True if the previous block is allocated
 * @param[in] pm True if previous block is a miniblock
 * @return The packed value
 */
static word_t pack(size_t size, bool alloc, bool pa, bool pm) {
    word_t word = size;
    if (alloc)
        word |= alloc_mask;
    if (pa)
        word |= pa_mask;
    if (pm)
        word |= pm_mask;

    return word;
}

/**
 * @brief Extracts the size represented in a packed word.
 *
 * This function simply clears the lowest 4 bits of the word, as the heap
 * is 16-byte aligned.
 *
 * @param[in] word
 * @return The size of the block represented by the word
 */
static size_t extract_size(word_t word) {
    return (word & size_mask);
}

/**
 * @brief Extracts the size of a block from its header.
 * @param[in] block
 * @return The size of the block
 */
static size_t get_size(block_t *block) {
    return extract_size(block->header);
}

/**
 * @brief Given a payload pointer, returns a pointer to the corresponding
 *        block.
 * @param[in] bp A pointer to a block's payload
 * @return The corresponding block
 */
static block_t *payload_to_header(void *bp) {
    return (block_t *)((char *)bp - offsetof(block_t, payload));
}

/**
 * @brief Given a block pointer, returns a pointer to the corresponding
 *        payload.
 * @param[in] block
 * @return A pointer to the block's payload
 * @pre The block must be a valid block, not a boundary tag.
 */
static void *header_to_payload(block_t *block) {
    dbg_requires(get_size(block) != 0);
    return (void *)(block->payload);
}

/**
 * @brief Given a block pointer, returns a pointer to the corresponding
 *        footer.
 * @param[in] block
 * @return A pointer to the block's footer
 * @pre The block must be a valid block, not a boundary tag.
 */
static word_t *header_to_footer(block_t *block) {
    dbg_requires(get_size(block) != 0 &&
                 "Called header_to_footer on the epilogue block");
    return (word_t *)(block->payload + get_size(block) - dsize);
}

/**
 * @brief Given a block footer, returns a pointer to the corresponding
 *        header.
 * @param[in] footer A pointer to the block's footer
 * @return A pointer to the start of the block
 * @pre The footer must be the footer of a valid block, not a boundary tag.
 */
static block_t *footer_to_header(word_t *footer) {
    size_t size = extract_size(*footer);
    dbg_assert(size != 0 && "Called footer_to_header on the prologue block");
    return (block_t *)((char *)footer + wsize - size);
}

/**
 * @brief Returns the allocation status of a given header value.
 *
 * This is based on the lowest bit of the header value.
 *
 * @param[in] word
 * @return The allocation status correpsonding to the word
 */
static bool extract_alloc(word_t word) {
    return (bool)(word & alloc_mask);
}

/**
 * @brief Returns the allocation status of a block, based on its header.
 * @param[in] block
 * @return The allocation status of the block
 */
static bool get_alloc(block_t *block) {
    return extract_alloc(block->header);
}

/**
 * @brief Returns the payload size of a given block.
 *
 * The payload size is equal to the entire block size minus the sizes of the
 * block's header and footer.
 *
 * @param[in] block
 * @return The size of the block's payload
 */
static size_t get_payload_size(block_t *block) {
    size_t asize = get_size(block);

    if (get_alloc(block) || get_size(block) == dsize)
        return asize - wsize;
    return asize - dsize;
}

/**
 * @brief Writes an epilogue header at the given address.
 *
 * The epilogue header has size 0, and is marked as allocated.
 *
 * @param[out] block The location to write the epilogue header
 */
static void write_epilogue(block_t *block) {
    dbg_requires(block != NULL);
    dbg_requires((char *)block == (char *)mem_heap_hi() - 7);
    block->header =
        pack(0, true, extract_pa(block->header), extract_pm(block->header));
}

/**
 * @brief Finds the next consecutive block on the heap.
 *
 * This function accesses the next block in the "implicit list" of the heap
 * by adding the size of the block.
 *
 * @param[in] block A block in the heap
 * @return The next consecutive block on the heap
 * @pre The block is not the epilogue
 */
static block_t *find_next(block_t *block) {
    dbg_requires(block != NULL);
    dbg_requires(get_size(block) != 0 &&
                 "Called find_next on the last block in the heap");
    return (block_t *)((char *)block + get_size(block));
}

/**
 * @brief Writes a block starting at the given address.
 *
 * This function writes both a header and footer, where the location of the
 * footer is computed in relation to the header.
 *
 * PRECONDITIONS: 1. Block isnt NULL. 2. size > 0
 *
 * @param[out] block The location to begin writing the block header
 * @param[in] size The size of the new block
 * @param[in] alloc The allocation status of the new block
 */
static void write_block(block_t *block, size_t size, bool alloc) {
    dbg_requires(block != NULL);
    dbg_requires(size > 0);

    bool pa = extract_pa(block->header);
    bool pm = extract_pm(block->header);
    block->header = pack(size, alloc, pa, pm);

    if (!alloc && size != miniblock_size) {
        word_t *footer = header_to_footer(block);
        *footer = block->header;
    }

    block_t *next = find_next(block);
    set_pa(next, alloc);

    bool mini = size == miniblock_size;
    set_pm(next, mini);
}

/**
 * @brief Finds the footer of the previous block on the heap.
 * @param[in] block A block in the heap
 * @return The location of the previous block's footer
 */
static word_t *find_prev_footer(block_t *block) {
    // Compute previous footer position as one word before the header
    return &(block->header) - 1;
}

/**
 * @brief Finds the previous consecutive block on the heap.
 *
 * This is the previous block in the "implicit list" of the heap.
 *
 * If the function is called on the first block in the heap, NULL will be
 * returned, since the first block in the heap has no previous block!
 *
 * The position of the previous block is found by reading the previous
 * block's footer to determine its size, then calculating the start of the
 * previous block based on its size.
 *
 * @param[in] block A block in the heap
 * @return The previous consecutive block in the heap.
 */
static block_t *find_prev(block_t *block) {
    dbg_requires(block != NULL);

    if (extract_pa(block->header))
        return NULL;

    if (extract_pm(block->header))
        return (block_t *)((char *)block - miniblock_size);

    word_t *footerp = find_prev_footer(block);
    // Return NULL if called on first block in the heap
    if (extract_size(*footerp) == 0) {
        return NULL;
    }

    return footer_to_header(footerp);
}

// Finds size-class of a given size within the different segregated lists for
// different sized blocks
static int seg_index(size_t s) {
    if (s < min_block_size)
        return 0;
    else if (min_block_size <= s && s < min_block_size * 2)
        return 1;
    else if (min_block_size * 2 <= s && s < min_block_size * 4)
        return 2;
    else if (min_block_size * 4 <= s && s < min_block_size * 8)
        return 3;
    else if (min_block_size * 8 <= s && s < min_block_size * 16)
        return 4;
    else if (min_block_size * 16 <= s && s < min_block_size * 32)
        return 5;
    else if (min_block_size * 32 <= s && s < min_block_size * 64)
        return 6;
    else if (min_block_size * 64 <= s && s < min_block_size * 128)
        return 7;
    else if (min_block_size * 128 <= s && s < min_block_size * 256)
        return 8;
    else if (min_block_size * 256 <= s && s < min_block_size * 512)
        return 9;
    else if (min_block_size * 512 <= s && s < min_block_size * 1024)
        return 10;
    else if (min_block_size * 1028 <= s && s < min_block_size * 2048)
        return 11;
    else if (min_block_size * 2048 <= s && s < min_block_size * 4096)
        return 12;
    else
        return 13;
}

// Adds a miniblock to the minis singly linked list
static void add_mini(block_t *block) {
    dbg_requires(get_size(block) == miniblock_size);
    block->next_mini = minis;
    minis = block;
}

// Traverses the minis linked list to remove a particular miniblock
static void remove_mini(block_t *block) {
    if (block == minis) {
        minis = block->next_mini;
        return;
    }

    for (block_t *curr = minis; curr->next_mini; curr = curr->next_mini) {
        if (curr->next_mini == block) {
            curr->next_mini = block->next_mini;
            block->next_mini = NULL;
            return;
        }
    }
}

// Pops off the head miniblock of the minis linked list
static block_t *find_mini(void) {
    block_t *block = minis;
    if (block != NULL)
        minis = block->next_mini;
    return block;
}

/*
 * ---------------------------------------------------------------------------
 *                        END SHORT HELPER FUNCTIONS
 * ---------------------------------------------------------------------------
 */

/******** The remaining content below are helper and debug routines ********/

static void add_free(block_t *block) {

    int index = seg_index(get_size(block));

    block->prev = NULL;
    block->next = seg_list[index];
    if (seg_list[index])
        seg_list[index]->prev = block;
    seg_list[index] = block;
}

static void remove_free(block_t *block) {
    dbg_requires(!get_alloc(block));

    int index = seg_index(get_size(block));

    if (seg_list[index] == block) {
        if (block->next) {
            block->next->prev = NULL;
            seg_list[index] = block->next;
        } else
            seg_list[index] = NULL;
    }

    else {
        if (block->next) {
            block->prev->next = block->next;
            block->next->prev = block->prev;
        } else
            block->prev->next = NULL;
    }
}

/**
 * @brief
 *
 * Check a block's implicit list neighbors and combines it with those that are
 * free Takes the pointer to the block whose neighbors are checked. Returns the
 * final starting address of the block after it has been merged with all
 * merge-able neighbors. PRECONDITION: that the block is free POSTCONDITION: 1.
 * that the block is free. 2. that the resulting block size >= than the original
 * block size 3. the resulting block doesn't have any free neighbors
 *
 * @param[in] block
 * @return
 */
static block_t *coalesce_block(block_t *block) {
    dbg_requires(!get_alloc(block));

    block_t *prev;
    block_t *next = find_next(block);

    bool prev_alloc = extract_pa(block->header);
    bool next_alloc = get_alloc(next);

    if (prev_alloc)
        prev = NULL;
    else
        prev = find_prev(block);

    size_t size = get_size(block);

    if (!prev_alloc && next_alloc) {
        if (get_size(prev) == miniblock_size)
            remove_mini(prev);
        else
            remove_free(prev);

        size += get_size(prev);
        write_block(prev, size, false);
        block = prev;
    }

    else if (prev_alloc && !next_alloc) {
        if (get_size(next) == miniblock_size)
            remove_mini(next);
        else
            remove_free(next);

        size += get_size(next);
        write_block(block, size, false);
    }

    else if (!prev_alloc && !next_alloc) {
        if (get_size(prev) == miniblock_size)
            remove_mini(prev);
        else
            remove_free(prev);

        if (get_size(next) == miniblock_size)
            remove_mini(next);
        else
            remove_free(next);

        size += get_size(prev) + get_size(next);
        write_block(prev, size, false);
        block = prev;
    }

    if (size == miniblock_size)
        add_mini(block);
    else
        add_free(block);
    return block;
}

/**
 * @brief
 *
 * Extends the heap when there are no usable memory left on the heap
 * Takes the amount, bytes, the heap should be raised by
 * Returns the newly added memory as a free block (coalesced with the last block
 * on the implicit list, if possible) PRECONDITOINS: that size >= 0
 *
 * @param[in] size
 * @return
 */
static block_t *extend_heap(size_t size) {
    void *bp;

    // Allocate an even number of words to maintain alignment
    size = round_up(size, dsize);
    if ((bp = mem_sbrk((intptr_t)size)) == (void *)-1) {
        return NULL;
    }

    // Initialize free block header/footer
    block_t *block = payload_to_header(bp);
    write_block(block, size, false);

    // Create new epilogue header
    block_t *block_next = find_next(block);
    write_epilogue(block_next);

    // Coalesce in case the previous block was free
    block = coalesce_block(block);

    return block;
}

/**
 * @brief
 *
 * Split the block into a allocated head and a free tail (if the unused space
 * within the block is big enough to be a mini block or regular block) Takes a
 * block to be split, and how much data, in bytes, occupies said block. Returns
 * void. PRECONDITIONS: 1. that block is allocated. 2. that asize <=
 * get_size(block) POSTCONDITIONS: 1. that get_size(block) <= starting size of
 * that block. 2. that block is still allocated.
 *
 * @param[in] block
 * @param[in] asize
 */
static void split_block(block_t *block, size_t asize) {
    dbg_requires(get_alloc(block));

    size_t block_size = get_size(block);
    size_t diff = block_size - asize;

    if (diff >= min_block_size) {
        write_block(block, asize, true);

        block_t *free_tail = find_next(block);
        write_block(free_tail, diff, false);

        add_free(free_tail);
    }

    else if (diff == miniblock_size) {
        write_block(block, asize, true);
        block_t *mini_tail = find_next(block);
        write_block(mini_tail, diff, false);
        add_mini(mini_tail);
    }

    dbg_ensures(get_alloc(block));
}

/**
 * @brief

 * Conducts a better-fit search for a block of a given size in the segregated
 lists
 * Takes in the size of block we are looking for
 * Returns the pointer to a block that fits the size
 *
 * PRECONDITIONS: asize >= min_block_size (4 words)
 *
 * @param[in] asize
 * @return
 */
static block_t *find_fit(size_t asize) {
    dbg_requires(min_block_size <= asize);

    int index = seg_index(asize);
    size_t best_size = SIZE_MAX;
    block_t *best = NULL;

    // Best fit for first seg list
    for (block_t *block = seg_list[index]; block; block = block->next) {
        size_t block_size = get_size(block);

        if (block_size >= asize && block_size < best_size) {
            best_size = block_size;
            best = block;

            if (best_size == asize)
                return best;
        }
    }

    if (best)
        return best;

    // First fit for the higher size class seg lists
    for (int i = index + 1; i < SEG_LEN; i++) {
        for (block_t *block = seg_list[i]; block; block = block->next) {
            if (get_size(block) >= asize) {
                return block;
            }
        }
    }

    return NULL;
}

/**
 * @brief
 *
 * Traverses the entire heap through the implicit list of allocated and free
 * block. For each block, checks the alignment to 16 bytes, that the size is at
 * least that of a miniblock, and checks the pa and pm bits of the next block
 * based on the allocation and miniblock status of the current one. Takes in the
 * line number on which the function is called POSTCONDITION: mm_checkheap(line)
 * @param[in] line
 * @return
 */
bool mm_checkheap(int line) {
    // dbg_printf("Heap Checker called at line %d\n", line);
    if (!heap_start)
        return true;

    unsigned int frees = 0;
    for (block_t *block = heap_start; get_size(block) != 0;
         block = find_next(block)) {
        size_t size = get_size(block);
        bool alloc = get_alloc(block);

        if (((uintptr_t)block - wsize) % dsize != 0) {
            dbg_printf("Error: block not aligned at %p\n", (void *)block);
            return false;
        }

        if (size < miniblock_size) {
            dbg_printf("Error: block too small at %p (size=%zu)\n",
                       (void *)block, size);
            return false;
        }

        if (!alloc && size != miniblock_size) {
            word_t *ftr = header_to_footer(block);
            if (*ftr != block->header) {
                dbg_printf("Error: header/footer mismatch at %p\n",
                           (void *)block);
                return false;
            }
            frees++;
        }

        block_t *next = find_next(block);
        bool expected_pa = alloc;
        bool expected_pm = (!alloc && size == miniblock_size);
        if (extract_pa(next->header) != expected_pa) {
            dbg_printf("Error: PA bit wrong at %p (from %p)\n", (void *)next,
                       (void *)block);
            return false;
        }
        if (extract_pm(next->header) != expected_pm) {
            dbg_printf("Error: PM bit wrong at %p (from %p)\n", (void *)next,
                       (void *)block);
            return false;
        }

        bool next_alloc = get_size(next) == 0 ? true : get_alloc(next);
        if (!alloc && !next_alloc && get_size(next) > 0) {
            dbg_printf("Error: two frees in a row at %p and %p\n",
                       (void *)block, (void *)next);
            return false;
        }
    }

    return true;
}

/**
 * @brief
 *
 * NULL-initializes the seglist heads and the head of the miniblock list
 * First, raises the heap break point and writes two allocated blocks with size
 * zero -- prologue and epilogue Then, calls extend heap to add chunksize amount
 * of space to the heap. Returns NULL if heap extension fails.
 * @return
 */
bool mm_init(void) {
    // Create the initial empty heap
    for (int i = 0; i < SEG_LEN; i++) {
        seg_list[i] = NULL;
    }

    minis = NULL;

    word_t *start = (word_t *)(mem_sbrk(2 * wsize));

    if (start == (void *)-1) {
        return false;
    }

    start[0] = pack(0, true, true, true); // Heap prologue (block footer)
    start[1] = pack(0, true, true, true); // Heap epilogue (block header)

    // Heap starts with first "block header", currently the epilogue
    heap_start = (block_t *)&(start[1]);

    // Extend the empty heap with a free block of chunksize bytes

    if (extend_heap(chunksize) == NULL) {
        return false;
    }

    dbg_ensures(mm_checkheap(__LINE__));
    return true;
}

/**
 * @brief
 *
 * Looks for a block greater than or equal to the requested amount of memory on
 * the heap. If no such blocks exist, extends the heap. Returns the pointer to
 * the block of memory, or NULL if both there exists no apt blocks and heap
 * extention fails.
 *
 * @param[in] size
 * @return
 */
void *malloc(size_t size) {
    dbg_requires(mm_checkheap(__LINE__));

    size_t asize;      // Adjusted block size
    size_t extendsize; // Amount to extend heap if no fit is found
    block_t *block;
    void *bp = NULL;

    // Initialize heap if it isn't initialized
    if (heap_start == NULL) {
        if (!(mm_init())) {
            dbg_printf("Problem initializing heap. Likely due to sbrk");
            return NULL;
        }
    }

    // Ignore spurious request
    if (size == 0) {
        dbg_ensures(mm_checkheap(__LINE__));
        return bp;
    }

    // Adjust block size to include overhead and to meet alignment requirements
    asize = round_up(size + wsize, dsize);

    if (asize == miniblock_size) {
        block_t *res = find_mini();
        if (res != NULL) {
            write_block(res, miniblock_size, true);
            return header_to_payload(res);
        }
    }

    size_t look_size = max(asize, min_block_size);

    // Search the free list for a fit
    block = find_fit(look_size);

    // If no fit is found, request more memory, and then and place the block
    if (block == NULL) {
        // Always request at least chunksize
        extendsize = max(asize, chunksize);
        block = extend_heap(extendsize);
        // extend_heap returns an error
        if (block == NULL) {
            return bp;
        }
    }

    // The block should be marked as free
    dbg_assert(!get_alloc(block));

    // Mark block as allocated
    size_t block_size = get_size(block);
    remove_free(block);
    write_block(block, block_size, true);

    // Try to split the block if too large
    split_block(block, asize);
    dbg_printf("Actual size: %lu\n", asize);

    bp = header_to_payload(block);

    dbg_ensures(mm_checkheap(__LINE__));
    return bp;
}

/**
 * @brief
 *
 * Marks an allocated block as free, merges the block with neighboring free
 * blocks, then adds it to the correct list (segregated or mini) based on its
 * size PRECONDITION: bp has to be an allocated block POSTCONDITION: bp is a
 * free block
 *
 * @param[in] bp
 */
void free(void *bp) {
    dbg_requires(mm_checkheap(__LINE__));

    if (bp == NULL) {
        return;
    }

    block_t *block = payload_to_header(bp);
    size_t size = get_size(block);

    // The block should be marked as allocated
    dbg_assert(get_alloc(block));

    // Mark the block as free
    write_block(block, size, false);

    // Try to coalesce the block with its neighbors
    coalesce_block(block);

    dbg_ensures(mm_checkheap(__LINE__));
}

/**
 * @brief
 *
 * Takes a block of memory and a new desired size for that memory, and allocates
 * a block of size elsewhere. Moves information in the inputted block into the
 * newly allocated one. Then frees the old block. PRECONDITION: ptr is an
 * allocated block POSTCONDITION: ptr is a free block and newptr is allocated
 * @param[in] ptr
 * @param[in] size
 * @return Returns a pointer to the new block
 */
void *realloc(void *ptr, size_t size) {
    block_t *block = payload_to_header(ptr);
    size_t copysize;
    void *newptr;

    // If size == 0, then free block and return NULL
    if (size == 0) {
        free(ptr);
        return NULL;
    }

    // If ptr is NULL, then equivalent to malloc
    if (ptr == NULL) {
        return malloc(size);
    }

    // Otherwise, proceed with reallocation
    newptr = malloc(size);

    // If malloc fails, the original block is left untouched
    if (newptr == NULL) {
        return NULL;
    }

    // Copy the old data
    copysize = get_payload_size(block); // gets size of old payload
    if (size < copysize) {
        copysize = size;
    }
    memcpy(newptr, ptr, copysize);

    // Free the old block
    free(ptr);

    dbg_ensures(mm_checkheap(__LINE__));
    return newptr;
}

/**
 * @brief
 *
 * Given a size and number of elements, allocates a 0-initialized block of
 * memory that is the size of size * elements POSTCONDITION: bp is allocated
 *
 * @param[in] elements
 * @param[in] size
 * @return
 */
void *calloc(size_t elements, size_t size) {
    void *bp;
    size_t asize = elements * size;

    if (elements == 0) {
        return NULL;
    }
    if (asize / elements != size) {
        // Multiplication overflowed
        return NULL;
    }

    bp = malloc(asize);
    if (bp == NULL) {
        return NULL;
    }

    // Initialize all bits to 0
    memset(bp, 0, asize);

    dbg_ensures(mm_checkheap(__LINE__));
    return bp;
}

/*
 *****************************************************************************
 * Do not delete the following super-secret(tm) lines!                       *
 *                                                                           *
 * 53 6f 20 79 6f 75 27 72 65 20 74 72 79 69 6e 67 20 74 6f 20               *
 *                                                                           *
 * 66 69 67 75 72 65 20 6f 75 74 20 77 68 61 74 20 74 68 65 20               *
 * 68 65 78 61 64 65 63 69 6d 61 6c 20 64 69 67 69 74 73 20 64               *
 * 6f 2e 2e 2e 20 68 61 68 61 68 61 21 20 41 53 43 49 49 20 69               *
 *                                                                           *
 * 73 6e 27 74 20 74 68 65 20 72 69 67 68 74 20 65 6e 63 6f 64               *
 * 69 6e 67 21 20 4e 69 63 65 20 74 72 79 2c 20 74 68 6f 75 67               *
 * 68 21 20 2d 44 72 2e 20 45 76 69 6c 0a c5 7c fc 80 6e 57 0a               *
 *                                                                           *
 *****************************************************************************
 */
