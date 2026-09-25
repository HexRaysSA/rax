/**
 * Custom Memory Allocator Implementation
 * =======================================
 * 
 * This file implements a free-list based memory allocator that manages a static
 * buffer of memory. This is similar to how malloc/free work internally, but
 * simplified for educational purposes.
 * 
 * KEY CONCEPTS:
 * 
 * 1. HEAP MANAGEMENT:
 *    - We use a large static buffer as our "heap" (1MB in this case)
 *    - The allocator manages this buffer, handing out chunks to callers
 *    - Unlike the real heap, our buffer has a fixed size
 * 
 * 2. BLOCK HEADERS:
 *    - Each allocated/free region has a header that stores metadata
 *    - Headers form a doubly-linked list for traversal
 *    - The header is placed immediately before the user's data
 * 
 * 3. FREE LIST:
 *    - We maintain a linked list of free blocks
 *    - When allocating, we search this list for a suitable block
 *    - When freeing, we add the block back to the free list
 * 
 * 4. FRAGMENTATION:
 *    - External fragmentation: free memory split into small non-contiguous chunks
 *    - We combat this with coalescing: merging adjacent free blocks
 * 
 * 5. ALLOCATION STRATEGIES:
 *    - First-fit: Use the first block that's large enough (our approach)
 *    - Best-fit: Use the smallest block that's large enough
 *    - Worst-fit: Use the largest available block
 * 
 * 6. ALIGNMENT:
 *    - CPUs access memory most efficiently at aligned addresses
 *    - We ensure all returned pointers are 8-byte aligned
 *    - This is crucial for performance and correctness on many architectures
 * 
 * Memory Layout:
 * 
 *    +----------------+------------------+----------------+------------------+
 *    | Block Header 1 | User Data 1      | Block Header 2 | User Data 2      |
 *    +----------------+------------------+----------------+------------------+
 *    ^                ^                  ^                ^
 *    |                |                  |                |
 *    Block start      Returned to user   Next block       Returned to user
 * 
 * Block Header Structure:
 * 
 *    +--------+----------+------+------+
 *    | size   | is_free  | next | prev |
 *    +--------+----------+------+------+
 *    
 *    size:    Total size of user data area (not including header)
 *    is_free: 1 if block is free, 0 if allocated
 *    next:    Pointer to next block in memory (not next free block)
 *    prev:    Pointer to previous block in memory
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * CONFIGURATION AND CONSTANTS
 * ============================================================================ */

/**
 * Total size of our heap buffer (1 MB)
 * In a real system, this would be obtained from the OS via brk() or mmap()
 */
#define HEAP_SIZE (1024 * 1024)

/**
 * Alignment requirement in bytes
 * Most modern systems require 8-byte alignment for optimal performance
 * This ensures pointers, doubles, and 64-bit integers are properly aligned
 */
#define ALIGNMENT 8

/**
 * Minimum block size for splitting
 * If the remainder after allocation is smaller than this, don't split
 * This prevents creating tiny unusable fragments
 */
#define MIN_BLOCK_SIZE 16

/**
 * Macro to align a size up to the nearest alignment boundary
 * 
 * How it works:
 * - (size + ALIGNMENT - 1) ensures we round up
 * - & ~(ALIGNMENT - 1) clears the lower bits to align down
 * 
 * Example with ALIGNMENT=8:
 * - size=1:  (1+7) & ~7 = 8 & ~7 = 8
 * - size=8:  (8+7) & ~7 = 15 & ~7 = 8
 * - size=9:  (9+7) & ~7 = 16 & ~7 = 16
 * - size=16: (16+7) & ~7 = 23 & ~7 = 16
 */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * Block Header Structure
 * 
 * This structure is placed at the beginning of each block (allocated or free).
 * It stores metadata needed to manage the memory.
 * 
 * The structure itself should be aligned, which is why we use size_t for size
 * (which is naturally aligned on most systems).
 * 
 * Memory layout for a single block:
 * 
 *    Low Address                                              High Address
 *    |                                                                   |
 *    v                                                                   v
 *    +------------------------------------------------------------------+
 *    | BlockHeader | Padding (if needed) | User Data Area               |
 *    +------------------------------------------------------------------+
 *    ^             ^                     ^
 *    |             |                     |
 *    Block start   Header end            Returned pointer (aligned)
 */
typedef struct BlockHeader {
    size_t size;                    /* Size of the user data area (not including header) */
    bool is_free;                   /* True if this block is free, false if allocated */
    struct BlockHeader *next;       /* Next block in memory (sequential, not free list) */
    struct BlockHeader *prev;       /* Previous block in memory */
} BlockHeader;

/**
 * Size of the block header, aligned to our alignment requirement
 * This ensures the user data area starts at an aligned address
 */
#define HEADER_SIZE ALIGN(sizeof(BlockHeader))

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

/**
 * The static heap buffer
 * This is our memory pool that we'll manage.
 * 
 * In a real allocator:
 * - This would be obtained from the OS via system calls
 * - brk()/sbrk() on Unix to extend the data segment
 * - mmap() for large allocations
 * - VirtualAlloc() on Windows
 * 
 * Using a static buffer means:
 * - Fixed maximum memory (can't grow)
 * - Simpler implementation (no OS interaction)
 * - Good for embedded systems or educational purposes
 */
static char heap[HEAP_SIZE];

/**
 * Pointer to the first block in our heap
 * This is our entry point into the block list
 */
static BlockHeader *heap_start = NULL;

/**
 * Statistics for debugging and analysis
 */
static struct {
    size_t total_allocations;       /* Number of successful allocations */
    size_t total_frees;             /* Number of successful frees */
    size_t total_bytes_allocated;   /* Current bytes in use */
    size_t peak_bytes_allocated;    /* Maximum bytes ever in use */
    size_t coalesce_count;          /* Number of coalesce operations performed */
    size_t split_count;             /* Number of block splits performed */
} stats = {0};

/* ============================================================================
 * INTERNAL HELPER FUNCTIONS
 * ============================================================================ */

/**
 * Initialize the heap
 * 
 * This function sets up the initial state of our heap. It creates a single
 * large free block that spans the entire heap buffer.
 * 
 * Called automatically on first allocation (lazy initialization).
 * 
 * Initial heap state:
 * 
 *    +------------------+------------------------------------------------+
 *    | BlockHeader      | Free space (HEAP_SIZE - HEADER_SIZE bytes)     |
 *    | size=...         |                                                |
 *    | is_free=true     |                                                |
 *    | next=NULL        |                                                |
 *    | prev=NULL        |                                                |
 *    +------------------+------------------------------------------------+
 */
static void heap_init(void) {
    /* 
     * Place the first block header at the start of the heap buffer
     * We cast the char array to our header type
     */
    heap_start = (BlockHeader *)heap;
    
    /*
     * Initialize the header:
     * - size: total heap minus the header itself
     * - is_free: true, since we haven't allocated anything yet
     * - next/prev: NULL, since this is the only block
     */
    heap_start->size = HEAP_SIZE - HEADER_SIZE;
    heap_start->is_free = true;
    heap_start->next = NULL;
    heap_start->prev = NULL;
    
    printf("[INIT] Heap initialized: %zu bytes total, %zu bytes usable\n",
           (size_t)HEAP_SIZE, heap_start->size);
}

/**
 * Get a pointer to the user data area from a block header
 * 
 * The user data immediately follows the header in memory.
 * We add HEADER_SIZE bytes to skip past the header.
 * 
 *    +------------------+------------------+
 *    | BlockHeader      | User Data        |
 *    +------------------+------------------+
 *    ^                  ^
 *    |                  |
 *    block              returned pointer
 */
static void *block_to_ptr(BlockHeader *block) {
    return (void *)((char *)block + HEADER_SIZE);
}

/**
 * Get the block header from a user data pointer
 * 
 * This is the inverse of block_to_ptr. Given a pointer that was
 * returned by my_malloc, find the corresponding header.
 * 
 *    +------------------+------------------+
 *    | BlockHeader      | User Data        |
 *    +------------------+------------------+
 *    ^                  ^
 *    |                  |
 *    returned pointer   ptr
 */
static BlockHeader *ptr_to_block(void *ptr) {
    return (BlockHeader *)((char *)ptr - HEADER_SIZE);
}

/**
 * Split a block if it's significantly larger than needed
 * 
 * When we find a free block that's larger than what was requested,
 * we can split it into two blocks:
 * 1. The allocated block (exactly the size requested)
 * 2. A new free block (the remainder)
 * 
 * This helps reduce internal fragmentation (wasted space within blocks).
 * 
 * Before split:
 *    +------------------+------------------------------------------------+
 *    | Header (free)    | Large free space                               |
 *    +------------------+------------------------------------------------+
 * 
 * After split:
 *    +------------------+-------------+------------------+---------------+
 *    | Header (alloc)   | User data   | Header (free)    | Free space    |
 *    +------------------+-------------+------------------+---------------+
 * 
 * @param block     The block to potentially split
 * @param size      The size actually needed (already aligned)
 */
static void split_block(BlockHeader *block, size_t size) {
    /*
     * Calculate remaining size after allocation
     * We need space for: requested size + new header
     */
    size_t remaining = block->size - size - HEADER_SIZE;
    
    /*
     * Only split if the remaining space is large enough to be useful
     * A tiny block would just waste space on its header
     */
    if (remaining < MIN_BLOCK_SIZE) {
        return; /* Don't split, give the user the whole block */
    }
    
    /*
     * Create the new free block after the allocated portion
     * 
     * Pointer arithmetic:
     * - Start at current block
     * - Skip header (HEADER_SIZE)
     * - Skip user data (size)
     * - That's where the new header goes
     */
    BlockHeader *new_block = (BlockHeader *)((char *)block + HEADER_SIZE + size);
    
    /* Initialize the new block's header */
    new_block->size = remaining;
    new_block->is_free = true;
    
    /*
     * Insert the new block into the linked list
     * 
     * Before: block <-> block->next
     * After:  block <-> new_block <-> block->next
     */
    new_block->next = block->next;
    new_block->prev = block;
    
    if (block->next != NULL) {
        block->next->prev = new_block;
    }
    block->next = new_block;
    
    /* Update the original block's size */
    block->size = size;
    
    stats.split_count++;
}

/**
 * Coalesce (merge) adjacent free blocks
 * 
 * When a block is freed, we check if its neighbors are also free.
 * If so, we merge them into a single larger block.
 * 
 * This combats external fragmentation, where we have enough total
 * free memory but it's split into chunks too small to use.
 * 
 * Example - freeing the middle block:
 * 
 * Before:
 *    +--------+--------+--------+--------+--------+
 *    | Free   | ALLOC  | FREE   | ALLOC  | Free   |
 *    +--------+--------+--------+--------+--------+
 *              ^
 *              Freeing this block
 * 
 * After coalescing with neighbors:
 *    +--------+------------------------+--------+
 *    | Free (merged)                   | ALLOC  | Free   |
 *    +--------+------------------------+--------+
 * 
 * @param block  The block that was just freed
 * @return       The resulting block after coalescing (may be different from input)
 */
static BlockHeader *coalesce(BlockHeader *block) {
    BlockHeader *result = block;
    
    /*
     * First, try to merge with the NEXT block
     * 
     * If the next block exists and is free, we absorb it:
     * - Add its size to ours (including its header, which becomes data space)
     * - Update our next pointer to skip over it
     */
    if (block->next != NULL && block->next->is_free) {
        /* 
         * New size = our size + next's header + next's size
         * The next block's header becomes part of our data area
         */
        block->size += HEADER_SIZE + block->next->size;
        
        /* Remove the next block from the list */
        block->next = block->next->next;
        if (block->next != NULL) {
            block->next->prev = block;
        }
        
        stats.coalesce_count++;
    }
    
    /*
     * Next, try to merge with the PREVIOUS block
     * 
     * If the previous block exists and is free, IT absorbs US:
     * - The previous block grows to include us
     * - We effectively disappear from the list
     */
    if (block->prev != NULL && block->prev->is_free) {
        /* Previous block absorbs us */
        block->prev->size += HEADER_SIZE + block->size;
        
        /* Remove us from the list */
        block->prev->next = block->next;
        if (block->next != NULL) {
            block->next->prev = block->prev;
        }
        
        /* Return the previous block as the result */
        result = block->prev;
        
        stats.coalesce_count++;
    }
    
    return result;
}

/**
 * Find a free block using first-fit strategy
 * 
 * First-fit searches the block list from the beginning and returns
 * the first block that is:
 * 1. Free (is_free == true)
 * 2. Large enough (size >= requested size)
 * 
 * Advantages of first-fit:
 * - Simple and fast (O(n) worst case, often faster)
 * - Tends to leave large blocks at the end of the heap
 * 
 * Disadvantages:
 * - Can cause fragmentation at the beginning of the heap
 * - May not find optimal fit
 * 
 * Alternatives:
 * - Best-fit: Find smallest adequate block (less waste, slower)
 * - Worst-fit: Find largest block (leaves medium blocks, can be bad)
 * - Next-fit: Like first-fit but start from last allocation
 * 
 * @param size  The size needed (already aligned)
 * @return      Pointer to a suitable block, or NULL if none found
 */
static BlockHeader *find_free_block(size_t size) {
    BlockHeader *current = heap_start;
    
    /*
     * Traverse the block list looking for a suitable block
     */
    while (current != NULL) {
        /*
         * Check if this block is:
         * 1. Free - not currently allocated
         * 2. Large enough - can hold the requested size
         */
        if (current->is_free && current->size >= size) {
            return current;
        }
        
        current = current->next;
    }
    
    /* No suitable block found - heap is full or too fragmented */
    return NULL;
}

/* ============================================================================
 * PUBLIC API FUNCTIONS
 * ============================================================================ */

/**
 * my_malloc - Allocate memory from the heap
 * 
 * This is our implementation of malloc(). It:
 * 1. Aligns the requested size
 * 2. Finds a suitable free block
 * 3. Optionally splits the block if it's too large
 * 4. Marks the block as allocated
 * 5. Returns a pointer to the user data area
 * 
 * @param size  Number of bytes to allocate
 * @return      Pointer to allocated memory, or NULL if allocation fails
 * 
 * Usage:
 *     int *arr = (int *)my_malloc(10 * sizeof(int));
 *     if (arr == NULL) {
 *         // Handle allocation failure
 *     }
 */
void *my_malloc(size_t size) {
    /* Handle edge case: zero-size allocation */
    if (size == 0) {
        return NULL;
    }
    
    /* Initialize heap on first use (lazy initialization) */
    if (heap_start == NULL) {
        heap_init();
    }
    
    /*
     * Align the requested size
     * 
     * This ensures:
     * 1. All allocations are properly aligned
     * 2. The next block header will also be aligned
     */
    size_t aligned_size = ALIGN(size);
    
    /*
     * Find a free block using first-fit strategy
     */
    BlockHeader *block = find_free_block(aligned_size);
    
    if (block == NULL) {
        /*
         * No suitable block found
         * 
         * In a real allocator, we would:
         * 1. Try to get more memory from the OS (sbrk/mmap)
         * 2. Return NULL if that fails too
         * 
         * Since we have a fixed buffer, we just return NULL
         */
        fprintf(stderr, "[MALLOC] Failed: no block of size %zu available\n", size);
        return NULL;
    }
    
    /*
     * Split the block if it's much larger than needed
     * This reduces internal fragmentation
     */
    split_block(block, aligned_size);
    
    /*
     * Mark the block as allocated
     */
    block->is_free = false;
    
    /*
     * Update statistics
     */
    stats.total_allocations++;
    stats.total_bytes_allocated += block->size;
    if (stats.total_bytes_allocated > stats.peak_bytes_allocated) {
        stats.peak_bytes_allocated = stats.total_bytes_allocated;
    }
    
    /*
     * Return pointer to the user data area (after the header)
     */
    return block_to_ptr(block);
}

/**
 * my_free - Release allocated memory back to the heap
 * 
 * This is our implementation of free(). It:
 * 1. Validates the pointer
 * 2. Marks the block as free
 * 3. Coalesces with adjacent free blocks
 * 
 * Important: Double-free and freeing invalid pointers are detected
 * and reported (in a real allocator, these would cause undefined behavior).
 * 
 * @param ptr  Pointer previously returned by my_malloc/my_calloc/my_realloc
 * 
 * Usage:
 *     my_free(arr);
 *     arr = NULL;  // Good practice to avoid dangling pointer
 */
void my_free(void *ptr) {
    /* Handle NULL pointer (free(NULL) is defined to do nothing) */
    if (ptr == NULL) {
        return;
    }
    
    /*
     * Validate that the pointer is within our heap
     * This catches some invalid free attempts
     */
    if ((char *)ptr < heap || (char *)ptr >= heap + HEAP_SIZE) {
        fprintf(stderr, "[FREE] Error: pointer %p is outside heap bounds\n", ptr);
        return;
    }
    
    /*
     * Get the block header from the user pointer
     */
    BlockHeader *block = ptr_to_block(ptr);
    
    /*
     * Check for double-free
     * Freeing an already-free block is a serious bug
     */
    if (block->is_free) {
        fprintf(stderr, "[FREE] Error: double free detected at %p\n", ptr);
        return;
    }
    
    /*
     * Update statistics
     */
    stats.total_frees++;
    stats.total_bytes_allocated -= block->size;
    
    /*
     * Mark the block as free
     */
    block->is_free = true;
    
    /*
     * Coalesce with adjacent free blocks
     * This is crucial for preventing fragmentation
     */
    coalesce(block);
}

/**
 * my_calloc - Allocate and zero-initialize memory
 * 
 * This is our implementation of calloc(). It:
 * 1. Calculates total size (num * size)
 * 2. Allocates memory using my_malloc
 * 3. Zeros out the allocated memory
 * 
 * The zeroing is important for security and correctness:
 * - Prevents information leaks from previous allocations
 * - Ensures predictable initial state
 * 
 * @param num   Number of elements to allocate
 * @param size  Size of each element
 * @return      Pointer to zeroed memory, or NULL on failure
 * 
 * Usage:
 *     int *arr = (int *)my_calloc(100, sizeof(int));
 *     // arr[0] through arr[99] are guaranteed to be 0
 */
void *my_calloc(size_t num, size_t size) {
    /*
     * Check for multiplication overflow
     * 
     * If num * size would overflow size_t, we'd allocate too little
     * memory, leading to buffer overflow vulnerabilities
     */
    if (num != 0 && size > SIZE_MAX / num) {
        fprintf(stderr, "[CALLOC] Error: size overflow (%zu * %zu)\n", num, size);
        return NULL;
    }
    
    size_t total_size = num * size;
    
    /*
     * Allocate the memory
     */
    void *ptr = my_malloc(total_size);
    
    if (ptr != NULL) {
        /*
         * Zero out the memory
         * memset is typically highly optimized for this
         */
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

/**
 * my_realloc - Resize an allocated block
 * 
 * This is our implementation of realloc(). It handles several cases:
 * 
 * 1. ptr == NULL: Equivalent to malloc(size)
 * 2. size == 0: Equivalent to free(ptr), returns NULL
 * 3. Shrinking: May split the block, returns same pointer
 * 4. Growing (fits in place): Returns same pointer
 * 5. Growing (doesn't fit): Allocate new, copy, free old
 * 
 * @param ptr   Pointer to previously allocated memory (or NULL)
 * @param size  New size in bytes
 * @return      Pointer to resized memory, or NULL on failure
 * 
 * Important: If realloc returns NULL (failure), the original block
 * is NOT freed. The caller must handle this to avoid memory leaks.
 * 
 * Usage:
 *     arr = (int *)my_realloc(arr, new_size);
 *     // DANGER: if realloc fails, we've lost the original pointer!
 *     
 *     // Safer pattern:
 *     int *new_arr = (int *)my_realloc(arr, new_size);
 *     if (new_arr != NULL) {
 *         arr = new_arr;
 *     } else {
 *         // Handle failure, arr is still valid
 *     }
 */
void *my_realloc(void *ptr, size_t size) {
    /*
     * Case 1: NULL pointer - equivalent to malloc
     */
    if (ptr == NULL) {
        return my_malloc(size);
    }
    
    /*
     * Case 2: Zero size - equivalent to free
     */
    if (size == 0) {
        my_free(ptr);
        return NULL;
    }
    
    /*
     * Get the block header
     */
    BlockHeader *block = ptr_to_block(ptr);
    size_t aligned_size = ALIGN(size);
    
    /*
     * Case 3: Block is already large enough
     * 
     * If shrinking or the block has enough space, we can reuse it.
     * We might split off excess space.
     */
    if (block->size >= aligned_size) {
        /*
         * Try to split if we're shrinking significantly
         * This returns excess space to the free pool
         */
        if (block->size >= aligned_size + HEADER_SIZE + MIN_BLOCK_SIZE) {
            /* Update statistics before split */
            stats.total_bytes_allocated -= block->size;
            split_block(block, aligned_size);
            stats.total_bytes_allocated += block->size;
            
            /* The new block created by split is already free, try to coalesce it */
            if (block->next != NULL && block->next->is_free) {
                coalesce(block->next);
            }
        }
        return ptr;
    }
    
    /*
     * Case 4: Check if we can expand into the next block
     * 
     * If the next block is free and combining would give us enough space,
     * we can expand in place without copying.
     */
    if (block->next != NULL && block->next->is_free) {
        size_t combined_size = block->size + HEADER_SIZE + block->next->size;
        
        if (combined_size >= aligned_size) {
            /* Update statistics */
            stats.total_bytes_allocated -= block->size;
            
            /* Absorb the next block */
            block->size = combined_size;
            block->next = block->next->next;
            if (block->next != NULL) {
                block->next->prev = block;
            }
            
            /* Split if we have excess */
            split_block(block, aligned_size);
            
            stats.total_bytes_allocated += block->size;
            stats.coalesce_count++;
            
            return ptr;
        }
    }
    
    /*
     * Case 5: Must relocate - allocate new block, copy data, free old
     * 
     * This is the slow path. We need to:
     * 1. Allocate a new block of the requested size
     * 2. Copy the old data to the new location
     * 3. Free the old block
     */
    void *new_ptr = my_malloc(size);
    
    if (new_ptr == NULL) {
        /* 
         * Allocation failed - return NULL but DON'T free the original
         * This matches standard realloc behavior
         */
        return NULL;
    }
    
    /*
     * Copy the old data to the new location
     * Only copy the minimum of old size and new size
     */
    size_t copy_size = (block->size < size) ? block->size : size;
    memcpy(new_ptr, ptr, copy_size);
    
    /*
     * Free the old block
     */
    my_free(ptr);
    
    return new_ptr;
}

/* ============================================================================
 * DEBUG AND DIAGNOSTIC FUNCTIONS
 * ============================================================================ */

/**
 * my_heap_dump - Print the current state of the heap
 * 
 * This function walks through all blocks (allocated and free) and
 * prints their status. Useful for debugging and understanding
 * heap behavior.
 * 
 * Output includes:
 * - Block number and address
 * - Size and status (FREE/USED)
 * - Visual representation of the heap
 */
void my_heap_dump(void) {
    if (heap_start == NULL) {
        printf("\n=== HEAP DUMP ===\n");
        printf("Heap not initialized\n");
        printf("=================\n\n");
        return;
    }
    
    printf("\n");
    printf("================================================================================\n");
    printf("                              HEAP DUMP                                         \n");
    printf("================================================================================\n");
    printf("\n");
    
    /* Print heap boundaries */
    printf("Heap range: %p - %p (%d bytes)\n", 
           (void *)heap, (void *)(heap + HEAP_SIZE), HEAP_SIZE);
    printf("Header size: %zu bytes\n", (size_t)HEADER_SIZE);
    printf("Alignment: %d bytes\n", ALIGNMENT);
    printf("\n");
    
    /* Walk through all blocks */
    BlockHeader *current = heap_start;
    int block_num = 0;
    size_t total_free = 0;
    size_t total_used = 0;
    size_t free_blocks = 0;
    size_t used_blocks = 0;
    size_t largest_free = 0;
    
    printf("Block List:\n");
    printf("---------------------------------------------------------------------------\n");
    printf(" #    Address            Size        Status    Data Range\n");
    printf("---------------------------------------------------------------------------\n");
    
    while (current != NULL) {
        void *data_start = block_to_ptr(current);
        void *data_end = (char *)data_start + current->size;
        
        printf("%3d   %p   %10zu   %s   %p - %p\n",
               block_num,
               (void *)current,
               current->size,
               current->is_free ? "FREE " : "USED ",
               data_start,
               data_end);
        
        /* Accumulate statistics */
        if (current->is_free) {
            total_free += current->size;
            free_blocks++;
            if (current->size > largest_free) {
                largest_free = current->size;
            }
        } else {
            total_used += current->size;
            used_blocks++;
        }
        
        current = current->next;
        block_num++;
    }
    
    printf("---------------------------------------------------------------------------\n");
    printf("\n");
    
    /* Print summary statistics */
    printf("Summary:\n");
    printf("  Total blocks:     %d\n", block_num);
    printf("  Used blocks:      %zu (%.1f%%)\n", 
           used_blocks, 
           block_num > 0 ? (100.0 * used_blocks / block_num) : 0.0);
    printf("  Free blocks:      %zu (%.1f%%)\n", 
           free_blocks,
           block_num > 0 ? (100.0 * free_blocks / block_num) : 0.0);
    printf("\n");
    printf("  Memory used:      %zu bytes\n", total_used);
    printf("  Memory free:      %zu bytes\n", total_free);
    printf("  Largest free:     %zu bytes\n", largest_free);
    printf("  Overhead:         %zu bytes (%d headers * %zu bytes)\n",
           (size_t)(block_num * HEADER_SIZE), block_num, (size_t)HEADER_SIZE);
    printf("\n");
    
    /* Print allocation statistics */
    printf("Allocation Statistics:\n");
    printf("  Total allocations: %zu\n", stats.total_allocations);
    printf("  Total frees:       %zu\n", stats.total_frees);
    printf("  Active allocations: %zu\n", stats.total_allocations - stats.total_frees);
    printf("  Peak memory:       %zu bytes\n", stats.peak_bytes_allocated);
    printf("  Coalesce ops:      %zu\n", stats.coalesce_count);
    printf("  Split ops:         %zu\n", stats.split_count);
    printf("\n");
    
    /* Visual representation of the heap */
    printf("Visual Heap Map (each char = ~%zu bytes):\n", (size_t)(HEAP_SIZE / 64));
    printf("[");
    
    current = heap_start;
    size_t position = 0;
    size_t chars_per_unit = HEAP_SIZE / 64;
    
    while (current != NULL) {
        size_t block_total = HEADER_SIZE + current->size;
        size_t chars_for_block = (block_total + chars_per_unit - 1) / chars_per_unit;
        if (chars_for_block == 0) chars_for_block = 1;
        
        char symbol = current->is_free ? '.' : '#';
        for (size_t i = 0; i < chars_for_block && position < 64; i++, position++) {
            putchar(symbol);
        }
        
        current = current->next;
    }
    
    /* Fill remaining space */
    while (position < 64) {
        putchar(' ');
        position++;
    }
    
    printf("]\n");
    printf("Legend: # = used, . = free\n");
    printf("\n");
    printf("================================================================================\n");
    printf("\n");
}

/* ============================================================================
 * STRESS TEST AND DEMONSTRATION
 * ============================================================================ */

/**
 * Stress test the allocator
 * 
 * This function performs various allocation patterns to test:
 * - Basic allocation/deallocation
 * - Fragmentation handling
 * - Coalescing effectiveness
 * - Realloc behavior
 * - Edge cases
 */
void stress_test(void) {
    printf("\n");
    printf("################################################################################\n");
    printf("#                         MEMORY ALLOCATOR STRESS TEST                         #\n");
    printf("################################################################################\n");
    printf("\n");
    
    /* -------------------------------------------------------------------------
     * Test 1: Basic allocation and deeing
     * ------------------------------------------------------------------------- */
    printf("=== TEST 1: Basic Allocation ===\n\n");
    
    printf("Allocating 3 blocks of different sizes...\n");
    void *p1 = my_malloc(100);
    void *p2 = my_malloc(200);
    void *p3 = my_malloc(300);
    
    printf("  p1 = %p (100 bytes)\n", p1);
    printf("  p2 = %p (200 bytes)\n", p2);
    printf("  p3 = %p (300 bytes)\n", p3);
    
    /* Write some data to verify memory works */
    if (p1) memset(p1, 'A', 100);
    if (p2) memset(p2, 'B', 200);
    if (p3) memset(p3, 'C', 300);
    
    my_heap_dump();
    
    /* -------------------------------------------------------------------------
     * Test 2: Free and coalesce
     * ------------------------------------------------------------------------- */
    printf("=== TEST 2: Free and Coalescing ===\n\n");
    
    printf("Freeing middle block (p2)...\n");
    my_free(p2);
    my_heap_dump();
    
    printf("Freeing first block (p1) - should coalesce with p2's space...\n");
    my_free(p1);
    my_heap_dump();
    
    printf("Freeing last block (p3) - should create one big free block...\n");
    my_free(p3);
    my_heap_dump();
    
    /* -------------------------------------------------------------------------
     * Test 3: Fragmentation stress test
     * ------------------------------------------------------------------------- */
    printf("=== TEST 3: Fragmentation Stress Test ===\n\n");
    
    printf("Allocating 10 blocks of 1000 bytes each...\n");
    void *blocks[10];
    for (int i = 0; i < 10; i++) {
        blocks[i] = my_malloc(1000);
        printf("  blocks[%d] = %p\n", i, blocks[i]);
    }
    
    my_heap_dump();
    
    printf("Freeing every other block (creating fragmentation)...\n");
    for (int i = 0; i < 10; i += 2) {
        printf("  Freeing blocks[%d]\n", i);
        my_free(blocks[i]);
        blocks[i] = NULL;
    }
    
    my_heap_dump();
    
    printf("Trying to allocate 3000 bytes (should fail - fragmented)...\n");
    void *big = my_malloc(3000);
    printf("  Result: %p %s\n", big, big ? "(success)" : "(failed as expected)");
    
    printf("\nFreeing remaining blocks...\n");
    for (int i = 1; i < 10; i += 2) {
        my_free(blocks[i]);
        blocks[i] = NULL;
    }
    
    my_heap_dump();
    
    printf("Now allocating 3000 bytes (should succeed - coalesced)...\n");
    big = my_malloc(3000);
    printf("  Result: %p %s\n", big, big ? "(success!)" : "(failed)");
    my_free(big);
    
    /* -------------------------------------------------------------------------
     * Test 4: Calloc test
     * ------------------------------------------------------------------------- */
    printf("\n=== TEST 4: Calloc (Zero-initialized allocation) ===\n\n");
    
    printf("Allocating array of 10 integers with calloc...\n");
    int *arr = (int *)my_calloc(10, sizeof(int));
    
    if (arr) {
        printf("  Checking if memory is zeroed: ");
        int all_zero = 1;
        for (int i = 0; i < 10; i++) {
            if (arr[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        printf("%s\n", all_zero ? "YES - all zeros!" : "NO - not zeroed!");
        my_free(arr);
    }
    
    /* -------------------------------------------------------------------------
     * Test 5: Realloc test
     * ------------------------------------------------------------------------- */
    printf("\n=== TEST 5: Realloc (Resize allocation) ===\n\n");
    
    printf("Initial allocation of 100 bytes...\n");
    char *str = (char *)my_malloc(100);
    if (str) {
        strcpy(str, "Hello, World!");
        printf("  Address: %p, Content: \"%s\"\n", (void *)str, str);
    }
    
    printf("\nGrowing to 200 bytes with realloc...\n");
    str = (char *)my_realloc(str, 200);
    if (str) {
        printf("  Address: %p, Content preserved: \"%s\"\n", (void *)str, str);
        strcat(str, " This is additional text after realloc.");
        printf("  After append: \"%s\"\n", str);
    }
    
    printf("\nShrinking to 50 bytes with realloc...\n");
    str = (char *)my_realloc(str, 50);
    if (str) {
        str[49] = '\0';  /* Ensure null termination */
        printf("  Address: %p, Content (truncated): \"%s\"\n", (void *)str, str);
    }
    
    my_free(str);
    
    /* -------------------------------------------------------------------------
     * Test 6: Edge cases
     * ------------------------------------------------------------------------- */
    printf("\n=== TEST 6: Edge Cases ===\n\n");
    
    printf("Testing malloc(0)...\n");
    void *zero = my_malloc(0);
    printf("  Result: %p (should be NULL)\n", zero);
    
    printf("\nTesting free(NULL)...\n");
    my_free(NULL);
    printf("  No crash - good!\n");
    
    printf("\nTesting realloc(NULL, 100) (should act like malloc)...\n");
    void *realloc_null = my_realloc(NULL, 100);
    printf("  Result: %p\n", realloc_null);
    my_free(realloc_null);
    
    printf("\nTesting realloc(ptr, 0) (should act like free)...\n");
    void *to_free = my_malloc(100);
    printf("  Allocated: %p\n", to_free);
    void *result = my_realloc(to_free, 0);
    printf("  After realloc(ptr, 0): %p (should be NULL)\n", result);
    
    /* -------------------------------------------------------------------------
     * Test 7: Many small allocations
     * ------------------------------------------------------------------------- */
    printf("\n=== TEST 7: Many Small Allocations ===\n\n");
    
    #define SMALL_ALLOC_COUNT 49 /* rax: was 100 */
    void *small_blocks[SMALL_ALLOC_COUNT];
    
    printf("Allocating %d small blocks (16-64 bytes each)...\n", SMALL_ALLOC_COUNT);
    for (int i = 0; i < SMALL_ALLOC_COUNT; i++) {
        size_t size = 16 + (i % 49);  /* 16 to 64 bytes */
        small_blocks[i] = my_malloc(size);
    }
    
    printf("  Allocated %d blocks\n", SMALL_ALLOC_COUNT);
    my_heap_dump();
    
    printf("Freeing all small blocks in random order...\n");
    /* Simple pseudo-random order using a known pattern */
    for (int i = 0; i < SMALL_ALLOC_COUNT; i++) {
        int idx = (i * 37) % SMALL_ALLOC_COUNT;  /* Simple scatter pattern */
        if (small_blocks[idx] != NULL) {
            my_free(small_blocks[idx]);
            small_blocks[idx] = NULL;
        }
    }
    
    printf("  All blocks freed\n");
    my_heap_dump();
    
    /* -------------------------------------------------------------------------
     * Final Summary
     * ------------------------------------------------------------------------- */
    printf("\n");
    printf("################################################################################\n");
    printf("#                           STRESS TEST COMPLETE                               #\n");
    printf("################################################################################\n");
    printf("\n");
    printf("Final Statistics:\n");
    printf("  Total allocations performed: %zu\n", stats.total_allocations);
    printf("  Total frees performed:       %zu\n", stats.total_frees);
    printf("  Peak memory usage:           %zu bytes\n", stats.peak_bytes_allocated);
    printf("  Coalescing operations:       %zu\n", stats.coalesce_count);
    printf("  Block splits:                %zu\n", stats.split_count);
    printf("\n");
    
    if (stats.total_allocations == stats.total_frees) {
        printf("SUCCESS: All allocated memory has been freed!\n");
    } else {
        printf("WARNING: Memory leak detected! %zu allocations not freed.\n",
               stats.total_allocations - stats.total_frees);
    }
    printf("\n");
}

/* ============================================================================
 * MAIN FUNCTION
 * ============================================================================ */

/**
 * Main entry point
 * 
 * Demonstrates the memory allocator with various tests
 */
int main(void) {
    printf("\n");
    printf("================================================================================\n");
    printf("       Custom Memory Allocator - Educational Implementation in C               \n");
    printf("================================================================================\n");
    printf("\n");
    printf("This program demonstrates a simple free-list based memory allocator.\n");
    printf("\n");
    printf("Features:\n");
    printf("  - Static 1MB heap buffer\n");
    printf("  - First-fit allocation strategy\n");
    printf("  - Block splitting to reduce internal fragmentation\n");
    printf("  - Coalescing to reduce external fragmentation\n");
    printf("  - 8-byte alignment for all allocations\n");
    printf("\n");
    
    /* Run the stress test */
    stress_test();
    
    /* Final heap state */
    printf("=== Final Heap State ===\n");
    my_heap_dump();
    
    return 0;
}
