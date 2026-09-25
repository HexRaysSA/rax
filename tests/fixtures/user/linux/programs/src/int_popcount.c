/*
 * Population Count and Bit Manipulation
 *
 * Counts set bits, leading/trailing zeros.
 * Uses both software and hardware (if available) implementations.
 *
 * Features exercised:
 *   - POPCNT instruction (x86, ARM)
 *   - CLZ/CTZ instructions
 *   - Bit manipulation patterns
 */

#include <stdint.h>
#include <stdio.h> /* rax: print the result so that runs can be compared */

volatile uint32_t sink;

/* Software popcount - naive */
static inline int popcount_naive(uint32_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

/* Software popcount - Brian Kernighan's algorithm */
static inline int popcount_kernighan(uint32_t x) {
    int count = 0;
    while (x) {
        x &= x - 1;  /* Clear least significant set bit */
        count++;
    }
    return count;
}

/* Software popcount - parallel */
static inline int popcount_parallel(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    x = x + (x >> 8);
    x = x + (x >> 16);
    return x & 0x3F;
}

/* Software popcount - lookup table */
static const uint8_t popcount_table[256] = {
    0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8
};

static inline int popcount_lookup(uint32_t x) {
    return popcount_table[x & 0xFF]
         + popcount_table[(x >> 8) & 0xFF]
         + popcount_table[(x >> 16) & 0xFF]
         + popcount_table[(x >> 24) & 0xFF];
}

/* 64-bit popcount */
static inline int popcount64_parallel(uint64_t x) {
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    x = x + (x >> 8);
    x = x + (x >> 16);
    x = x + (x >> 32);
    return (int)(x & 0x7F);
}

/* Count leading zeros (software) */
static inline int clz_soft(uint32_t x) {
    if (x == 0) return 32;

    int n = 0;
    if ((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF000000) == 0) { n += 8; x <<= 8; }
    if ((x & 0xF0000000) == 0) { n += 4; x <<= 4; }
    if ((x & 0xC0000000) == 0) { n += 2; x <<= 2; }
    if ((x & 0x80000000) == 0) { n += 1; }
    return n;
}

/* Count trailing zeros (software) */
static inline int ctz_soft(uint32_t x) {
    if (x == 0) return 32;

    int n = 0;
    if ((x & 0x0000FFFF) == 0) { n += 16; x >>= 16; }
    if ((x & 0x000000FF) == 0) { n += 8; x >>= 8; }
    if ((x & 0x0000000F) == 0) { n += 4; x >>= 4; }
    if ((x & 0x00000003) == 0) { n += 2; x >>= 2; }
    if ((x & 0x00000001) == 0) { n += 1; }
    return n;
}

/* Find first set bit (1-indexed, 0 if none) */
static inline int ffs_soft(uint32_t x) {
    if (x == 0) return 0;
    return ctz_soft(x) + 1;
}

/* Bit reversal */
static inline uint32_t bit_reverse(uint32_t x) {
    x = ((x & 0x55555555) << 1) | ((x & 0xAAAAAAAA) >> 1);
    x = ((x & 0x33333333) << 2) | ((x & 0xCCCCCCCC) >> 2);
    x = ((x & 0x0F0F0F0F) << 4) | ((x & 0xF0F0F0F0) >> 4);
    x = ((x & 0x00FF00FF) << 8) | ((x & 0xFF00FF00) >> 8);
    x = (x << 16) | (x >> 16);
    return x;
}

/* Byte swap */
static inline uint32_t byte_swap(uint32_t x) {
    return ((x >> 24) & 0x000000FF)
         | ((x >> 8)  & 0x0000FF00)
         | ((x << 8)  & 0x00FF0000)
         | ((x << 24) & 0xFF000000);
}

/* Parity (1 if odd number of bits set) */
static inline int parity(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}

/* Using compiler builtins when available */
#if defined(__GNUC__) || defined(__clang__)
#define BUILTIN_POPCOUNT(x) __builtin_popcount(x)
#define BUILTIN_CLZ(x) ((x) ? __builtin_clz(x) : 32)
#define BUILTIN_CTZ(x) ((x) ? __builtin_ctz(x) : 32)
#define BUILTIN_FFS(x) __builtin_ffs(x)
#define BUILTIN_PARITY(x) __builtin_parity(x)
#else
#define BUILTIN_POPCOUNT(x) popcount_parallel(x)
#define BUILTIN_CLZ(x) clz_soft(x)
#define BUILTIN_CTZ(x) ctz_soft(x)
#define BUILTIN_FFS(x) ffs_soft(x)
#define BUILTIN_PARITY(x) parity(x)
#endif

int main(void) {
    uint32_t checksum = 0;

    for (uint32_t iter = 0; iter < 1000; iter++) { /* rax: was 100000 */
        /* Generate test value */
        uint32_t x = iter * 0x9E3779B9;  /* Golden ratio hash */
        uint64_t x64 = ((uint64_t)x << 32) | (x ^ 0xDEADBEEF);

        /* Test various popcount implementations */
        int pc1 = popcount_naive(x);
        int pc2 = popcount_kernighan(x);
        int pc3 = popcount_parallel(x);
        int pc4 = popcount_lookup(x);
        int pc5 = BUILTIN_POPCOUNT(x);
        int pc6 = popcount64_parallel(x64);

        checksum += (uint32_t)(pc1 + pc2 + pc3 + pc4 + pc5 + pc6);

        /* Test CLZ/CTZ */
        int lz1 = clz_soft(x);
        int lz2 = BUILTIN_CLZ(x);
        int tz1 = ctz_soft(x);
        int tz2 = BUILTIN_CTZ(x);
        int ff = BUILTIN_FFS(x);

        checksum += (uint32_t)(lz1 + lz2 + tz1 + tz2 + ff);

        /* Test other operations */
        uint32_t rev = bit_reverse(x);
        uint32_t swp = byte_swap(x);
        int par = parity(x);
        int par2 = BUILTIN_PARITY(x);

        checksum ^= rev;
        checksum ^= swp;
        checksum += (uint32_t)(par + par2);
    }

    sink = checksum;
    printf("sink=%08x\n", (unsigned)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
