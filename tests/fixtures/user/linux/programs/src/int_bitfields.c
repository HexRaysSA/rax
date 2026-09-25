/*
 * int_bitfields.c
 *
 * Complex bitfield packing and extraction patterns.
 * Stresses sign extension, packed storage units, and zero-width alignment.
 *
 * Features exercised:
 *   - Packed bitfields across storage units
 *   - Signed/unsigned bitfield extraction and sign extension
 *   - Zero-width bitfields to force alignment
 *   - Volatile bitfield access
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile uint64_t sink;

typedef struct __attribute__((packed)) {
    unsigned int a:3;
    unsigned int b:5;
    unsigned int c:1;
    unsigned int :0;
    unsigned int d:17;
    signed int e:11;
    unsigned long long f:33;
    unsigned long long g:31;
} BitFieldA;

typedef struct __attribute__((packed)) {
    signed int s1:4;
    signed int s2:7;
    unsigned int u1:5;
    unsigned int u2:9;
    unsigned int :0;
    signed long long s3:20;
    unsigned long long u3:12;
} BitFieldB;

__attribute__((noinline))
uint64_t pack_fields(volatile BitFieldA *bf, uint32_t seed) {
    bf->a = seed & 0x7u;
    bf->b = (seed >> 3) & 0x1fu;
    bf->c = (seed >> 8) & 0x1u;
    bf->d = (seed * 3u) & 0x1ffffu;
    bf->e = (int)(seed & 0x7ffu) - 512;
    bf->f = ((unsigned long long)seed << 13) ^ 0x1ffffffffull;
    bf->g = (bf->f >> 1) & 0x7fffffffu;

    return (((uint64_t)bf->a) |
            ((uint64_t)bf->b << 3) |
            ((uint64_t)bf->c << 8) |
            ((uint64_t)bf->d << 9)) ^
           (uint64_t)bf->f;
}

__attribute__((noinline))
int64_t sign_fields(volatile BitFieldB *bf, int32_t seed) {
    uint32_t useed = (uint32_t)seed;
    int64_t s3 = ((int64_t)seed * 17);

    bf->s1 = (int)((useed & 0x7u) - 4u);
    bf->s2 = (int)(((useed >> 3) & 0x3fu) - 32u);
    bf->u1 = (unsigned int)((useed >> 1) & 0x1fu);
    bf->u2 = (unsigned int)((useed * 5u) & 0x1ffu);
    bf->s3 = (int)((s3 & 0xfffff) - 0x80000);
    bf->u3 = (unsigned int)((useed >> 2) & 0xfffu);

    return (int64_t)bf->s1 + (int64_t)bf->s2 +
           (int64_t)bf->u1 + (int64_t)bf->u2 +
           (int64_t)bf->s3 - (int64_t)bf->u3;
}

int main(void) {
    uint64_t result = 0;
    volatile BitFieldA a;
    volatile BitFieldB b;

    for (uint32_t i = 0; i < 600; i++) { /* rax: was 50000 */
        result += pack_fields(&a, i * 11u + 7u);
        result += (uint64_t)sign_fields(&b, (int32_t)i - 300); /* rax: was 25000 */
    }

    sink = result;
    printf("sink=%016" PRIx64 "\n", (uint64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
