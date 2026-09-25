/*
 * mem_tls.c
 *
 * Thread-local storage access patterns.
 * Exercises TLS data access and updates.
 *
 * Features exercised:
 *   - _Thread_local variables of multiple sizes
 *   - TLS access in loops and helper calls
 *   - Mixed TLS reads/writes and address taking
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile uint64_t sink;

_Thread_local uint32_t tls_counter;
_Thread_local uint64_t tls_accum;
_Thread_local uint8_t tls_bytes[13];

typedef struct {
    uint32_t a;
    uint16_t b;
    uint8_t c;
    uint8_t d;
} TlsBlock;

_Thread_local TlsBlock tls_block;
_Thread_local uint64_t tls_array[4];

__attribute__((noinline))
uint64_t tls_update(uint32_t seed) {
    uint32_t *ctr_ptr = &tls_counter;
    *ctr_ptr += seed + 1u;
    tls_accum ^= ((uint64_t)seed << 32) | (uint64_t)(*ctr_ptr);

    for (int i = 0; i < 13; i++) {
        tls_bytes[i] = (uint8_t)(tls_bytes[i] + seed + (uint32_t)i);
    }

    tls_block.a += seed ^ 0x5a5au;
    tls_block.b ^= (uint16_t)seed;
    tls_block.c = (uint8_t)(tls_block.c + 1u);
    tls_block.d = (uint8_t)(tls_block.d ^ (seed >> 3));

    tls_array[seed & 3u] ^= tls_accum;

    return tls_accum + tls_block.a + tls_block.b + tls_block.c + tls_block.d;
}

__attribute__((noinline))
uint64_t tls_fold(void) {
    uint64_t sum = tls_counter + tls_accum;
    for (int i = 0; i < 13; i++) {
        sum += tls_bytes[i];
    }
    for (int i = 0; i < 4; i++) {
        sum ^= tls_array[i];
    }
    sum += tls_block.a + tls_block.b + tls_block.c + tls_block.d;
    return sum;
}

int main(void) {
    uint64_t result = 0;

    for (uint32_t i = 0; i < 1000; i++) { /* rax: was 5000 */
        result += tls_update(i * 7u + 3u);
        if ((i & 31u) == 0u) {
            result ^= tls_fold();
        }
    }

    sink = result;
    printf("sink=%016" PRIx64 "\n", (uint64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
