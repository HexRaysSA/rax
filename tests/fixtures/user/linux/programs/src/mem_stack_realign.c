/*
 * mem_stack_realign.c
 *
 * Stack alignment and dynamic allocation patterns.
 * Stresses VLAs, alloca, and over-aligned locals.
 *
 * Features exercised:
 *   - Variable-length arrays
 *   - __builtin_alloca with manual alignment
 *   - Over-aligned local buffers
 *   - Mixed stack frame sizes
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile uint64_t sink;

__attribute__((noinline))
uint64_t stack_mix(uint32_t seed, uint32_t n) {
    _Alignas(32) uint8_t fixed[64];
    for (uint32_t i = 0; i < 64; i++) {
        fixed[i] = (uint8_t)(seed + i * 3u);
    }

    uint32_t len = (n & 0x3fu) + 1u;
    uint32_t vla[len];
    for (uint32_t i = 0; i < len; i++) {
        vla[i] = seed ^ (uint32_t)(i * 0x9e37u);
    }

    uint32_t dyn_size = len * 3u + 17u;
    uint8_t *raw = (uint8_t *)__builtin_alloca(dyn_size + 31u);
    uintptr_t aligned_addr = ((uintptr_t)raw + 31u) & ~(uintptr_t)31u;
    uint8_t *aligned = (uint8_t *)aligned_addr;

    for (uint32_t i = 0; i < dyn_size; i++) {
        aligned[i] = (uint8_t)(fixed[i & 63u] ^ (uint8_t)vla[i % len]);
    }

    uint64_t sum = 0;
    for (uint32_t i = 0; i < len; i++) {
        sum += vla[i];
    }
    for (uint32_t i = 0; i < dyn_size; i += 5u) {
        sum += aligned[i];
    }
    sum ^= (uint64_t)aligned[0] << 56;

    return sum;
}

int main(void) {
    uint64_t result = 0;

    for (uint32_t i = 1; i < 100; i++) { /* rax: was 2000 */
        result += stack_mix(i * 7u + 3u, i);
    }

    sink = result;
    printf("sink=%016" PRIx64 "\n", (uint64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
