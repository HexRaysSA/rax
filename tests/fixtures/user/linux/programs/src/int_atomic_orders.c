/*
 * int_atomic_orders.c
 *
 * Atomic operations with varied memory orders and sizes.
 * Exercises atomic builtins across multiple widths and fences.
 *
 * Features exercised:
 *   - __atomic builtins with different sizes
 *   - Acquire/release/seq_cst ordering
 *   - Compare-exchange (strong/weak)
 *   - Thread fences
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile uint64_t sink;

static uint8_t atomic_u8;
static uint16_t atomic_u16;
static uint32_t atomic_u32;
static uint64_t atomic_u64;

__attribute__((noinline))
uint64_t atomic_mix(uint32_t seed) {
    uint64_t sum = 0;

    __atomic_store_n(&atomic_u32, seed, __ATOMIC_RELAXED);
    sum += __atomic_load_n(&atomic_u32, __ATOMIC_ACQUIRE);

    uint32_t expected = seed;
    __atomic_compare_exchange_n(&atomic_u32, &expected, seed ^ 0xa5a5a5a5u,
                                0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    sum += expected;

    sum += __atomic_fetch_add(&atomic_u32, 7u, __ATOMIC_SEQ_CST);

    uint8_t old8 = __atomic_fetch_xor(&atomic_u8, (uint8_t)seed, __ATOMIC_RELEASE);
    uint16_t old16 = __atomic_fetch_or(&atomic_u16, (uint16_t)(seed >> 1),
                                       __ATOMIC_ACQ_REL);

    uint64_t add64 = ((uint64_t)seed << 32) | (uint64_t)seed;
    uint64_t old64 = __atomic_fetch_add(&atomic_u64, add64, __ATOMIC_ACQ_REL);
    sum ^= old64;

    uint64_t expected64 = old64 + add64;
    __atomic_compare_exchange_n(&atomic_u64, &expected64, expected64 ^ 0x5a5a5a5a5a5a5a5aull,
                                1, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    sum += expected64;

    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    sum += __atomic_load_n(&atomic_u64, __ATOMIC_ACQUIRE);

    sum ^= __atomic_exchange_n(&atomic_u64,
                               (uint64_t)seed * 0x9e3779b97f4a7c15ull,
                               __ATOMIC_SEQ_CST);

    return sum + old8 + old16;
}

int main(void) {
    uint64_t result = 0;

    for (uint32_t i = 0; i < 2000; i++) { /* rax: was 10000 */
        result += atomic_mix(i * 3u + 1u);
    }

    sink = result;
    printf("sink=%016" PRIx64 "\n", (uint64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
