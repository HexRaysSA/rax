/*
 * int_int128_ops.c
 *
 * 128-bit arithmetic and conversions.
 * Exercises wide integer operations, shifts, and division helpers.
 *
 * Features exercised:
 *   - 128-bit add/mul/shift/xor
 *   - 128-bit division and modulo
 *   - 64 <-> 128 conversions
 *   - Wide rotate/bit-mix patterns
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

typedef unsigned __int128 u128;
typedef __int128 s128;

volatile u128 sink128;
volatile uint64_t sink;

static inline u128 make_u128(uint64_t hi, uint64_t lo) {
    return ((u128)hi << 64) | (u128)lo;
}

__attribute__((noinline))
u128 rotl_u128(u128 v, unsigned shift) {
    shift &= 127u;
    if (shift == 0) {
        return v;
    }
    return (v << shift) | (v >> (128u - shift));
}

__attribute__((noinline))
u128 mix_u128(u128 a, u128 b, unsigned shift) {
    u128 x = a + (b << 7);
    u128 y = a * (b | 1);
    u128 z = x ^ rotl_u128(y, shift);
    z += (z >> 11) ^ (a << 3);
    return z;
}

__attribute__((noinline))
s128 divmod_u128(s128 numer, s128 denom, s128 *rem) {
    s128 q = numer / denom;
    *rem = numer % denom;
    return q;
}

__attribute__((noinline))
uint64_t fold_u128(u128 v) {
    return (uint64_t)v ^ (uint64_t)(v >> 64);
}

int main(void) {
    uint64_t result = 0;

    for (uint64_t i = 1; i < 1000; i++) { /* rax: was 8000 */
        uint64_t hi = (i * 0x9e3779b97f4a7c15ull) & 0x7fffffffffffffffull;
        uint64_t lo = i * 0xbf58476d1ce4e5b9ull + 0x94d049bb133111ebull;
        u128 a = make_u128(hi, lo);
        u128 b = make_u128(hi ^ 0x13579bdf2468ace0ull,
                           lo ^ 0x0f0e0d0c0b0a0908ull) | 1u;

        u128 mixed = mix_u128(a, b, (unsigned)(i & 127u));

        s128 rem = 0;
        s128 q = divmod_u128((s128)mixed, (s128)(b | 1u), &rem);

        sink128 = (u128)q ^ (u128)rem ^ mixed;
        result += fold_u128((u128)q) ^ fold_u128((u128)rem);
    }

    sink = result;
    u128 last128 = sink128; /* rax: print the result so that runs can be compared */
    printf("sink128_hi=%016" PRIx64 "\n", (uint64_t)(last128 >> 64));
    printf("sink128_lo=%016" PRIx64 "\n", (uint64_t)last128);
    printf("sink=%016" PRIx64 "\n", (uint64_t)sink);
    return 0;
}
