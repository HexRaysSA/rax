/*
 * Portable SIMD Bitplane Transform
 *
 * Packs bytes into bitplanes, runs lane-wise bit mixing with portable compiler
 * vector extensions when available, and reconstructs a checksum. No target
 * specific flags or platform intrinsics are required.
 *
 * Features exercised:
 *   - Portable fixed-width vector operations
 *   - Scalar fallback for the same bitplane transform
 *   - Bit shifts, rotates, xor/or/and mixing
 *   - Byte packing and unpacking across bitplanes
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PIXELS 1024 /* rax: was 4096 */
#define LANES_PER_WORD 32
#define WORDS (PIXELS / LANES_PER_WORD)
#define PLANES 8
#define ROUNDS 32 /* rax: was 96 */

#if defined(__clang__) || defined(__GNUC__)
#define HAS_PORTABLE_VECTOR 1
typedef uint32_t u32x4 __attribute__((vector_size(16)));
#endif

volatile uint64_t sink;

static uint8_t pixels[PIXELS];
static uint8_t reconstructed[PIXELS];
static uint32_t planes[PLANES][WORDS];
static uint32_t work[PLANES][WORDS];

static uint32_t rotl32(uint32_t x, unsigned int bits) {
    return (x << bits) | (x >> (32u - bits));
}

static uint64_t mix64(uint64_t h, uint64_t v) {
    h ^= v + UINT64_C(0x9e3779b97f4a7c15) + (h << 6) + (h >> 2);
    h ^= h >> 31;
    h *= UINT64_C(0x7fb5d329728ea185);
    h ^= h >> 27;
    return h;
}

static void init_pixels(void) {
    uint32_t s = UINT32_C(0x13579bdf);

    for (int i = 0; i < PIXELS; i++) {
        s = s * UINT32_C(1103515245) + UINT32_C(12345);
        uint32_t a = (uint32_t)i * UINT32_C(37);
        uint32_t b = (uint32_t)(i >> 3) * UINT32_C(19);
        pixels[i] = (uint8_t)((s >> 23) ^ a ^ b ^ (uint32_t)(i * i));
    }
}

static void pack_bitplanes(const uint8_t *src, uint32_t dst[PLANES][WORDS]) {
    for (int p = 0; p < PLANES; p++) {
        for (int w = 0; w < WORDS; w++) {
            uint32_t bits = 0;
            int base = w * LANES_PER_WORD;

            for (int lane = 0; lane < LANES_PER_WORD; lane++) {
                uint32_t bit = (uint32_t)((src[base + lane] >> p) & 1u);
                bits |= bit << (unsigned int)lane;
            }

            dst[p][w] = bits;
        }
    }
}

static void unpack_bitplanes(const uint32_t src[PLANES][WORDS], uint8_t *dst) {
    for (int w = 0; w < WORDS; w++) {
        int base = w * LANES_PER_WORD;

        for (int lane = 0; lane < LANES_PER_WORD; lane++) {
            uint8_t value = 0;

            for (int p = 0; p < PLANES; p++) {
                uint32_t bit = (src[p][w] >> (unsigned int)lane) & 1u;
                value = (uint8_t)(value | (uint8_t)(bit << (unsigned int)p));
            }

            dst[base + lane] = value;
        }
    }
}

#if !defined(HAS_PORTABLE_VECTOR)
static void transform_scalar(uint32_t state[PLANES][WORDS], int round) {
    uint32_t round_key = UINT32_C(0x9e3779b9) ^ (uint32_t)round * UINT32_C(0x45d9f3b);

    for (int i = 0; i < WORDS; i++) {
        uint32_t p0 = state[0][i];
        uint32_t p1 = state[1][i];
        uint32_t p2 = state[2][i];
        uint32_t p3 = state[3][i];
        uint32_t p4 = state[4][i];
        uint32_t p5 = state[5][i];
        uint32_t p6 = state[6][i];
        uint32_t p7 = state[7][i];

        uint32_t lo = p0 ^ rotl32(p1, 1) ^ (p2 & rotl32(p3, 5));
        uint32_t hi = (p4 | p5) ^ (p6 + round_key) ^ rotl32(p7, 13);
        uint32_t cross = lo + (hi ^ (lo >> 3));
        uint32_t mask = rotl32(cross ^ p3 ^ round_key, 7);

        state[0][i] = lo ^ mask;
        state[1][i] = p2 ^ rotl32(cross, 11);
        state[2][i] = p3 + (hi & UINT32_C(0x0f0f0f0f));
        state[3][i] = p4 ^ rotl32(lo, 17);
        state[4][i] = hi + (mask | UINT32_C(0x01010101));
        state[5][i] = p6 ^ (cross >> 5) ^ round_key;
        state[6][i] = p7 + rotl32(mask, 3);
        state[7][i] = cross ^ rotl32(p0 + p5, 19);
    }
}
#endif

#if defined(HAS_PORTABLE_VECTOR)
static u32x4 load_u32x4(const uint32_t *src) {
    u32x4 value;
    memcpy(&value, src, sizeof(value));
    return value;
}

static void store_u32x4(uint32_t *dst, u32x4 value) {
    memcpy(dst, &value, sizeof(value));
}

static u32x4 rotl32x4(u32x4 x, unsigned int bits) {
    return (x << bits) | (x >> (32u - bits));
}

static void transform_vector(uint32_t state[PLANES][WORDS], int round) {
    uint32_t key_scalar = UINT32_C(0x9e3779b9) ^ (uint32_t)round * UINT32_C(0x45d9f3b);
    u32x4 round_key = { key_scalar, key_scalar, key_scalar, key_scalar };
    u32x4 low_mask = {
        UINT32_C(0x0f0f0f0f),
        UINT32_C(0x0f0f0f0f),
        UINT32_C(0x0f0f0f0f),
        UINT32_C(0x0f0f0f0f)
    };
    u32x4 byte_carry = {
        UINT32_C(0x01010101),
        UINT32_C(0x01010101),
        UINT32_C(0x01010101),
        UINT32_C(0x01010101)
    };

    for (int i = 0; i < WORDS; i += 4) {
        u32x4 p0 = load_u32x4(&state[0][i]);
        u32x4 p1 = load_u32x4(&state[1][i]);
        u32x4 p2 = load_u32x4(&state[2][i]);
        u32x4 p3 = load_u32x4(&state[3][i]);
        u32x4 p4 = load_u32x4(&state[4][i]);
        u32x4 p5 = load_u32x4(&state[5][i]);
        u32x4 p6 = load_u32x4(&state[6][i]);
        u32x4 p7 = load_u32x4(&state[7][i]);

        u32x4 lo = p0 ^ rotl32x4(p1, 1) ^ (p2 & rotl32x4(p3, 5));
        u32x4 hi = (p4 | p5) ^ (p6 + round_key) ^ rotl32x4(p7, 13);
        u32x4 cross = lo + (hi ^ (lo >> 3));
        u32x4 mask = rotl32x4(cross ^ p3 ^ round_key, 7);

        store_u32x4(&state[0][i], lo ^ mask);
        store_u32x4(&state[1][i], p2 ^ rotl32x4(cross, 11));
        store_u32x4(&state[2][i], p3 + (hi & low_mask));
        store_u32x4(&state[3][i], p4 ^ rotl32x4(lo, 17));
        store_u32x4(&state[4][i], hi + (mask | byte_carry));
        store_u32x4(&state[5][i], p6 ^ (cross >> 5) ^ round_key);
        store_u32x4(&state[6][i], p7 + rotl32x4(mask, 3));
        store_u32x4(&state[7][i], cross ^ rotl32x4(p0 + p5, 19));
    }
}
#endif

static uint64_t checksum_bytes(const uint8_t *data, int count) {
    uint64_t h = UINT64_C(0x626974706c616e65);

    for (int i = 0; i < count; i++) {
        h = mix64(h, (uint64_t)data[i] ^ ((uint64_t)(uint32_t)i << 8));
    }

    return h;
}

int main(void) {
    init_pixels();
    pack_bitplanes(pixels, planes);
    memcpy(work, planes, sizeof(work));

    for (int round = 0; round < ROUNDS; round++) {
#if defined(HAS_PORTABLE_VECTOR)
        transform_vector(work, round);
#else
        transform_scalar(work, round);
#endif
    }

    unpack_bitplanes((const uint32_t (*)[WORDS])work, reconstructed);

    uint64_t checksum = checksum_bytes(reconstructed, PIXELS);
    uint32_t edge = 0;
    for (int i = 0; i < WORDS; i += 7) {
        edge ^= work[i & 7][i];
        edge = rotl32(edge, 5) ^ work[(i + 3) & 7][WORDS - 1 - i];
    }

    sink = checksum ^ edge;
    printf("simd_portable_bitplane checksum=%016" PRIx64 " edge=%08" PRIx32 "\n", sink, edge);
    return 0;
}
