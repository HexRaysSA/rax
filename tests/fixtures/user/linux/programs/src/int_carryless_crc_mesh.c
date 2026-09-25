// SPDX-License-Identifier: MIT
/*
 * int_carryless_crc_mesh.c
 *
 * Carryless GF(2)-style multiplication, CRC-like folding, and a bit-matrix
 * mesh. This is deterministic, bounded, and uses only integer operations.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define MESH_N 8u /* rax: was 16u */
#define ROUNDS 2u /* rax: was 96u */
#define GF_POLY UINT64_C(0x1b)

typedef struct {
    uint64_t lo;
    uint64_t hi;
} ClProduct;

typedef struct {
    uint64_t row[MESH_N];
} BitMatrix;

static uint64_t crc_table[256];
static uint64_t mesh[MESH_N][MESH_N];
static BitMatrix matrix_bank[4];

volatile uint64_t sink;

static uint64_t rotl64(uint64_t x, unsigned bits) {
    bits &= 63u;
    return bits == 0u ? x : ((x << bits) | (x >> (64u - bits)));
}

static uint64_t rotr64(uint64_t x, unsigned bits) {
    bits &= 63u;
    return bits == 0u ? x : ((x >> bits) | (x << (64u - bits)));
}

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 29;
    x *= UINT64_C(0xc4ceb9fe1a85ec53);
    return x ^ (x >> 32);
}

static uint64_t parity64(uint64_t x) {
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    return (UINT64_C(0x6996) >> (x & 15u)) & 1u;
}

static ClProduct clmul64(uint64_t a, uint64_t b) {
    ClProduct p = { 0u, 0u };

    for (unsigned bit = 0; bit < 64u; bit++) {
        if (((b >> bit) & 1u) != 0u) {
            if (bit == 0u) {
                p.lo ^= a;
            } else {
                p.lo ^= a << bit;
                p.hi ^= a >> (64u - bit);
            }
        }
    }

    return p;
}

static void toggle_product_bit(ClProduct *p, unsigned bit) {
    if (bit < 64u) {
        p->lo ^= UINT64_C(1) << bit;
    } else {
        p->hi ^= UINT64_C(1) << (bit - 64u);
    }
}

static uint64_t gf_reduce64(ClProduct p) {
    for (int bit = 127; bit >= 64; bit--) {
        unsigned high_bit = (unsigned)bit - 64u;

        if (((p.hi >> high_bit) & 1u) != 0u) {
            unsigned base = (unsigned)bit - 64u;

            toggle_product_bit(&p, (unsigned)bit);
            toggle_product_bit(&p, base);
            toggle_product_bit(&p, base + 1u);
            toggle_product_bit(&p, base + 3u);
            toggle_product_bit(&p, base + 4u);
        }
    }

    return p.lo;
}

__attribute__((noinline))
static uint64_t gf_mul64(uint64_t a, uint64_t b) {
    return gf_reduce64(clmul64(a, b));
}

static uint64_t crc64_fold(uint64_t crc, uint64_t word) {
    crc ^= word;
    for (unsigned i = 0; i < 8u; i++) {
        uint8_t idx = (uint8_t)crc;
        crc = (crc >> 8) ^ crc_table[idx] ^ rotl64(word, i * 7u + 3u);
        word = rotr64(word ^ crc, 11u);
    }
    return crc;
}

static uint64_t matrix_apply(const BitMatrix *matrix, uint64_t v) {
    uint64_t out = 0u;

    for (unsigned row = 0; row < MESH_N; row++) {
        uint64_t bit = parity64(matrix->row[row] & v);
        out |= bit << row;
    }

    return out | (v & UINT64_C(0xffffffffffff0000));
}

static void init_crc_table(void) {
    for (unsigned i = 0; i < 256u; i++) {
        uint64_t crc = i;

        for (unsigned bit = 0; bit < 8u; bit++) {
            uint64_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (UINT64_C(0xc96c5795d7870f42) & mask);
        }

        crc_table[i] = crc;
    }
}

static void init_matrices(void) {
    uint64_t seed = UINT64_C(0x243f6a8885a308d3);

    for (unsigned bank = 0; bank < 4u; bank++) {
        for (unsigned row = 0; row < MESH_N; row++) {
            seed = mix64(seed + ((uint64_t)bank << 24) + row);
            matrix_bank[bank].row[row] = (seed | (UINT64_C(1) << row)) & UINT64_C(0xffff);
        }
    }
}

static void init_mesh(void) {
    uint64_t seed = UINT64_C(0x13198a2e03707344);

    for (unsigned r = 0; r < MESH_N; r++) {
        for (unsigned c = 0; c < MESH_N; c++) {
            seed = mix64(seed ^ ((uint64_t)r << 32) ^ c);
            mesh[r][c] = seed ^ rotl64(UINT64_C(0x9e3779b97f4a7c15), r + c + 1u);
        }
    }
}

__attribute__((noinline))
static uint64_t mesh_round(unsigned round, uint64_t carry) {
    uint64_t diag = carry ^ crc_table[(round * 29u) & 255u];

    for (unsigned r = 0; r < MESH_N; r++) {
        uint64_t left = mesh[r][(round + r) & (MESH_N - 1u)];
        uint64_t above = mesh[(r + MESH_N - 1u) & (MESH_N - 1u)][r];
        uint64_t factor = matrix_apply(&matrix_bank[(round + r) & 3u], left ^ above ^ diag);
        uint64_t product = gf_mul64(left ^ carry, factor | UINT64_C(1));
        uint64_t folded = crc64_fold(diag ^ product, above + ((uint64_t)r << 48));

        for (unsigned c = 0; c < MESH_N; c++) {
            uint64_t old = mesh[r][c];
            uint64_t neighbor = mesh[(r + c + 3u) & (MESH_N - 1u)][(c + 5u) & (MESH_N - 1u)];
            uint64_t gate = gf_mul64(old ^ folded, neighbor | UINT64_C(1));

            if (((gate >> ((c + r) & 31u)) & 1u) != 0u) {
                mesh[r][c] = crc64_fold(gate ^ product, old) ^ rotl64(factor, c + 1u);
            } else if ((folded & (UINT64_C(1) << (c & 15u))) != 0u) {
                mesh[r][c] = gf_mul64(old ^ diag, folded | UINT64_C(1)) + rotr64(neighbor, r + 7u);
            } else {
                mesh[r][c] = old ^ gate ^ rotl64(neighbor + carry, r + c + 3u);
            }

            diag ^= matrix_apply(&matrix_bank[c & 3u], mesh[r][c]);
            diag = crc64_fold(diag, mesh[r][c] ^ ((uint64_t)c << 56));
        }
    }

    return diag;
}

static uint64_t checksum_mesh(void) {
    uint64_t h = UINT64_C(0xcbf29ce484222325);

    for (unsigned r = 0; r < MESH_N; r++) {
        for (unsigned c = 0; c < MESH_N; c++) {
            uint64_t v = mesh[r][c] ^ ((uint64_t)r << 40) ^ ((uint64_t)c << 8);
            h = crc64_fold(h, v);
            h ^= gf_mul64(v | UINT64_C(1), h ^ UINT64_C(0xd6e8feb86659fd93));
        }
    }

    return h;
}

int main(void) {
    uint64_t trace = UINT64_C(0x6d6f726f6b676632);

    init_crc_table();
    init_matrices();
    init_mesh();

    for (unsigned round = 0; round < ROUNDS; round++) {
        trace ^= mesh_round(round, trace + crc_table[round & 255u]);
        trace = rotl64(trace ^ UINT64_C(0xa5a5a5a55a5a5a5a), (round & 31u) + 1u);
    }

    sink = checksum_mesh() ^ trace;
    printf("int_carryless_crc_mesh checksum=%016" PRIx64 " trace=%016" PRIx64 "\n", sink, trace);
    return 0;
}
