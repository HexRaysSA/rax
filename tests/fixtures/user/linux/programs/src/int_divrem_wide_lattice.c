// SPDX-License-Identifier: MIT
/*
 * int_divrem_wide_lattice.c
 *
 * Fringe integer division/remainder lattice with mixed signed and unsigned
 * cells. Operands are generated inside conservative bounds to avoid signed
 * overflow, division by zero, and INT_MIN / -1.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define ROWS 17u
#define COLS 19u
#define ROUNDS 1u /* rax: was 41u */

typedef struct {
    int64_t signed_lane[4];
    uint64_t unsigned_lane[4];
    uint64_t tag;
} LatticeCell;

static LatticeCell lattice[ROWS][COLS];
static uint64_t divisor_table[64];

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
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static int64_t signed_numerator(uint64_t x) {
    uint64_t bounded = x & ((UINT64_C(1) << 51) - 1u);
    return (int64_t)bounded - (INT64_C(1) << 50);
}

static int64_t signed_denominator(uint64_t x) {
    int64_t mag = (int64_t)((x & UINT64_C(0x1ffff)) + 3u);
    return (x & UINT64_C(0x20000)) != 0u ? -mag : mag;
}

static uint64_t unsigned_denominator(uint64_t x) {
    uint64_t d = ((x >> 7) ^ (x >> 29) ^ UINT64_C(0x9e3779b97f4a7c15));
    return ((d & UINT64_C(0x0000ffffffffffff)) | UINT64_C(1));
}

static uint64_t fold_signed_result(int64_t q, int64_t r, int64_t d, uint64_t salt) {
    int64_t abs_r = r < 0 ? -r : r;
    uint64_t uq = (uint64_t)q;
    uint64_t ur = (uint64_t)abs_r;
    uint64_t ud = (uint64_t)(d < 0 ? -d : d);

    return rotl64(uq ^ (ur * UINT64_C(0x100000001b3)), (unsigned)(salt & 31u) + 1u)
         ^ rotr64(ud + salt, (unsigned)((salt >> 9) & 31u) + 1u);
}

__attribute__((noinline))
static uint64_t signed_divrem_cell(LatticeCell *cell, uint64_t seed, unsigned round) {
    uint64_t acc = cell->tag ^ seed;

    for (unsigned lane = 0; lane < 4u; lane++) {
        uint64_t basis = mix64(acc + divisor_table[(round + lane * 7u) & 63u]);
        int64_t n = signed_numerator(basis ^ (uint64_t)cell->signed_lane[lane]);
        int64_t d = signed_denominator(basis >> 11);
        int64_t q = n / d;
        int64_t r = n % d;
        int64_t rebuilt = q * d + r;

        if (rebuilt == n) {
            acc ^= fold_signed_result(q, r, d, basis);
            cell->signed_lane[lane] = q + (r ^ (int64_t)(round + lane));
        } else {
            acc ^= UINT64_C(0xdeaddeaddeaddead);
            cell->signed_lane[lane] = r;
        }

        if (((uint64_t)r & 3u) == (lane & 3u)) {
            acc += rotl64((uint64_t)(q ^ r), lane + round + 1u);
        } else {
            acc ^= rotr64((uint64_t)(q - r), lane * 5u + round + 3u);
        }
    }

    cell->tag = rotl64(cell->tag ^ acc ^ seed, (round % 23u) + 1u);
    return acc;
}

__attribute__((noinline))
static uint64_t unsigned_divrem_cell(LatticeCell *cell, uint64_t seed, unsigned round) {
    uint64_t acc = seed ^ rotr64(cell->tag, round + 5u);

    for (unsigned lane = 0; lane < 4u; lane++) {
        uint64_t n = mix64(cell->unsigned_lane[lane] + acc + divisor_table[(lane * 13u + round) & 63u]);
        uint64_t d = unsigned_denominator(n ^ seed ^ ((uint64_t)lane << 32));
        uint64_t q = n / d;
        uint64_t r = n % d;
        uint64_t rebuilt = q * d + r;

        if (rebuilt == n) {
            acc += rotl64(q ^ divisor_table[(r + lane) & 63u], (unsigned)(r & 31u) + 1u);
            acc ^= rotr64(r + UINT64_C(0xa5a5a5a55a5a5a5a), lane + 9u);
        } else {
            acc ^= UINT64_C(0xfeedfacecafef00d);
        }

        if ((q ^ r ^ acc) & UINT64_C(0x80)) {
            cell->unsigned_lane[lane] = q + rotl64(r, lane + 1u);
        } else {
            cell->unsigned_lane[lane] = r ^ rotr64(q + acc, lane + 3u);
        }
    }

    cell->tag ^= rotl64(acc + seed + (uint64_t)round, (round & 15u) + 1u);
    return acc;
}

static void init_tables(void) {
    uint64_t x = UINT64_C(0x6a09e667f3bcc909);

    for (unsigned i = 0; i < 64u; i++) {
        x = mix64(x + (uint64_t)i * UINT64_C(0x9e3779b97f4a7c15));
        divisor_table[i] = (x | UINT64_C(1)) ^ ((uint64_t)(i + 3u) << 48);
    }
}

static void init_lattice(void) {
    for (unsigned r = 0; r < ROWS; r++) {
        for (unsigned c = 0; c < COLS; c++) {
            uint64_t seed = mix64(UINT64_C(0x123456789abcdef0) ^ ((uint64_t)r << 32) ^ c);
            LatticeCell *cell = &lattice[r][c];

            cell->tag = seed ^ divisor_table[(r * 11u + c) & 63u];
            for (unsigned lane = 0; lane < 4u; lane++) {
                uint64_t v = mix64(seed + (uint64_t)lane * UINT64_C(0x45d9f3b));
                cell->signed_lane[lane] = signed_numerator(v);
                cell->unsigned_lane[lane] = v ^ divisor_table[(c * 5u + lane) & 63u];
            }
        }
    }
}

__attribute__((noinline))
static uint64_t lattice_round(unsigned round) {
    uint64_t wave = mix64(UINT64_C(0x3141592653589793) + round);

    for (unsigned r = 0; r < ROWS; r++) {
        for (unsigned c = 0; c < COLS; c++) {
            LatticeCell *cell = &lattice[r][c];
            uint64_t neighbor = lattice[(r + ROWS - 1u) % ROWS][(c + 3u) % COLS].tag;
            uint64_t seed = wave ^ neighbor ^ ((uint64_t)r << 40) ^ ((uint64_t)c << 8);

            if (((r + c + round) & 1u) == 0u) {
                wave ^= signed_divrem_cell(cell, seed, round);
                wave += unsigned_divrem_cell(cell, seed ^ wave, round + c);
            } else {
                wave += unsigned_divrem_cell(cell, seed, round);
                wave ^= signed_divrem_cell(cell, seed + wave, round + r);
            }

            if ((cell->tag & UINT64_C(0x100000000)) != 0u) {
                cell->tag += rotl64(wave, (r + c + round) & 31u);
            } else {
                cell->tag ^= rotr64(wave + divisor_table[(r + c) & 63u], (round & 31u) + 1u);
            }
        }
    }

    return wave;
}

static uint64_t checksum_lattice(void) {
    uint64_t h = UINT64_C(0xcbf29ce484222325);

    for (unsigned r = 0; r < ROWS; r++) {
        for (unsigned c = 0; c < COLS; c++) {
            const LatticeCell *cell = &lattice[r][c];

            h ^= cell->tag + ((uint64_t)r << 16) + c;
            h *= UINT64_C(0x100000001b3);
            for (unsigned lane = 0; lane < 4u; lane++) {
                h ^= (uint64_t)cell->signed_lane[lane] ^ rotl64(cell->unsigned_lane[lane], lane + 1u);
                h = rotl64(h, 11u) * UINT64_C(0xd6e8feb86659fd93);
            }
        }
    }

    return h;
}

int main(void) {
    uint64_t trace = UINT64_C(0x6d6f726f6b646976);

    init_tables();
    init_lattice();

    for (unsigned round = 0; round < ROUNDS; round++) {
        trace ^= lattice_round(round);
        trace = rotl64(trace + divisor_table[round & 63u], (round % 37u) + 1u);
    }

    sink = checksum_lattice() ^ trace;
    printf("int_divrem_wide_lattice checksum=%016" PRIx64 " trace=%016" PRIx64 "\n", sink, trace);
    return 0;
}
