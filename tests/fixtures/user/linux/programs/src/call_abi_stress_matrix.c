/*
 * call_abi_stress_matrix.c
 *
 * Dense call matrix with mixed scalar and aggregate ABI traffic.
 * Stresses calls, returns, varargs, pointer aliasing, and integer/FP mixing.
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

volatile uint64_t call_abi_sink;

typedef struct {
    uint64_t lo;
    uint64_t hi;
    uint32_t tag;
    uint8_t lane[6];
} Packet;

typedef struct {
    double d0;
    double d1;
    float f0;
    float f1;
    uint64_t u;
    int32_t i;
} Mixed;

typedef struct {
    uint64_t row[4][3];
    uint32_t bias[5];
} BigMatrix;

typedef struct {
    uint32_t cell[4][4];
    uint8_t pad[16];
} AliasBox;

static uint32_t rotl32(uint32_t value, unsigned amount) {
    amount &= 31u;
    return amount == 0u ? value : (value << amount) | (value >> (32u - amount));
}

static uint64_t rotl64(uint64_t value, unsigned amount) {
    amount &= 63u;
    return amount == 0u ? value : (value << amount) | (value >> (64u - amount));
}

static uint64_t mix64(uint64_t value) {
    value ^= value >> 30u;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27u;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31u;
    return value;
}

__attribute__((noinline))
static Packet make_packet(uint64_t seed,
                          uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
                          uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7,
                          uint8_t mode) {
    Packet packet;
    uint64_t folded = seed ^ ((uint64_t)a0 << 32u) ^ a7;

    packet.lo = mix64(folded + a1 + ((uint64_t)a2 << 17u));
    packet.hi = mix64(seed ^ ((uint64_t)a3 << 41u) ^ ((uint64_t)a4 << 9u));
    packet.tag = (uint32_t)(packet.lo ^ (packet.hi >> 32u) ^ a5 ^ rotl32(a6, mode));

    for (uint32_t i = 0; i < 6u; ++i) {
        packet.lane[i] = (uint8_t)(packet.tag >> ((i & 3u) * 8u));
        packet.lane[i] ^= (uint8_t)(seed >> ((i + 1u) * 7u));
    }

    return packet;
}

__attribute__((noinline))
static Packet route_alpha(Packet packet, uint64_t salt, uint32_t round) {
    packet.lo += mix64(salt ^ packet.hi ^ round);
    packet.hi ^= rotl64(packet.lo + packet.tag, (round & 31u) + 1u);
    packet.tag += (uint32_t)(packet.lo >> 32u) ^ round;
    packet.lane[round % 6u] ^= (uint8_t)(packet.tag >> 5u);
    return packet;
}

__attribute__((noinline))
static Packet route_beta(Packet packet, uint64_t salt, uint32_t round) {
    packet.hi += mix64(salt + packet.lo + UINT64_C(0x51ed2705));
    packet.lo ^= rotl64(packet.hi ^ packet.tag, (round & 15u) + 11u);
    packet.tag = rotl32(packet.tag ^ (uint32_t)salt, (round & 7u) + 1u);
    packet.lane[(round + 2u) % 6u] += (uint8_t)(packet.lo >> 11u);
    return packet;
}

__attribute__((noinline))
static Packet route_gamma(Packet packet, uint64_t salt, uint32_t round) {
    uint64_t bridge = mix64(packet.lo + packet.hi + salt + round);
    packet.lo += bridge ^ rotl64(packet.hi, 9u);
    packet.hi += rotl64(bridge, 29u) ^ packet.lo;
    packet.tag ^= (uint32_t)(bridge >> 24u) + round;
    packet.lane[(round + 5u) % 6u] ^= (uint8_t)(bridge >> 48u);
    return packet;
}

typedef Packet (*RouteFn)(Packet, uint64_t, uint32_t);

static RouteFn route_table[3] = {
    route_alpha,
    route_beta,
    route_gamma,
};

__attribute__((noinline))
static void alias_box(AliasBox *box, Packet *packet, uint32_t round) {
    uint32_t *first = &box->cell[round & 3u][(round >> 2u) & 3u];
    uint32_t *second = &box->cell[(round + 1u) & 3u][(round + 3u) & 3u];
    uint8_t *bytes = (uint8_t *)box->cell;
    uint32_t mixed = rotl32(*first + packet->tag + round, (round & 15u) + 1u);

    *first ^= mixed + *second;
    *second += rotl32(*first ^ (uint32_t)packet->lo, ((round >> 4u) & 15u) + 1u);
    bytes[(round * 5u + packet->lane[round % 6u]) & 63u] ^=
        (uint8_t)(*first >> ((round & 3u) * 8u));
    packet->lane[(round + *second) % 6u] += (uint8_t)(*second >> 13u);
    packet->tag ^= *first + rotl32(*second, 7u);
}

__attribute__((noinline))
static Mixed make_mixed(Packet packet, double scale, float bend, uint64_t extra) {
    Mixed mixed;
    uint32_t low = (uint32_t)(packet.lo ^ extra);
    uint32_t high = (uint32_t)((packet.hi >> 32u) ^ packet.tag);

    mixed.d0 = (double)(low & UINT32_C(0xffff)) * scale + 0.5;
    mixed.d1 = (double)(high & UINT32_C(0xffff)) * 0.25 + (double)packet.lane[0];
    mixed.f0 = (float)(packet.lane[1] + packet.lane[2]) * bend;
    mixed.f1 = (float)(packet.lane[3] ^ packet.lane[4]) * 0.125f;
    mixed.u = mix64(packet.lo + packet.hi + extra);
    mixed.i = (int32_t)((low ^ high) & UINT32_C(0x3fffffff));
    return mixed;
}

__attribute__((noinline))
static BigMatrix fill_matrix(Packet packet, Mixed mixed, uint32_t salt) {
    BigMatrix matrix;
    uint64_t base = packet.lo ^ packet.hi ^ mixed.u ^ salt;

    for (uint32_t r = 0; r < 4u; ++r) {
        for (uint32_t c = 0; c < 3u; ++c) {
            uint64_t lane = packet.lane[(r + c) % 6u];
            matrix.row[r][c] = mix64(base + lane + (uint64_t)(r * 13u + c * 29u));
        }
    }
    for (uint32_t i = 0; i < 5u; ++i) {
        matrix.bias[i] = (uint32_t)mix64(base + i * UINT64_C(0x100000001b3));
    }

    return matrix;
}

__attribute__((noinline))
static BigMatrix twist_matrix(BigMatrix matrix, Packet packet,
                              uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                              uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {
    uint64_t args[8] = {a0, a1, a2, a3, a4, a5, a6, a7};

    for (uint32_t r = 0; r < 4u; ++r) {
        for (uint32_t c = 0; c < 3u; ++c) {
            uint64_t salt = args[(r * 3u + c) & 7u] ^ packet.lane[(r + c) % 6u];
            matrix.row[r][c] = rotl64(matrix.row[r][c] + salt, (unsigned)(r + c + 1u));
        }
    }
    for (uint32_t i = 0; i < 5u; ++i) {
        matrix.bias[i] ^= (uint32_t)(args[(i + packet.tag) & 7u] >> (i * 5u));
    }

    return matrix;
}

__attribute__((noinline))
static uint64_t consume_matrix(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                               uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                               uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11,
                               Packet packet, Mixed mixed, BigMatrix matrix) {
    uint64_t acc = a0 ^ rotl64(a1, 3u) ^ rotl64(a2, 7u) ^ rotl64(a3, 11u);
    acc += a4 ^ rotl64(a5, 17u) ^ rotl64(a6, 23u) ^ rotl64(a7, 29u);
    acc ^= a8 + rotl64(a9, 31u) + rotl64(a10, 37u) + rotl64(a11, 41u);
    acc += packet.lo ^ packet.hi ^ packet.tag;

    for (uint32_t r = 0; r < 4u; ++r) {
        for (uint32_t c = 0; c < 3u; ++c) {
            acc ^= mix64(matrix.row[r][c] + matrix.bias[(r + c) % 5u] + acc);
        }
    }

    acc += (uint64_t)(mixed.d0 * 4096.0);
    acc ^= (uint64_t)(mixed.d1 * 2048.0);
    acc += (uint64_t)(mixed.f0 * 1024.0f);
    acc ^= (uint64_t)(mixed.f1 * 512.0f);
    acc += mixed.u ^ (uint32_t)mixed.i;
    return mix64(acc);
}

__attribute__((noinline))
static uint64_t fold_variadic(const char *pattern, ...) {
    va_list ap;
    uint64_t acc = UINT64_C(0xcbf29ce484222325);

    va_start(ap, pattern);
    for (const char *p = pattern; *p != '\0'; ++p) {
        switch (*p) {
            case 'u': {
                uint64_t value = va_arg(ap, uint64_t);
                acc ^= mix64(value + acc);
                break;
            }
            case 'i': {
                int value = va_arg(ap, int);
                acc += mix64((uint32_t)value ^ acc);
                break;
            }
            case 'd': {
                double value = va_arg(ap, double);
                acc ^= (uint64_t)(value * 8192.0);
                break;
            }
            case 'P': {
                Packet packet = va_arg(ap, Packet);
                acc += packet.lo ^ rotl64(packet.hi, 21u) ^ packet.tag;
                for (uint32_t i = 0; i < 6u; ++i) {
                    acc ^= (uint64_t)packet.lane[i] << ((i & 7u) * 8u);
                }
                break;
            }
            default:
                acc ^= UINT64_C(0x9e3779b97f4a7c15);
                break;
        }
    }
    va_end(ap);

    return mix64(acc);
}

int main(void) {
    AliasBox box;
    uint64_t checksum = UINT64_C(0x0123456789abcdef);

    for (uint32_t r = 0; r < 4u; ++r) {
        for (uint32_t c = 0; c < 4u; ++c) {
            box.cell[r][c] = (uint32_t)mix64((uint64_t)r * 17u + c * 41u + 3u);
        }
    }
    for (uint32_t i = 0; i < 16u; ++i) {
        box.pad[i] = (uint8_t)(i * 19u + 7u);
    }

    Packet packet = make_packet(UINT64_C(0xfeedfacecafebeef),
                                1u, 3u, 5u, 7u, 11u, 13u, 17u, 19u, 5u);

    for (uint32_t round = 0; round < 192u; ++round) { /* rax: was 3072u */
        alias_box(&box, &packet, round);

        uint32_t route = (box.cell[round & 3u][(round >> 3u) & 3u] ^ packet.tag ^ round) % 3u;
        packet = route_table[route](packet, checksum, round);

        Mixed mixed = make_mixed(packet, 0.5 + (double)(round & 7u) * 0.125,
                                 0.25f + (float)(round & 3u) * 0.125f,
                                 checksum);
        BigMatrix matrix = fill_matrix(packet, mixed, round ^ box.cell[(round + 1u) & 3u][round & 3u]);

        matrix = twist_matrix(matrix, packet,
                              checksum,
                              checksum + round,
                              packet.lo,
                              packet.hi,
                              mixed.u,
                              (uint64_t)box.cell[0][round & 3u],
                              (uint64_t)box.cell[1][(round + 1u) & 3u],
                              (uint64_t)box.cell[2][(round + 2u) & 3u]);

        uint64_t call_sum = consume_matrix(checksum,
                                           checksum ^ packet.lo,
                                           checksum + packet.hi,
                                           (uint64_t)packet.tag << 32u,
                                           mixed.u,
                                           matrix.row[0][0],
                                           matrix.row[1][1],
                                           matrix.row[2][2],
                                           matrix.row[3][0],
                                           box.cell[0][0],
                                           box.cell[1][1],
                                           box.cell[2][2],
                                           packet,
                                           mixed,
                                           matrix);

        checksum ^= call_sum + fold_variadic("uidP",
                                             (uint64_t)round,
                                             (int)(round & 32767u),
                                             0.125 + (double)(round & 15u) * 0.0625,
                                             packet);
        checksum = mix64(checksum + matrix.row[round & 3u][round % 3u]);
    }

    call_abi_sink = checksum ^ packet.lo ^ rotl64(packet.hi, 33u);
    printf("call_abi_stress_matrix %016" PRIx64 "\n", call_abi_sink);
    return 0;
}
