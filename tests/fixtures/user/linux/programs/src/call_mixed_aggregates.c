/*
 * call_mixed_aggregates.c
 *
 * Mixed aggregate calling conventions.
 * Stresses struct passing, return values, and alignment.
 *
 * Features exercised:
 *   - Small/large struct passing and returns
 *   - Mixed integer/float/double fields
 *   - Over-aligned aggregates
 *   - By-value aggregate arrays
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile uint64_t sink;

typedef struct {
    int8_t a;
    int16_t b;
    int32_t c;
} SmallA;

typedef struct {
    double d;
    int32_t x;
    uint16_t y;
    uint8_t z;
    uint8_t pad;
} MixedA;

typedef struct {
    float f[3];
    uint32_t tag;
} MixedB;

typedef struct {
    uint64_t a;
    uint64_t b;
    uint32_t c;
    uint32_t d;
} BigA;

typedef struct __attribute__((aligned(16))) {
    uint8_t bytes[24];
} AlignedA;

__attribute__((noinline))
SmallA make_small(int32_t seed) {
    SmallA s;
    s.a = (int8_t)seed;
    s.b = (int16_t)(seed >> 3);
    s.c = seed ^ 0x12345678;
    return s;
}

__attribute__((noinline))
MixedA tweak_mixed(MixedA m, SmallA s, int flag) {
    if (flag) {
        m.d += (double)s.c * 0.5;
        m.x ^= s.c;
    } else {
        m.d -= (double)s.b * 1.25;
        m.x += s.c;
    }
    m.y += (uint16_t)(s.a * 3);
    m.z ^= (uint8_t)(flag * 7);
    return m;
}

__attribute__((noinline))
MixedB scale_mixedb(MixedB b, float scale) {
    for (int i = 0; i < 3; i++) {
        b.f[i] = b.f[i] * scale + (float)i;
    }
    b.tag ^= (uint32_t)(scale * 100.0f);
    return b;
}

__attribute__((noinline))
BigA merge_big(BigA a, BigA b) {
    BigA out;
    out.a = a.a + b.b;
    out.b = a.b ^ b.a;
    out.c = a.c + b.c;
    out.d = a.d ^ b.d;
    return out;
}

__attribute__((noinline))
AlignedA shuffle_aligned(AlignedA in, uint32_t seed) {
    AlignedA out = in;
    for (int i = 0; i < 24; i++) {
        uint32_t idx = (uint32_t)(i + seed) % 24u;
        out.bytes[i] = (uint8_t)(in.bytes[idx] ^ (uint8_t)(seed + i));
    }
    return out;
}

__attribute__((noinline))
uint64_t consume_all(SmallA s, MixedA m, MixedB b, BigA big, AlignedA al) {
    float acc = b.f[0] + b.f[1] * 2.0f - b.f[2] * 0.25f;
    uint64_t sum = 0;

    sum += (uint64_t)s.a + (uint64_t)s.b + (uint64_t)s.c;
    sum += (uint64_t)m.x + (uint64_t)m.y + (uint64_t)m.z;
    sum += (uint64_t)(m.d + (double)acc);
    sum += big.a + big.b + big.c + big.d;

    for (int i = 0; i < 24; i++) {
        sum += al.bytes[i];
    }

    return sum;
}

int main(void) {
    uint64_t result = 0;

    for (uint32_t i = 0; i < 500; i++) { /* rax: was 5000 */
        SmallA s = make_small((int32_t)i * 7);
        MixedA m = { (double)i * 1.5, (int32_t)i ^ 0x55aa55aa, (uint16_t)i, (uint8_t)(i ^ 0x5a), 0 };
        MixedB b = { { (float)i, (float)(i * 2), (float)(i * 3) }, i };
        BigA big = { (uint64_t)i << 32, (uint64_t)i * 0x1234u, i ^ 0xa5a5u, i + 1 };
        AlignedA al = { {0} };

        for (int j = 0; j < 24; j++) {
            al.bytes[j] = (uint8_t)(i + j * 3);
        }

        m = tweak_mixed(m, s, (i & 1u) != 0u);
        b = scale_mixedb(b, (float)((i & 7u) + 1u) * 0.5f);
        big = merge_big(big, (BigA){ big.b, big.a, big.d, big.c });
        al = shuffle_aligned(al, i);

        result += consume_all(s, m, b, big, al);
    }

    sink = result;
    printf("sink=%" PRIu64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
