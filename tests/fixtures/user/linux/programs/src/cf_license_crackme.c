#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

static uint32_t r0(uint32_t x, unsigned n) {
    n &= 31u;
    return (x << n) | (x >> ((32u - n) & 31u));
}

static uint32_t r1(uint32_t x, unsigned n) {
    n &= 31u;
    return (x >> n) | (x << ((32u - n) & 31u));
}

static uint32_t m0(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static uint32_t m1(uint32_t x) {
    x += 0x9e3779b9u;
    x = (x ^ (x >> 13)) * 0xc2b2ae35u;
    x = (x ^ (x >> 16)) * 0x27d4eb2du;
    return x ^ (x >> 15);
}

#define BLOB_A(ID, SEED, ...) \
static void ID(FILE *q) { \
    static unsigned char z[] = { __VA_ARGS__ }; \
    static unsigned char c; \
    if ((c & 1u) == 0u) { \
        uint32_t s = (uint32_t)(SEED) ^ (uint32_t)(sizeof(z) * 0x9e3779b9u); \
        for (size_t i = 0; i < sizeof(z); ++i) { \
            s += 0x7f4a7c15u + (uint32_t)(i * 17u); \
            s ^= s << 13; \
            s ^= s >> 17; \
            s ^= s << 5; \
            z[i] ^= (unsigned char)(((s >> ((i & 3u) * 3u)) + 0xa5u + (uint32_t)i * 29u) & 0xffu); \
        } \
        c = 1u; \
    } \
    fwrite(z, 1u, sizeof(z), q); \
}

#define BLOB_B(ID, SEED, ...) \
static void ID(FILE *q) { \
    static unsigned char z[] = { __VA_ARGS__ }; \
    static unsigned char c; \
    if ((c & 1u) == 0u) { \
        uint32_t s = (uint32_t)(SEED) + (uint32_t)(sizeof(z) * 0x6d2b79f5u) + 0x85ebca6bu; \
        for (size_t i = 0; i < sizeof(z); ++i) { \
            s ^= s >> 15; \
            s *= 0x2c1b3c6du; \
            s ^= s >> 12; \
            s *= 0x297a2d39u; \
            s ^= s >> 15; \
            z[i] ^= (unsigned char)(((s >> 24) ^ (s >> 9) ^ ((uint32_t)i * 47u + 0x3cu)) & 0xffu); \
        } \
        c = 1u; \
    } \
    fwrite(z, 1u, sizeof(z), q); \
}

#define BLOB_C(ID, SEED, ...) \
static void ID(FILE *q) { \
    static unsigned char z[] = { __VA_ARGS__ }; \
    static unsigned char c; \
    if ((c & 1u) == 0u) { \
        uint32_t s = (uint32_t)(SEED) ^ 0xc2b2ae35u ^ ((uint32_t)sizeof(z) << 16); \
        for (size_t i = 0; i < sizeof(z); ++i) { \
            s = s * 1664525u + 1013904223u + (uint32_t)(i * 97u); \
            uint32_t t = s ^ r0(s, (unsigned)((i & 7u) + 3u)); \
            z[i] ^= (unsigned char)((t + (t >> 11) + 0x5du + (uint32_t)i * 11u) & 0xffu); \
        } \
        c = 1u; \
    } \
    fwrite(z, 1u, sizeof(z), q); \
}

#define BLOB_D(ID, SEED, ...) \
static void ID(FILE *q) { \
    static unsigned char z[] = { __VA_ARGS__ }; \
    static unsigned char c; \
    if ((c & 1u) == 0u) { \
        uint32_t s = (uint32_t)(SEED) + 0xd1b54a35u + (uint32_t)(sizeof(z) * 0x94d049bbu); \
        for (size_t i = 0; i < sizeof(z); ++i) { \
            s ^= (uint32_t)i + 0xa0761d65u; \
            s = (s ^ (s >> 16)) * 0x7feb352du; \
            s = (s ^ (s >> 15)) * 0x846ca68bu; \
            s ^= s >> 16; \
            z[i] ^= (unsigned char)(((s >> ((i & 1u) ? 16u : 8u)) + (s >> 27) + (uint32_t)i * 73u) & 0xffu); \
        } \
        c = 1u; \
    } \
    fwrite(z, 1u, sizeof(z), q); \
}

BLOB_A(e0, 0x493a17c1u, 0x62, 0xcc, 0x49, 0x50, 0x90, 0x49, 0xcb, 0xad, 0x21, 0x88, 0x25, 0x5b, 0x37, 0xd3, 0x4f, 0x73, 0xc7, 0x84, 0xd7, 0xc4, 0xb7, 0xc0, 0x51, 0x4b, 0x24, 0x93, 0x63, 0x74, 0x7e, 0x13, 0xa5, 0x2d, 0xf5, 0xc5, 0x82, 0x28, 0x45, 0xa7, 0x32, 0xf6, 0x15, 0xb0, 0xdd, 0xa7, 0xb7, 0xc6, 0xbb, 0x17, 0xfa, 0x06, 0x78, 0x59, 0x47, 0xf7, 0xf3, 0xee, 0xd5, 0x93, 0x04, 0x00, 0x5c, 0xda, 0xda, 0x55, 0x8d, 0xb7, 0xe5, 0x47, 0x0a, 0xd5, 0x1f, 0xb2, 0x3d, 0x8a, 0x91, 0x87, 0xd3, 0xfc, 0x88, 0x84, 0x84, 0x1f, 0x7a, 0xb3, 0x4a, 0xaf, 0xe5, 0x63, 0xa6, 0xd0, 0x61, 0x2b, 0x37, 0x50, 0x5e, 0x93, 0x08, 0x50, 0x7a, 0x97, 0x07, 0x54, 0x58, 0x64, 0xc4, 0x93, 0x6b, 0xee, 0xb0, 0x36, 0x50, 0xc3, 0x4e, 0x2d, 0x69, 0xfe, 0x35, 0xd7, 0xf3, 0x19, 0x76, 0xb0, 0x52, 0x6a, 0x51, 0x1b, 0x99, 0xfc, 0x79, 0x0b, 0x8f, 0x36, 0xb8, 0x45, 0x9c, 0xed, 0x26, 0xfd, 0xd6, 0x6a, 0x55, 0xbc, 0xb6, 0x83, 0x91, 0x84, 0xc1, 0x39, 0xee, 0x6d, 0xd5, 0xbb, 0x2d, 0xb8, 0x32, 0xf3, 0xc8, 0x0d, 0xc8, 0x4e, 0x6d, 0x94, 0xb3, 0x49, 0xbf, 0xd1, 0x76, 0xb1, 0x5e, 0xab, 0xcb, 0xc7, 0x5c, 0x9d, 0xb8, 0xe9, 0x4c, 0x73, 0x98, 0x2a, 0x9d, 0x1c, 0x66, 0xd9, 0xbb, 0x05)
BLOB_B(e1, 0x9b7215a4u, 0x3f, 0xb0, 0xd9, 0x78, 0x29, 0x24, 0xa0, 0x15, 0x99, 0x36, 0xff, 0xe1, 0xcb, 0xf0, 0xb3, 0x6a, 0x34, 0x6b, 0xe1, 0xb4, 0x1f, 0x1e, 0x42, 0x5d, 0x30, 0x68, 0x25, 0x51, 0xd3, 0x23, 0x36, 0xf4, 0xd0, 0x5e, 0x86, 0x85, 0x2c, 0xaa, 0x50, 0x7e, 0xb2, 0x1d, 0x9d, 0xaa, 0xca, 0xff, 0x29, 0x30, 0xd0, 0x8c, 0xce, 0xcd, 0x3a, 0x68, 0xd0)
BLOB_C(e2, 0x17cf66d9u, 0xf1, 0xa1, 0x56, 0x09, 0x7c, 0x0a, 0xba, 0xe9, 0x01, 0xdc, 0xe0, 0xc3, 0x1e, 0x07, 0xb4, 0x45, 0x1c, 0x4e, 0x6b, 0x39, 0xab, 0x64, 0x34, 0x25, 0x4e, 0x58, 0x8e, 0x17, 0x0d, 0x57, 0x7b, 0x2d, 0xf0, 0xb6, 0x03, 0x9f, 0xd3, 0xb1, 0xcf, 0x0c, 0x5f, 0xcd, 0xa6, 0xe1, 0x76, 0xb6, 0xcd, 0x07, 0x35, 0xec, 0x59, 0xef, 0x00, 0x37, 0xa5, 0x63, 0x01)
BLOB_D(e3, 0xd8712c3bu, 0xf0, 0xe6, 0x51, 0x86, 0x3b, 0x86, 0xdd, 0x17, 0x32, 0x59, 0x22, 0x0a, 0x9e, 0x0d, 0xe9, 0x3b, 0x44, 0x47, 0x5c, 0xfa, 0x70, 0x80, 0xbe, 0x6a, 0x01, 0x2d, 0x7f, 0x2f, 0x83, 0xd4, 0xe7, 0xa2, 0x07, 0x18, 0x9b, 0x6f, 0x6e, 0x51, 0x33, 0x10, 0xbf, 0xce, 0x31, 0xf8, 0xde, 0x8f, 0x11, 0xb6, 0x00, 0x3b, 0x39, 0xe6, 0x81, 0xf9, 0xdc, 0xb8, 0xd0, 0x35, 0xf8, 0x00, 0x16, 0x24, 0xbe, 0x0d, 0x6b)
BLOB_A(e4, 0x8c35ba19u, 0xc4, 0xa8, 0xfd, 0x52, 0xa2, 0x87, 0xd8, 0x52, 0x9d, 0x5d, 0x55, 0x1e, 0x27, 0x4f, 0x9b, 0x9c, 0xe0, 0x6b, 0xdd, 0xb9, 0x5a, 0xe0, 0xad, 0xf5, 0x3f, 0xdd, 0x7c, 0x0d, 0x5e, 0xef, 0xa6, 0xa6, 0xe0, 0x6f, 0x38, 0x39, 0x8e, 0xf7, 0x06, 0x2b, 0x7d, 0x19, 0x93)
BLOB_B(e5, 0x4f39aadeu, 0x3d, 0x69, 0x5a, 0x61, 0x5e, 0xf1, 0x38, 0x01, 0x21, 0x47, 0x56, 0x7f, 0xa4, 0xf6, 0xf0, 0xf5, 0x09, 0xe3, 0x2f, 0x3e, 0x07, 0x05, 0xc9, 0x51, 0x15, 0xa7, 0x49)
BLOB_C(e6, 0xaa53c921u, 0xe2, 0x85, 0x22, 0x5a, 0x17, 0x87, 0xdd, 0x9e, 0x7b, 0x11, 0x82, 0xe1, 0x7c, 0x19, 0x8d, 0x55, 0xe0, 0x34, 0x41, 0x04, 0x87, 0xaa, 0xd8, 0x6b, 0xa8, 0x50, 0x68, 0xc0, 0x42, 0x97, 0x50, 0xe5, 0x73, 0xd9, 0x46, 0x52, 0x46, 0xc3, 0x92, 0xda, 0x96, 0x12, 0xb8, 0x13, 0xb5, 0x42, 0x69, 0x23, 0x82, 0x2a, 0x74, 0xae, 0xb0)
BLOB_D(e7, 0x726cc947u, 0x15, 0x3e, 0xb4, 0x3a, 0x71, 0x37, 0x22, 0x92, 0x50, 0x42, 0xa3, 0x06, 0xbb, 0x3c, 0x12, 0xe5, 0xaf, 0x2a, 0x66, 0x08, 0xae, 0x56, 0x4f, 0xd3, 0xb4, 0x31, 0x98, 0x81, 0xe5, 0x75, 0xf6, 0x51, 0x82, 0xc0, 0xf4, 0x0e, 0xd6, 0xe6, 0x5e, 0x18, 0x18, 0x67, 0x85, 0x71, 0x00, 0x7a, 0x31, 0xd5, 0xa3, 0x58, 0x45)
BLOB_A(e8, 0x271d63b8u, 0xf8, 0xad, 0xea, 0x2c, 0x1b, 0x49, 0xc7, 0xbf, 0x59, 0x1a, 0xb3, 0xa1, 0x80, 0x01, 0xaa, 0x0f, 0xbb, 0x4e, 0x50, 0xd8, 0xef, 0xf3, 0x9d, 0x22, 0x60, 0xde, 0x3d, 0x7b, 0x3e, 0x81, 0xbd, 0x90, 0xb8, 0xdf, 0x47, 0xd8, 0xc1, 0x2e, 0x3b, 0xc1, 0xb5, 0x58, 0xc2, 0xbe, 0x52, 0xef, 0x75, 0x78, 0x7c)
BLOB_B(e9, 0x5198ac43u, 0x98, 0x77, 0x43, 0xb1, 0xbb, 0xf6, 0x67, 0xe5, 0x7f, 0x81, 0xda, 0xfb, 0x16, 0xab, 0x56, 0x2d, 0xdd, 0xc6, 0xdb, 0x1d, 0x59, 0x1d, 0x39, 0x9c, 0x74, 0x05, 0x08, 0x7a, 0x93, 0x8a, 0xbe, 0x32, 0x2c, 0xca, 0x6b, 0xeb, 0x67, 0x92, 0x8e, 0xdf, 0x08, 0xe7, 0x4f, 0x6a, 0x14, 0x70, 0xf2, 0x2a, 0x6b, 0x28, 0x97, 0x34, 0x02, 0x96, 0x1e, 0x94, 0x01, 0xf7, 0xbb, 0x6c, 0x69, 0xeb, 0x0f)
BLOB_C(e10, 0x010a2b3cu, 0xda, 0x0d, 0x3f, 0x1c)
BLOB_D(e11, 0x213f87acu, 0x0a, 0xf0, 0x31, 0xdf, 0xfb, 0xa0, 0x12)
BLOB_A(e12, 0x8822beefu, 0x18, 0xde, 0x3b)
BLOB_B(e13, 0x71245ab9u, 0x16, 0x36, 0x6c, 0x5a, 0x2c, 0xd5, 0xff, 0x66)
#if defined(CF_LICENSE_CRACKME_DELIVER_KEYGEN)
BLOB_C(e14, 0x5f10df65u, 0xc3, 0xb4, 0xe0, 0xa9, 0xc7, 0xff, 0xb0, 0x10, 0x77, 0x9b, 0xd2, 0x18, 0x5e, 0x54, 0x24, 0xdd, 0x53, 0xe4, 0xaf, 0x81, 0x14, 0xb1, 0x9a, 0x66, 0xfd, 0x64, 0x1e, 0x31, 0x92, 0x92, 0x5c, 0x89, 0xdd, 0xd4, 0xd1, 0xd4, 0xdf)
BLOB_D(e15, 0x426871bdu, 0xeb, 0xce, 0xf1, 0xc7, 0xe3, 0x66, 0x7c, 0xdc, 0x1b, 0xa5, 0x05)
BLOB_A(e16, 0xbb6c204eu, 0xf6, 0x50, 0x11, 0x06, 0x95, 0xe8, 0xb4, 0xae, 0x69, 0xb2, 0x75, 0xfd, 0x34, 0x29, 0xaa, 0xef, 0x4e, 0x8e, 0x4c, 0x21, 0xd7, 0x21, 0xfb, 0x36, 0x25, 0xfc, 0x6c, 0x78, 0xe4, 0x57, 0x7d, 0xaa, 0x27, 0x27, 0x18, 0x4f, 0xc2, 0x6f, 0x12, 0x66, 0x10, 0xac, 0xd6, 0x5c, 0x59, 0x97, 0xf1, 0x78, 0xdd, 0xcb, 0x2c, 0x89)
BLOB_B(e17, 0x091d88cau, 0x17, 0x31, 0xad, 0x23, 0x9a, 0x6a, 0x63, 0x1b, 0xb3, 0x1c, 0x17, 0xf9, 0xdf, 0xa3, 0x4b, 0x8b, 0xe4, 0x9a, 0x1a, 0x4f, 0x44, 0x9b, 0xca, 0x16, 0x9c, 0x56, 0xb9, 0x27, 0xda, 0x79, 0x83, 0x63, 0x4b, 0x02, 0x98, 0x78, 0x1a, 0x4e, 0x3e, 0xde, 0x59, 0xe6, 0xd2, 0x5f, 0x5b, 0xbf, 0xe6, 0xa8, 0xe8, 0xcf, 0xb5, 0x28)
#endif

typedef void (*e_fn)(FILE *);

static void p0(FILE *q, unsigned t) {
    static e_fn v[4] = { e10, e11, e12, e13 };
    v[t & 3u](q);
}

static uint32_t q0(uint32_t a, uint32_t b) {
    a ^= r0(b + 0xa511e9b3u, (a ^ b) & 15u);
    a += (b ^ 0x63d83595u) * 0x45d9f3bu;
    return m0(a ^ r1(b, 7));
}

static uint32_t q1(uint32_t a, uint32_t b) {
    b += r1(a ^ 0x91e10da5u, (b >> 3) & 15u);
    b ^= (a + 0x7f4a7c15u) * 0x119de1f3u;
    return m1(a ^ b ^ r0(a, 11));
}

static uint32_t q2(uint32_t a, uint32_t b) {
    uint32_t c = (a & b) + ((a | b) ^ 0xbead6b61u);
    c ^= r0(a + b + 0x6c8e9cf5u, (c >> 27) & 31u);
    return m0(c + r1(b, 5));
}

static uint32_t q3(uint32_t a, uint32_t b) {
    uint32_t c = (a ^ 0xd1b54a35u) + r0(b, 9);
    c ^= (b + 0x27d4eb2du) * 0x165667b1u;
    return m1(c ^ r1(a, 13));
}

static uint32_t q4(uint32_t a, uint32_t b) {
    uint32_t c = (a + (b ^ 0x85ebca6bu)) ^ r1(a + b, 3);
    c += ((a << 1) | 1u) * ((b >> 1) | 1u);
    return m0(c ^ 0xc2b2ae35u);
}

static uint32_t q5(uint32_t a, uint32_t b) {
    uint32_t c = (a - r0(b, 17)) ^ ((b + 0x94d049bbu) * 0x9e3779b9u);
    c += (a ^ (b >> 3)) + 0x632be59bu;
    return m1(c);
}

static uint32_t q6(uint32_t a, uint32_t b) {
    uint32_t c = (a ^ r1(b, 21)) + ((a & 0xffffu) * 0x1003fu);
    c ^= (b | 0x13579bdfu) + r0(a, 3);
    return m0(c);
}

static uint32_t q7(uint32_t a, uint32_t b) {
    uint32_t c = ((a | 1u) * 0x2c1b3c6du) ^ (b + r1(a, 19));
    c += r0(c ^ b, 7) ^ 0x297a2d39u;
    return m1(c);
}

typedef uint32_t (*q_fn)(uint32_t, uint32_t);

static uint32_t l0(const unsigned char *b, size_t n, unsigned t) {
    static q_fn f[8] = { q0, q1, q2, q3, q4, q5, q6, q7 };
    uint32_t a = 0x4f1bbcdcu ^ ((uint32_t)t * 0x1f123bb5u);
    uint32_t c = 0xa0761d65u + ((uint32_t)n * 0x7f4a7c15u);
    for (size_t i = 0; i < n; ++i) {
        uint32_t w = (uint32_t)b[i] + ((uint32_t)i << ((i & 3u) + 1u)) + r0(c, (unsigned)((i + t) & 15u));
        unsigned s = (unsigned)((a ^ c ^ w ^ (uint32_t)i ^ ((uint32_t)t << 2)) & 7u);
        a = f[s](a, w ^ c);
        if (((i + t) & 3u) == 1u) {
            c ^= f[(s + 3u) & 7u](c + 0x9e3779b9u, a ^ ((uint32_t)i * 0x45d9f3bu));
        } else {
            c += r1(a ^ w, (unsigned)((i * 5u + t) & 31u)) ^ 0x6d2b79f5u;
        }
    }
    return m0(a ^ r0(c, 9) ^ (uint32_t)(n * 0x27d4eb2du));
}

static uint32_t l1(const unsigned char *b, unsigned t) {
    uint32_t s = 0x243f6a88u ^ ((uint32_t)t * 0x9e3779b9u);
    for (unsigned i = 0; i < 11u; ++i) {
        uint32_t k = (uint32_t)b[(i * 7u + 3u) % 11u] + ((uint32_t)b[i] << ((i & 3u) + 4u));
        switch ((s ^ k ^ i ^ t) & 7u) {
            case 0u: s = q3(s, k + 0x13198a2eu); break;
            case 1u: s = q6(k ^ s, r0(s, 5)); break;
            case 2u: s ^= q1(s + k, 0xa4093822u ^ i); break;
            case 3u: s += q5(s ^ 0x299f31d0u, k); break;
            case 4u: s = r0(s + q2(k, s), (i + 11u) & 31u); break;
            case 5u: s = q7(s - k, k ^ 0x082efa98u); break;
            case 6u: s ^= r1(q0(s, k), (t + i) & 31u); break;
            default: s += q4(k + 0xec4e6c89u, s); break;
        }
    }
    return m1(s ^ r1(s, 17) ^ 0x452821e6u);
}

static uint32_t u0(const unsigned char *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

#if defined(CF_LICENSE_CRACKME_DELIVER_KEYGEN)
static uint64_t r2(uint64_t x, unsigned n) {
    n &= 63u;
    return (x << n) | (x >> ((64u - n) & 63u));
}

static void u1(unsigned char *p, uint32_t x) {
    p[0] = (unsigned char)x;
    p[1] = (unsigned char)(x >> 8);
    p[2] = (unsigned char)(x >> 16);
    p[3] = (unsigned char)(x >> 24);
}
#endif

static uint32_t u2(uint32_t a, uint32_t b, unsigned y, unsigned t) {
    uint32_t x = a + r0(b ^ 0xbead6b61u, t + 9u);
    x ^= (uint32_t)y * 0x1f1f1f1fu;
    x += ((uint32_t)t + 1u) * 0x7f4a7c15u;
    return m0(x ^ r1(a, 11) ^ 0x5bf03635u);
}

static unsigned char u3(uint32_t a, uint32_t b, unsigned y, unsigned z, unsigned t) {
    uint32_t x = a ^ r0(b, t + 5u) ^ ((uint32_t)y << 13) ^ ((uint32_t)(z & 0xfcu) << 21) ^ 0x91e10da5u;
    uint32_t k = m1(x) ^ m0(b + ((uint32_t)t * 0x45d9f3bu) + (a >> 3));
    return (unsigned char)((k >> 11) ^ (k >> 19) ^ ((uint32_t)t * 0x53u) ^ ((uint32_t)y * 13u));
}

static unsigned g0(int ch) {
    unsigned c = (unsigned char)ch;
    if (c >= (unsigned)'a' && c <= (unsigned)'z') {
        c -= 32u;
    }
    if (c >= (unsigned)'2' && c <= (unsigned)'9') {
        return c - (unsigned)'2';
    }
    if (c >= (unsigned)'A' && c <= (unsigned)'H') {
        return 8u + c - (unsigned)'A';
    }
    if (c >= (unsigned)'J' && c <= (unsigned)'N') {
        return 8u + c - (unsigned)'A' - 1u;
    }
    if (c >= (unsigned)'P' && c <= (unsigned)'Z') {
        return 8u + c - (unsigned)'A' - 2u;
    }
    return 255u;
}

static int g1(const char *in, unsigned char out[24]) {
    size_t n = 0;
    for (size_t i = 0; in[i] != 0; ++i) {
        unsigned c = (unsigned char)in[i];
        if (c == (unsigned)'-' || c == (unsigned)' ' || c == (unsigned)'\t' ||
            c == (unsigned)'\n' || c == (unsigned)'\r') {
            continue;
        }
        if (g0((int)c) >= 32u) {
            return -1;
        }
        if (c >= (unsigned)'a' && c <= (unsigned)'z') {
            c -= 32u;
        }
        if (n >= 24u) {
            return -1;
        }
        out[n++] = (unsigned char)c;
    }
    return n == 24u ? 0 : -1;
}

static int g2(const unsigned char in[24], unsigned char out[15]) {
    uint32_t acc = 0;
    unsigned bits = 0;
    unsigned j = 0;
    for (unsigned i = 0; i < 24u; ++i) {
        unsigned v = g0((int)in[i]);
        if (v >= 32u) {
            return 0;
        }
        acc = (acc << 5) | v;
        bits += 5u;
        if (bits >= 8u) {
            bits -= 8u;
            if (j >= 15u) {
                return 0;
            }
            out[j++] = (unsigned char)((acc >> bits) & 0xffu);
        }
    }
    return j == 15u && bits == 0u;
}

#if defined(CF_LICENSE_CRACKME_DELIVER_KEYGEN)
static unsigned char g3(unsigned v) {
    v &= 31u;
    if (v < 8u) {
        return (unsigned char)((unsigned)'2' + v);
    }
    v -= 8u;
    unsigned c = (unsigned)'A' + v;
    if (c >= (unsigned)'I') {
        ++c;
    }
    if (c >= (unsigned)'O') {
        ++c;
    }
    return (unsigned char)c;
}

static void g4(const unsigned char in[15], char out[27]) {
    uint32_t acc = 0;
    unsigned bits = 0;
    unsigned j = 0;
    unsigned w = 0;
    for (unsigned i = 0; i < 15u; ++i) {
        acc = (acc << 8) | in[i];
        bits += 8u;
        while (bits >= 5u) {
            bits -= 5u;
            if (j != 0u && (j % 7u) == 6u) {
                out[j++] = (char)'-';
            }
            out[j++] = (char)g3((acc >> bits) & 31u);
            ++w;
            (void)w;
        }
    }
}

static uint32_t h0(const char *s) {
    uint32_t h = 0xa9fc1a35u;
    uint32_t n = 0;
    for (size_t i = 0; s[i] != 0; ++i) {
        unsigned c = (unsigned char)s[i];
        if (c >= (unsigned)'A' && c <= (unsigned)'Z') {
            c += 32u;
        }
        if (c == (unsigned)'-' || c == (unsigned)'_' || c == (unsigned)' ') {
            continue;
        }
        h ^= c + 0x9e3779b9u + (h << 6) + (h >> 2);
        h = r0(h, 5) * 0x85ebca6bu + 0xc2b2ae35u + n * 0x27d4eb2du;
        ++n;
    }
    h ^= n * 0x165667b1u;
    return m0(h);
}

static int h1(const char *s) {
    uint32_t h = h0(s);
    if (h == 0xe6f99588u) {
        return 0;
    }
    if (h == 0x72dc8956u) {
        return 1;
    }
    if (h == 0x802fdf48u) {
        return 2;
    }
    if (h == 0x941a43b9u) {
        return 3;
    }
    return -1;
}

static uint64_t h2(int argc, char **argv, int start) {
    uint64_t h = 0x8a5cd789635d2dffull ^ ((uint64_t)(unsigned)argc * 0x9e3779b97f4a7c15ull);
    uint64_t c = 0x6a09e667f3bcc909ull;
    unsigned seen = 0;
    for (int a = start; a < argc; ++a) {
        for (size_t i = 0; argv[a][i] != 0; ++i) {
            unsigned ch = (unsigned char)argv[a][i];
            if (ch >= (unsigned)'A' && ch <= (unsigned)'Z') {
                ch += 32u;
            }
            h ^= (uint64_t)(ch + 0x31u + ((unsigned)a << 3)) * 0x100000001b3ull;
            h = r2(h, (unsigned)((ch ^ seen) & 31u) + 7u) * 0xd6e8feb86659fd93ull;
            c += h ^ ((uint64_t)ch << ((seen & 7u) * 8u));
            c = r2(c, 19) ^ 0xa0761d6478bd642full;
            ++seen;
        }
        h ^= 0x1full + ((uint64_t)a << 17);
        h = r2(h + c, 23) * 0x9e3779b185ebca87ull;
    }
    if (seen == 0u) {
        h ^= 0xfedcba9876543210ull;
        c += 0x243f6a8885a308d3ull;
    }
    h ^= c + r2(h, 41);
    h *= 0x94d049bb133111ebull;
    h ^= h >> 31;
    h *= 0xbf58476d1ce4e5b9ull;
    h ^= h >> 27;
    return h ^ (h >> 33);
}

static void k0(unsigned t, uint64_t owner, unsigned char b[15]) {
    uint32_t lo = (uint32_t)owner;
    uint32_t hi = (uint32_t)(owner >> 32);
    uint32_t a = m0(lo ^ r0(hi, 7u + t) ^ 0x76d5e9a3u);
    uint32_t n = m1(hi + r0(a, 3) + 0xa511e9b3u + t * 0x1f123bb5u);
    uint32_t c = m0((a ^ r1(n, t + 5u)) + 0xc3b2e187u);
    u1(b, a);
    u1(b + 4, n);
    b[8] = (unsigned char)((c >> 7) ^ (a >> 19) ^ 0x5bu);
    b[9] = (unsigned char)(((c >> 15) & 0xfcu) |
                           ((t ^ (((a >> 7) + (n >> 11) + 0x2du) & 3u)) & 3u));
    b[10] = u3(a, n, b[8], b[9], t);
    uint32_t tag = l0(b, 11u, t) ^ l1(b, t) ^ u2(a, n, b[8], t);
    u1(b + 11, tag);
}
#endif

struct k1 {
    unsigned ok;
    unsigned shape;
    unsigned tier;
    uint32_t mark;
};

/* Returns a packed verdict (bit0=ok, bit1=shape, bits2-3=tier) instead of a
 * by-value struct: a scalar return is virtualizable, an aggregate return is not.
 * The internal struct is kept so the decision logic is byte-for-byte unchanged. */
static unsigned k2(const char *s) {
    struct k1 v = { 0u, 0u, 0u, 0u };
    unsigned char a[24];
    unsigned char b[15];
    if (g1(s, a) == 0) {
        v.shape = 1u;
        if (g2(a, b)) {
            uint32_t x = u0(b);
            uint32_t y = u0(b + 4);
            unsigned cloak = (((x >> 7) + (y >> 11) + 0x2du) & 3u);
            unsigned tier = ((unsigned)b[9] & 3u) ^ cloak;
            if (tier < 4u) {
                uint32_t p = l1(b, tier);
                switch ((p ^ x ^ (uint32_t)b[8] ^ tier) & 7u) {
                    case 0u:
                    case 3u:
                    case 5u:
                        p ^= q2(p, y + b[10]);
                        break;
                    case 1u:
                    case 6u:
                        p += q5(x ^ p, y ^ b[9]);
                        break;
                    case 2u:
                        p = r0(p ^ q7(y, x), (tier + 9u) & 31u);
                        break;
                    default:
                        p ^= q4(y + p, x ^ 0xd1b54a35u);
                        break;
                }
                if ((((unsigned)b[9] & 3u) ^ cloak) == tier) {
                    unsigned char want = u3(x, y, b[8], b[9], tier);
                    if (b[10] == want) {
                        uint32_t tag = l0(b, 11u, tier) ^ l1(b, tier) ^ u2(x, y, b[8], tier);
                        uint32_t got = u0(b + 11);
                        if (got == tag) {
                            uint32_t last = p ^ tag ^ q6(x + b[8], y + b[10]);
                            volatile uint32_t drag = last ^ p ^ got;
                            if (drag != 0u || b[10] == want) {
                                v.ok = 1u;
                                v.tier = tier;
                                v.mark = last;
                            }
                        }
                    }
                }
            }
        }
    }
    return (v.ok & 1u) | ((v.shape & 1u) << 1) | ((v.tier & 3u) << 2);
}

static void k3(FILE *out) {
    e0(out);
    e1(out);
    e2(out);
    e3(out);
    fflush(out);
}

#if defined(CF_LICENSE_CRACKME_DELIVER_KEYGEN)
static int k4(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }
    if (h0(argv[1]) != 0x3fd868ecu) {
        return 0;
    }
    if (argc < 4) {
        e17(stdout);
        return 1;
    }
    int tier = h1(argv[2]);
    if (tier < 0) {
        e16(stdout);
        return 1;
    }
    unsigned char b[15];
    char out[27];
    k0((unsigned)tier, h2(argc, argv, 3), b);
    g4(b, out);
    e14(stdout);
    p0(stdout, (unsigned)tier);
    e15(stdout);
    fwrite(out, 1u, sizeof(out), stdout);
    fputc((int)'\n', stdout);
    return 1;
}
#endif

#if defined(CF_LICENSE_CRACKME_DELIVER_KEYGEN)
int main(int argc, char **argv) {
    if (k4(argc, argv)) {
        return 0;
    }
#else
int main(void) {
#endif
    char line[160];
    k3(stdout);
    if (fgets(line, (int)sizeof(line), stdin) == NULL) {
        e9(stdout);
        return 1;
    }
    unsigned verdict = k2(line);
    if (verdict & 1u) {
        e4(stdout);
        p0(stdout, (verdict >> 2) & 3u);
        e5(stdout);
        e6(stdout);
        return 0;
    }
    if ((verdict >> 1) & 1u) {
        e7(stdout);
        e8(stdout);
    } else {
        e9(stdout);
    }
    return 1;
}
