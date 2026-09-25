/*
 * SIMD String Search (memchr-like)
 *
 * Searches for a byte in a buffer using SIMD instructions.
 * Pattern found in string libraries and parsers.
 *
 * Features exercised:
 *   x86:    SSE2/AVX2 pcmpeqb, pmovmskb
 *   ARM:    NEON vceq, vmaxv
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h> /* rax: print the result so that runs can be compared */

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define HAS_X86_SIMD 1
#endif

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#define HAS_NEON 1
#endif

#define BUFFER_SIZE 4096

volatile size_t sink;

static char buffer[BUFFER_SIZE];

/* Scalar implementation */
const char *memchr_scalar(const char *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    unsigned char uc = (unsigned char)c;

    while (n--) {
        if (*p == uc) {
            return (const char *)p;
        }
        p++;
    }
    return NULL;
}

#if defined(HAS_X86_SIMD) && defined(__SSE2__)
const char *memchr_sse2(const char *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    unsigned char uc = (unsigned char)c;

    /* Create mask with search byte in all positions */
    __m128i needle = _mm_set1_epi8((char)uc);

    /* Process 16 bytes at a time */
    while (n >= 16) {
        __m128i chunk = _mm_loadu_si128((const __m128i *)p);
        __m128i cmp = _mm_cmpeq_epi8(chunk, needle);
        int mask = _mm_movemask_epi8(cmp);

        if (mask != 0) {
            /* Find position of first match */
            int pos = __builtin_ctz(mask);
            return (const char *)(p + pos);
        }

        p += 16;
        n -= 16;
    }

    /* Handle remaining bytes */
    while (n--) {
        if (*p == uc) {
            return (const char *)p;
        }
        p++;
    }

    return NULL;
}
#endif

#if defined(HAS_X86_SIMD) && defined(__AVX2__)
const char *memchr_avx2(const char *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    unsigned char uc = (unsigned char)c;

    __m256i needle = _mm256_set1_epi8((char)uc);

    /* Process 32 bytes at a time */
    while (n >= 32) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)p);
        __m256i cmp = _mm256_cmpeq_epi8(chunk, needle);
        int mask = _mm256_movemask_epi8(cmp);

        if (mask != 0) {
            int pos = __builtin_ctz(mask);
            return (const char *)(p + pos);
        }

        p += 32;
        n -= 32;
    }

    /* Fall back to SSE2 for remainder */
    return memchr_sse2((const char *)p, c, n);
}
#endif

#if defined(HAS_NEON)
const char *memchr_neon(const char *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    unsigned char uc = (unsigned char)c;

    uint8x16_t needle = vdupq_n_u8(uc);

    /* Process 16 bytes at a time */
    while (n >= 16) {
        uint8x16_t chunk = vld1q_u8(p);
        uint8x16_t cmp = vceqq_u8(chunk, needle);

#if defined(__aarch64__)
        /* Check if any match */
        if (vmaxvq_u8(cmp) != 0) {
            /* Find first match position */
            for (int i = 0; i < 16; i++) {
                if (p[i] == uc) {
                    return (const char *)(p + i);
                }
            }
        }
#else
        /* ARM32: Check if any match using horizontal max */
        uint8x8_t max1 = vpmax_u8(vget_low_u8(cmp), vget_high_u8(cmp));
        uint8x8_t max2 = vpmax_u8(max1, max1);
        uint8x8_t max3 = vpmax_u8(max2, max2);
        uint8x8_t max4 = vpmax_u8(max3, max3);
        if (vget_lane_u8(max4, 0) != 0) {
            for (int i = 0; i < 16; i++) {
                if (p[i] == uc) {
                    return (const char *)(p + i);
                }
            }
        }
#endif

        p += 16;
        n -= 16;
    }

    /* Handle remaining bytes */
    while (n--) {
        if (*p == uc) {
            return (const char *)p;
        }
        p++;
    }

    return NULL;
}
#endif

int main(void) {
    /* Initialize buffer with pseudo-random data */
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = (char)((i * 17 + 31) % 256);
    }

    size_t total_found = 0;

    for (int iter = 0; iter < 300; iter++) { /* rax: was 10000 */
        /* Search for different bytes */
        int search_byte = iter % 256;

#if defined(HAS_X86_SIMD) && defined(__AVX2__)
        const char *found = memchr_avx2(buffer, search_byte, BUFFER_SIZE);
#elif defined(HAS_X86_SIMD) && defined(__SSE2__)
        const char *found = memchr_sse2(buffer, search_byte, BUFFER_SIZE);
#elif defined(HAS_NEON)
        const char *found = memchr_neon(buffer, search_byte, BUFFER_SIZE);
#else
        const char *found = memchr_scalar(buffer, search_byte, BUFFER_SIZE);
#endif

        if (found != NULL) {
            total_found += (size_t)(found - buffer);
        }
    }

    sink = total_found;
    printf("total_found=%zu\n", total_found); /* rax: print the result so that runs can be compared */
    return 0;
}
