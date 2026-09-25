/*
 * SIMD Dot Product
 *
 * Computes vector dot product using SIMD intrinsics.
 * Uses architecture-specific intrinsics with scalar fallback.
 *
 * Features exercised:
 *   x86:    SSE/AVX multiply, add, horizontal sum
 *   ARM:    NEON vfma, vaddv
 *   RISC-V: RVV (if available)
 */

#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define HAS_X86_SIMD 1
#endif

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#define HAS_NEON 1
#endif

#define ARRAY_SIZE 1024

volatile float sink;

static float a[ARRAY_SIZE];
static float b[ARRAY_SIZE];

float dot_product_scalar(const float *x, const float *y, size_t n) {
    float sum = 0.0f;
    for (size_t i = 0; i < n; i++) {
        sum += x[i] * y[i];
    }
    return sum;
}

#if defined(HAS_X86_SIMD) && defined(__SSE__)
float dot_product_sse(const float *x, const float *y, size_t n) {
    __m128 sum = _mm_setzero_ps();
    size_t i = 0;

    for (; i + 4 <= n; i += 4) {
        __m128 vx = _mm_loadu_ps(&x[i]);
        __m128 vy = _mm_loadu_ps(&y[i]);
        sum = _mm_add_ps(sum, _mm_mul_ps(vx, vy));
    }

    /* Horizontal sum */
    __m128 shuf = _mm_shuffle_ps(sum, sum, _MM_SHUFFLE(2, 3, 0, 1));
    sum = _mm_add_ps(sum, shuf);
    shuf = _mm_movehl_ps(shuf, sum);
    sum = _mm_add_ss(sum, shuf);

    float result = _mm_cvtss_f32(sum);

    /* Handle remaining elements */
    for (; i < n; i++) {
        result += x[i] * y[i];
    }

    return result;
}
#endif

#if defined(HAS_X86_SIMD) && defined(__AVX__)
float dot_product_avx(const float *x, const float *y, size_t n) {
    __m256 sum = _mm256_setzero_ps();
    size_t i = 0;

    for (; i + 8 <= n; i += 8) {
        __m256 vx = _mm256_loadu_ps(&x[i]);
        __m256 vy = _mm256_loadu_ps(&y[i]);
        sum = _mm256_add_ps(sum, _mm256_mul_ps(vx, vy));
    }

    /* Horizontal sum across 256-bit vector */
    __m128 hi = _mm256_extractf128_ps(sum, 1);
    __m128 lo = _mm256_castps256_ps128(sum);
    __m128 sum128 = _mm_add_ps(lo, hi);

    __m128 shuf = _mm_shuffle_ps(sum128, sum128, _MM_SHUFFLE(2, 3, 0, 1));
    sum128 = _mm_add_ps(sum128, shuf);
    shuf = _mm_movehl_ps(shuf, sum128);
    sum128 = _mm_add_ss(sum128, shuf);

    float result = _mm_cvtss_f32(sum128);

    /* Handle remaining elements */
    for (; i < n; i++) {
        result += x[i] * y[i];
    }

    return result;
}
#endif

#if defined(HAS_NEON)
float dot_product_neon(const float *x, const float *y, size_t n) {
    float32x4_t sum = vdupq_n_f32(0.0f);
    size_t i = 0;

    for (; i + 4 <= n; i += 4) {
        float32x4_t vx = vld1q_f32(&x[i]);
        float32x4_t vy = vld1q_f32(&y[i]);
        sum = vmlaq_f32(sum, vx, vy);
    }

    /* Horizontal sum */
#if defined(__aarch64__)
    float result = vaddvq_f32(sum);
#else
    float32x2_t sum2 = vadd_f32(vget_low_f32(sum), vget_high_f32(sum));
    sum2 = vpadd_f32(sum2, sum2);
    float result = vget_lane_f32(sum2, 0);
#endif

    /* Handle remaining elements */
    for (; i < n; i++) {
        result += x[i] * y[i];
    }

    return result;
}
#endif

int main(void) {
    /* Initialize arrays */
    for (int i = 0; i < ARRAY_SIZE; i++) {
        a[i] = (float)(i % 100) * 0.01f;
        b[i] = (float)((i * 7) % 100) * 0.01f;
    }

    float result = 0.0f;

    for (int iter = 0; iter < 40; iter++) { /* rax: was 10000 */
        /* Use best available SIMD implementation */
#if defined(HAS_X86_SIMD) && defined(__AVX__)
        result += dot_product_avx(a, b, ARRAY_SIZE);
#elif defined(HAS_X86_SIMD) && defined(__SSE__)
        result += dot_product_sse(a, b, ARRAY_SIZE);
#elif defined(HAS_NEON)
        result += dot_product_neon(a, b, ARRAY_SIZE);
#else
        result += dot_product_scalar(a, b, ARRAY_SIZE);
#endif
    }

    sink = result;
    uint32_t result_bits; /* rax: print the result so that runs can be compared */
    memcpy(&result_bits, &result, sizeof result_bits);
    printf("result=%08" PRIx32 "\n", result_bits);
    return 0;
}
