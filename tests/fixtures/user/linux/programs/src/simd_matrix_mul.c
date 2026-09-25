/*
 * SIMD Matrix Multiplication
 *
 * 4x4 matrix multiply using SIMD intrinsics.
 * Common operation in graphics and ML workloads.
 *
 * Features exercised:
 *   x86:    SSE/AVX shuffle, broadcast, FMA
 *   ARM:    NEON vfma, transpose
 */

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

#define MATRIX_SIZE 4

volatile float sink;

typedef struct {
    float m[MATRIX_SIZE][MATRIX_SIZE];
} Matrix4x4;

/* Scalar implementation */
void matrix_mul_scalar(const Matrix4x4 *a, const Matrix4x4 *b, Matrix4x4 *c) {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            float sum = 0.0f;
            for (int k = 0; k < MATRIX_SIZE; k++) {
                sum += a->m[i][k] * b->m[k][j];
            }
            c->m[i][j] = sum;
        }
    }
}

#if defined(HAS_X86_SIMD) && defined(__SSE__)
void matrix_mul_sse(const Matrix4x4 *a, const Matrix4x4 *b, Matrix4x4 *c) {
    /* Load B columns */
    __m128 b_col0 = _mm_set_ps(b->m[3][0], b->m[2][0], b->m[1][0], b->m[0][0]);
    __m128 b_col1 = _mm_set_ps(b->m[3][1], b->m[2][1], b->m[1][1], b->m[0][1]);
    __m128 b_col2 = _mm_set_ps(b->m[3][2], b->m[2][2], b->m[1][2], b->m[0][2]);
    __m128 b_col3 = _mm_set_ps(b->m[3][3], b->m[2][3], b->m[1][3], b->m[0][3]);

    for (int i = 0; i < MATRIX_SIZE; i++) {
        __m128 a_row = _mm_loadu_ps(a->m[i]);

        /* Broadcast each element of a_row and multiply with B columns */
        __m128 a0 = _mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(0, 0, 0, 0));
        __m128 a1 = _mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(1, 1, 1, 1));
        __m128 a2 = _mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(2, 2, 2, 2));
        __m128 a3 = _mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(3, 3, 3, 3));

        __m128 result = _mm_mul_ps(a0, b_col0);
        result = _mm_add_ps(result, _mm_mul_ps(a1, b_col1));
        result = _mm_add_ps(result, _mm_mul_ps(a2, b_col2));
        result = _mm_add_ps(result, _mm_mul_ps(a3, b_col3));

        _mm_storeu_ps(c->m[i], result);
    }
}
#endif

#if defined(HAS_NEON)
void matrix_mul_neon(const Matrix4x4 *a, const Matrix4x4 *b, Matrix4x4 *c) {
    /* Load all columns of B */
    float32x4_t b_col0 = {b->m[0][0], b->m[1][0], b->m[2][0], b->m[3][0]};
    float32x4_t b_col1 = {b->m[0][1], b->m[1][1], b->m[2][1], b->m[3][1]};
    float32x4_t b_col2 = {b->m[0][2], b->m[1][2], b->m[2][2], b->m[3][2]};
    float32x4_t b_col3 = {b->m[0][3], b->m[1][3], b->m[2][3], b->m[3][3]};

    for (int i = 0; i < MATRIX_SIZE; i++) {
        float32x4_t a_row = vld1q_f32(a->m[i]);

        /* Multiply and accumulate */
        float32x4_t result = vmulq_n_f32(b_col0, vgetq_lane_f32(a_row, 0));
        result = vmlaq_n_f32(result, b_col1, vgetq_lane_f32(a_row, 1));
        result = vmlaq_n_f32(result, b_col2, vgetq_lane_f32(a_row, 2));
        result = vmlaq_n_f32(result, b_col3, vgetq_lane_f32(a_row, 3));

        vst1q_f32(c->m[i], result);
    }
}
#endif

int main(void) {
    Matrix4x4 a, b, c;

    /* Initialize matrices */
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            a.m[i][j] = (float)(i * MATRIX_SIZE + j + 1) * 0.1f;
            b.m[i][j] = (float)((i + j) % MATRIX_SIZE + 1) * 0.1f;
        }
    }

    float result_sum = 0.0f;

    for (int iter = 0; iter < 2000; iter++) { /* rax: was 100000 */
        /* Use best available SIMD implementation */
#if defined(HAS_X86_SIMD) && defined(__SSE__)
        matrix_mul_sse(&a, &b, &c);
#elif defined(HAS_NEON)
        matrix_mul_neon(&a, &b, &c);
#else
        matrix_mul_scalar(&a, &b, &c);
#endif

        /* Accumulate results */
        for (int i = 0; i < MATRIX_SIZE; i++) {
            for (int j = 0; j < MATRIX_SIZE; j++) {
                result_sum += c.m[i][j];
            }
        }

        /* Use result as next input to prevent optimization */
        a = c;
    }

    sink = result_sum;
    uint32_t result_sum_bits; /* rax: print the result so that runs can be compared */
    memcpy(&result_sum_bits, &result_sum, sizeof result_sum_bits);
    printf("result_sum=%08" PRIx32 "\n", result_sum_bits);
    return 0;
}
