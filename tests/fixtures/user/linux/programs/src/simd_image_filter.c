/*
 * SIMD Image Box Blur Filter
 *
 * Applies 3x3 box blur using SIMD instructions.
 * Common pattern in image processing pipelines.
 *
 * Features exercised:
 *   x86:    SSE/AVX packed byte operations, unpack, average
 *   ARM:    NEON vld, vst, vhadd
 */

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define HAS_X86_SIMD 1
#endif

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#define HAS_NEON 1
#endif

#define WIDTH 64 /* rax: was 128 */
#define HEIGHT 64 /* rax: was 128 */

volatile uint8_t sink;

static uint8_t input[HEIGHT][WIDTH];
static uint8_t output[HEIGHT][WIDTH];

/* Scalar 3x3 box blur */
void box_blur_scalar(void) {
    for (int y = 1; y < HEIGHT - 1; y++) {
        for (int x = 1; x < WIDTH - 1; x++) {
            int sum = 0;
            for (int dy = -1; dy <= 1; dy++) {
                for (int dx = -1; dx <= 1; dx++) {
                    sum += input[y + dy][x + dx];
                }
            }
            output[y][x] = (uint8_t)(sum / 9);
        }
    }
}

#if defined(HAS_X86_SIMD) && defined(__SSE2__)
void box_blur_sse2(void) {
    for (int y = 1; y < HEIGHT - 1; y++) {
        for (int x = 1; x < WIDTH - 1 - 16; x += 16) {
            __m128i sum = _mm_setzero_si128();

            /* Process 3x3 neighborhood */
            for (int dy = -1; dy <= 1; dy++) {
                /* Load 16 bytes from each row position */
                __m128i row_left = _mm_loadu_si128((__m128i *)&input[y + dy][x - 1]);
                __m128i row_center = _mm_loadu_si128((__m128i *)&input[y + dy][x]);
                __m128i row_right = _mm_loadu_si128((__m128i *)&input[y + dy][x + 1]);

                /* Unpack to 16-bit for accumulation */
                __m128i lo_l = _mm_unpacklo_epi8(row_left, _mm_setzero_si128());
                __m128i lo_c = _mm_unpacklo_epi8(row_center, _mm_setzero_si128());
                __m128i lo_r = _mm_unpacklo_epi8(row_right, _mm_setzero_si128());

                sum = _mm_add_epi16(sum, lo_l);
                sum = _mm_add_epi16(sum, lo_c);
                sum = _mm_add_epi16(sum, lo_r);
            }

            /* Divide by 9 (approximate with multiply and shift) */
            /* 9 ~= 1/9 * 65536 = 7282 */
            __m128i divisor = _mm_set1_epi16(7282);
            sum = _mm_mulhi_epu16(sum, divisor);

            /* Pack back to bytes */
            __m128i result = _mm_packus_epi16(sum, _mm_setzero_si128());
            _mm_storel_epi64((__m128i *)&output[y][x], result);
        }
    }
}
#endif

#if defined(HAS_NEON)
void box_blur_neon(void) {
    for (int y = 1; y < HEIGHT - 1; y++) {
        for (int x = 1; x < WIDTH - 1 - 8; x += 8) {
            uint16x8_t sum = vdupq_n_u16(0);

            /* Process 3x3 neighborhood */
            for (int dy = -1; dy <= 1; dy++) {
                uint8x8_t row_left = vld1_u8(&input[y + dy][x - 1]);
                uint8x8_t row_center = vld1_u8(&input[y + dy][x]);
                uint8x8_t row_right = vld1_u8(&input[y + dy][x + 1]);

                /* Widen and accumulate */
                sum = vaddw_u8(sum, row_left);
                sum = vaddw_u8(sum, row_center);
                sum = vaddw_u8(sum, row_right);
            }

            /* Divide by 9: multiply by 7282 and take high 16 bits */
            uint16x8_t divisor = vdupq_n_u16(7282);
            uint32x4_t prod_lo = vmull_u16(vget_low_u16(sum), vget_low_u16(divisor));
            uint32x4_t prod_hi = vmull_u16(vget_high_u16(sum), vget_high_u16(divisor));
            uint16x4_t result_lo = vshrn_n_u32(prod_lo, 16);
            uint16x4_t result_hi = vshrn_n_u32(prod_hi, 16);
            uint16x8_t result16 = vcombine_u16(result_lo, result_hi);

            /* Narrow to 8-bit */
            uint8x8_t result = vmovn_u16(result16);
            vst1_u8(&output[y][x], result);
        }
    }
}
#endif

int main(void) {
    /* Initialize input image with gradient pattern */
    for (int y = 0; y < HEIGHT; y++) {
        for (int x = 0; x < WIDTH; x++) {
            input[y][x] = (uint8_t)((x + y) & 0xFF);
        }
    }

    for (int iter = 0; iter < 3; iter++) { /* rax: was 1000 */
        /* Use best available SIMD implementation */
#if defined(HAS_X86_SIMD) && defined(__SSE2__)
        box_blur_sse2();
#elif defined(HAS_NEON)
        box_blur_neon();
#else
        box_blur_scalar();
#endif

        /* Swap buffers */
        for (int y = 1; y < HEIGHT - 1; y++) {
            for (int x = 1; x < WIDTH - 1; x++) {
                input[y][x] = output[y][x];
            }
        }
    }

    /* Prevent optimization */
    uint8_t sum = 0;
    for (int i = 0; i < HEIGHT; i++) {
        for (int j = 0; j < WIDTH; j++) {
            sum ^= output[i][j];
        }
    }
    sink = sum;

    uint64_t output_digest = UINT64_C(0xcbf29ce484222325); /* rax: print the result so that runs can be compared */
    for (int i = 0; i < HEIGHT; i++) {
        for (int j = 0; j < WIDTH; j++) {
            output_digest = (output_digest ^ output[i][j]) * UINT64_C(0x100000001b3);
        }
    }
    printf("sum=%u\n", (unsigned)sum);
    printf("output_digest=%016" PRIx64 "\n", output_digest);
    return 0;
}
