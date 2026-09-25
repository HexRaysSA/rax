/*
 * Many Floating Point Arguments
 *
 * Functions with many FP arguments to exercise FP register passing.
 * Most ABIs have separate FP registers for arguments.
 *
 * Features exercised:
 *   - FP register arguments (XMM, NEON, etc.)
 *   - Stack spillage for excess FP args
 *   - Single/double precision handling
 */

#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>
#include <string.h>

volatile double sink_d;
volatile float sink_f;

__attribute__((noinline))
double sum_8_doubles(double a, double b, double c, double d,
                     double e, double f, double g, double h) {
    return a + b + c + d + e + f + g + h;
}

__attribute__((noinline))
double sum_12_doubles(double a, double b, double c, double d,
                      double e, double f, double g, double h,
                      double i, double j, double k, double l) {
    return a + b + c + d + e + f + g + h + i + j + k + l;
}

__attribute__((noinline))
float sum_8_floats(float a, float b, float c, float d,
                   float e, float f, float g, float h) {
    return a + b + c + d + e + f + g + h;
}

__attribute__((noinline))
float sum_16_floats(float a, float b, float c, float d,
                    float e, float f, float g, float h,
                    float i, float j, float k, float l,
                    float m, float n, float o, float p) {
    return a + b + c + d + e + f + g + h +
           i + j + k + l + m + n + o + p;
}

__attribute__((noinline))
double weighted_double(double a, double b, double c, double d,
                       double w1, double w2, double w3, double w4) {
    return a * w1 + b * w2 + c * w3 + d * w4;
}

__attribute__((noinline))
double dot_product_8(double a1, double a2, double a3, double a4,
                     double b1, double b2, double b3, double b4) {
    return a1 * b1 + a2 * b2 + a3 * b3 + a4 * b4;
}

/* Recursive with many float args */
__attribute__((noinline))
double recursive_sum_f(int depth, double a, double b, double c, double d,
                       double e, double f, double g, double h) {
    if (depth <= 0) {
        return a + b + c + d + e + f + g + h;
    }
    return recursive_sum_f(depth - 1, a + 0.1, b + 0.1, c + 0.1, d + 0.1,
                          e + 0.1, f + 0.1, g + 0.1, h + 0.1);
}

int main(void) {
    double result_d = 0.0;
    float result_f = 0.0f;

    for (int i = 0; i < 1200; i++) { /* rax: was 100000 */
        double d = (double)i * 0.001;
        float f = (float)i * 0.001f;

        result_d += sum_8_doubles(d, d+0.1, d+0.2, d+0.3,
                                  d+0.4, d+0.5, d+0.6, d+0.7);

        result_d += sum_12_doubles(d, d+0.1, d+0.2, d+0.3, d+0.4, d+0.5,
                                   d+0.6, d+0.7, d+0.8, d+0.9, d+1.0, d+1.1);

        result_f += sum_8_floats(f, f+0.1f, f+0.2f, f+0.3f,
                                f+0.4f, f+0.5f, f+0.6f, f+0.7f);

        result_f += sum_16_floats(f, f+0.1f, f+0.2f, f+0.3f, f+0.4f, f+0.5f, f+0.6f, f+0.7f,
                                 f+0.8f, f+0.9f, f+1.0f, f+1.1f, f+1.2f, f+1.3f, f+1.4f, f+1.5f);

        result_d += weighted_double(d, d+1, d+2, d+3, 1.0, 2.0, 3.0, 4.0);

        result_d += dot_product_8(d, d+1, d+2, d+3, 0.5, 0.5, 0.5, 0.5);

        if (i % 1000 == 0) {
            result_d += recursive_sum_f(5, d, d+0.1, d+0.2, d+0.3,
                                        d+0.4, d+0.5, d+0.6, d+0.7);
        }
    }

    sink_d = result_d;
    sink_f = result_f;
    double sink_d_v = sink_d; /* rax: print the result so that runs can be compared */
    float sink_f_v = sink_f;
    uint64_t sink_d_bits;
    uint32_t sink_f_bits;
    memcpy(&sink_d_bits, &sink_d_v, sizeof sink_d_bits);
    memcpy(&sink_f_bits, &sink_f_v, sizeof sink_f_bits);
    printf("sink_d=%016" PRIx64 "\n", sink_d_bits);
    printf("sink_f=%08" PRIx32 "\n", sink_f_bits);
    return 0;
}
