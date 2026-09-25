/*
 * Mixed Integer and Floating Point Arguments
 *
 * Tests interleaved int/float arguments.
 * Most ABIs use separate register sets for int/float.
 *
 * Features exercised:
 *   - Interleaved argument types
 *   - Register allocation across types
 *   - Type promotion/demotion
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>
#include <string.h>

volatile double sink;

__attribute__((noinline))
double mixed_8(int a, double b, int c, double d,
               int e, double f, int g, double h) {
    return (double)a + b + (double)c + d + (double)e + f + (double)g + h;
}

__attribute__((noinline))
double mixed_16(int a1, double b1, int a2, double b2,
                int a3, double b3, int a4, double b4,
                int a5, double b5, int a6, double b6,
                int a7, double b7, int a8, double b8) {
    return (double)(a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8) +
           b1 + b2 + b3 + b4 + b5 + b6 + b7 + b8;
}

__attribute__((noinline))
double float_int_float(float a, int b, float c, int d,
                       float e, int f, float g, int h) {
    return (double)a + (double)b + (double)c + (double)d +
           (double)e + (double)f + (double)g + (double)h;
}

__attribute__((noinline))
double pointer_and_values(int *p1, double v1, int *p2, double v2,
                          int *p3, double v3, int *p4, double v4) {
    return (double)*p1 + v1 + (double)*p2 + v2 +
           (double)*p3 + v3 + (double)*p4 + v4;
}

__attribute__((noinline))
double many_mixed(int8_t a, float b, int16_t c, double d,
                  int32_t e, float f, int64_t g, double h,
                  uint8_t i, float j, uint16_t k, double l) {
    return (double)a + b + (double)c + d + (double)e + f +
           (double)g + h + (double)i + j + (double)k + l;
}

int main(void) {
    double result = 0.0;
    int vals[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    for (int i = 0; i < 1500; i++) { /* rax: was 100000 */
        double d = (double)i * 0.001;

        result += mixed_8(i, d, i+1, d+0.1, i+2, d+0.2, i+3, d+0.3);

        result += mixed_16(i, d, i+1, d+0.1, i+2, d+0.2, i+3, d+0.3,
                          i+4, d+0.4, i+5, d+0.5, i+6, d+0.6, i+7, d+0.7);

        result += float_int_float((float)d, i, (float)(d+0.1), i+1,
                                 (float)(d+0.2), i+2, (float)(d+0.3), i+3);

        result += pointer_and_values(&vals[0], d, &vals[1], d+0.1,
                                    &vals[2], d+0.2, &vals[3], d+0.3);

        result += many_mixed((int8_t)i, (float)d, (int16_t)i, d,
                            i, (float)d, (int64_t)i, d,
                            (uint8_t)i, (float)d, (uint16_t)i, d);

        vals[i % 8] = i;
    }

    sink = result;
    double sink_v = sink; /* rax: print the result so that runs can be compared */
    uint64_t sink_bits;
    memcpy(&sink_bits, &sink_v, sizeof sink_bits);
    printf("sink=%016" PRIx64 "\n", sink_bits);
    return 0;
}
