/*
 * Many Integer Arguments
 *
 * Functions with many integer arguments to exercise register/stack passing.
 * Tests the calling convention's register allocation and stack spillage.
 *
 * Features exercised:
 *   - Register arguments (first N args)
 *   - Stack arguments (remaining args)
 *   - Argument ordering
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Prevent inlining to preserve call semantics */
__attribute__((noinline))
int64_t sum_8_args(int a, int b, int c, int d, int e, int f, int g, int h) {
    return (int64_t)a + b + c + d + e + f + g + h;
}

__attribute__((noinline))
int64_t sum_12_args(int a, int b, int c, int d, int e, int f,
                    int g, int h, int i, int j, int k, int l) {
    return (int64_t)a + b + c + d + e + f + g + h + i + j + k + l;
}

__attribute__((noinline))
int64_t sum_16_args(int a, int b, int c, int d, int e, int f, int g, int h,
                    int i, int j, int k, int l, int m, int n, int o, int p) {
    return (int64_t)a + b + c + d + e + f + g + h +
           i + j + k + l + m + n + o + p;
}

__attribute__((noinline))
int64_t weighted_sum(int a, int b, int c, int d, int e, int f, int g, int h,
                     int w1, int w2, int w3, int w4, int w5, int w6, int w7, int w8) {
    return (int64_t)a * w1 + (int64_t)b * w2 + (int64_t)c * w3 + (int64_t)d * w4 +
           (int64_t)e * w5 + (int64_t)f * w6 + (int64_t)g * w7 + (int64_t)h * w8;
}

/* 64-bit arguments on 32-bit platforms require pairs */
__attribute__((noinline))
int64_t sum_64bit_args(int64_t a, int64_t b, int64_t c, int64_t d,
                       int64_t e, int64_t f, int64_t g, int64_t h) {
    return a + b + c + d + e + f + g + h;
}

/* Mixed sizes */
__attribute__((noinline))
int64_t mixed_sizes(int8_t a, int16_t b, int32_t c, int64_t d,
                    uint8_t e, uint16_t f, uint32_t g, uint64_t h) {
    return (int64_t)a + b + c + d + e + f + g + (int64_t)h;
}

/* Recursive with many args */
__attribute__((noinline))
int64_t recursive_sum(int depth, int a, int b, int c, int d,
                      int e, int f, int g, int h) {
    if (depth <= 0) {
        return (int64_t)a + b + c + d + e + f + g + h;
    }
    return recursive_sum(depth - 1, a + 1, b + 1, c + 1, d + 1,
                        e + 1, f + 1, g + 1, h + 1);
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 1200; i++) { /* rax: was 100000 */
        result += sum_8_args(i, i+1, i+2, i+3, i+4, i+5, i+6, i+7);

        result += sum_12_args(i, i+1, i+2, i+3, i+4, i+5,
                             i+6, i+7, i+8, i+9, i+10, i+11);

        result += sum_16_args(i, i+1, i+2, i+3, i+4, i+5, i+6, i+7,
                             i+8, i+9, i+10, i+11, i+12, i+13, i+14, i+15);

        result += weighted_sum(i, i+1, i+2, i+3, i+4, i+5, i+6, i+7,
                              1, 2, 3, 4, 5, 6, 7, 8);

        result += sum_64bit_args(i, i*2, i*3, i*4, i*5, i*6, i*7, i*8);

        result += mixed_sizes((int8_t)i, (int16_t)i, i, (int64_t)i,
                             (uint8_t)i, (uint16_t)i, (uint32_t)i, (uint64_t)i);

        if (i % 1000 == 0) {
            result += recursive_sum(5, i, i+1, i+2, i+3, i+4, i+5, i+6, i+7);
        }
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
