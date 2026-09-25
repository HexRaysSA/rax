/*
 * Sequential Memory Access Patterns
 *
 * Tests linear memory traversal patterns.
 * Exercises prefetching and cache line utilization.
 *
 * Features exercised:
 *   - Sequential reads and writes
 *   - Stream processing
 *   - Cache-friendly access patterns
 *   - Memory bandwidth utilization
 */

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

#define ARRAY_SIZE 1024 /* rax: was 4096 */

volatile int64_t sink;

static int32_t array_a[ARRAY_SIZE];
static int32_t array_b[ARRAY_SIZE];
static int32_t array_c[ARRAY_SIZE];
static double array_d[ARRAY_SIZE];
static double array_e[ARRAY_SIZE];

/* Sequential read */
__attribute__((noinline))
int64_t sequential_read(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

/* Sequential write */
__attribute__((noinline))
void sequential_write(int32_t *arr, size_t len, int32_t value) {
    for (size_t i = 0; i < len; i++) {
        arr[i] = value + (int32_t)i;
    }
}

/* Sequential copy */
__attribute__((noinline))
void sequential_copy(int32_t *dst, const int32_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

/* Sequential add (a = b + c) */
__attribute__((noinline))
void sequential_add(int32_t *a, const int32_t *b, const int32_t *c, size_t len) {
    for (size_t i = 0; i < len; i++) {
        a[i] = b[i] + c[i];
    }
}

/* Sequential scale (a = b * scalar) */
__attribute__((noinline))
void sequential_scale(int32_t *a, const int32_t *b, int32_t scalar, size_t len) {
    for (size_t i = 0; i < len; i++) {
        a[i] = b[i] * scalar;
    }
}

/* Sequential FMA (a = b * c + d) */
__attribute__((noinline))
void sequential_fma(double *a, const double *b, const double *c, const double *d, size_t len) {
    for (size_t i = 0; i < len; i++) {
        a[i] = b[i] * c[i] + d[i];
    }
}

/* Triad (a = b + scalar * c) - classic bandwidth test */
__attribute__((noinline))
void sequential_triad(double *a, const double *b, const double *c, double scalar, size_t len) {
    for (size_t i = 0; i < len; i++) {
        a[i] = b[i] + scalar * c[i];
    }
}

/* Sequential reduction */
__attribute__((noinline))
int32_t sequential_reduce_min(const int32_t *arr, size_t len) {
    int32_t min_val = arr[0];
    for (size_t i = 1; i < len; i++) {
        if (arr[i] < min_val) {
            min_val = arr[i];
        }
    }
    return min_val;
}

__attribute__((noinline))
int32_t sequential_reduce_max(const int32_t *arr, size_t len) {
    int32_t max_val = arr[0];
    for (size_t i = 1; i < len; i++) {
        if (arr[i] > max_val) {
            max_val = arr[i];
        }
    }
    return max_val;
}

/* Sequential search */
__attribute__((noinline))
int sequential_find(const int32_t *arr, size_t len, int32_t target) {
    for (size_t i = 0; i < len; i++) {
        if (arr[i] == target) {
            return (int)i;
        }
    }
    return -1;
}

/* Sequential count */
__attribute__((noinline))
size_t sequential_count(const int32_t *arr, size_t len, int32_t value) {
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        if (arr[i] == value) {
            count++;
        }
    }
    return count;
}

/* Sequential filter (copy matching elements) */
__attribute__((noinline))
size_t sequential_filter(int32_t *dst, const int32_t *src, size_t len, int32_t threshold) {
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (src[i] > threshold) {
            dst[j++] = src[i];
        }
    }
    return j;
}

/* Sequential transform */
__attribute__((noinline))
void sequential_transform(int32_t *arr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int32_t x = arr[i];
        arr[i] = ((x * 3) >> 1) + (x & 0xFF);
    }
}

/* Sequential dot product */
__attribute__((noinline))
double sequential_dot(const double *a, const double *b, size_t len) {
    double sum = 0.0;
    for (size_t i = 0; i < len; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

/* Sequential accumulate with dependency */
__attribute__((noinline))
int64_t sequential_dependent(const int32_t *arr, size_t len) {
    int64_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc = acc * 3 + arr[i];
    }
    return acc;
}

/* Multiple sequential passes */
__attribute__((noinline))
void multi_pass(int32_t *arr, size_t len, int passes) {
    for (int p = 0; p < passes; p++) {
        for (size_t i = 0; i < len; i++) {
            arr[i] = arr[i] + p;
        }
    }
}

/* Forward and backward sequential access */
__attribute__((noinline))
int64_t forward_backward(const int32_t *arr, size_t len) {
    int64_t sum = 0;

    /* Forward pass */
    for (size_t i = 0; i < len; i++) {
        sum += arr[i];
    }

    /* Backward pass */
    for (size_t i = len; i > 0; i--) {
        sum += arr[i - 1];
    }

    return sum;
}

int main(void) {
    int64_t result = 0;

    /* Initialize arrays */
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        array_a[i] = (int32_t)i;
        array_b[i] = (int32_t)(i * 2);
        array_c[i] = (int32_t)(i % 100);
        array_d[i] = (double)i * 0.1;
        array_e[i] = (double)i * 0.2;
    }

    for (int iter = 0; iter < 3; iter++) { /* rax: was 1000 */
        /* Sequential read */
        result += sequential_read(array_a, ARRAY_SIZE);

        /* Sequential write */
        sequential_write(array_b, ARRAY_SIZE, iter);

        /* Sequential copy */
        sequential_copy(array_c, array_a, ARRAY_SIZE);

        /* Sequential add */
        sequential_add(array_a, array_b, array_c, ARRAY_SIZE);

        /* Sequential scale */
        sequential_scale(array_c, array_b, 3, ARRAY_SIZE);

        /* Sequential FMA */
        sequential_fma(array_d, array_d, array_e, array_e, ARRAY_SIZE);

        /* Sequential triad */
        sequential_triad(array_e, array_d, array_e, 2.5, ARRAY_SIZE);

        /* Reductions */
        result += sequential_reduce_min(array_a, ARRAY_SIZE);
        result += sequential_reduce_max(array_a, ARRAY_SIZE);

        /* Search */
        result += sequential_find(array_a, ARRAY_SIZE, iter % ARRAY_SIZE);

        /* Count */
        result += (int64_t)sequential_count(array_c, ARRAY_SIZE, iter % 100);

        /* Filter */
        result += (int64_t)sequential_filter(array_b, array_a, ARRAY_SIZE, ARRAY_SIZE / 2);

        /* Transform */
        sequential_transform(array_c, ARRAY_SIZE);

        /* Dot product */
        result += (int64_t)sequential_dot(array_d, array_e, ARRAY_SIZE);

        /* Dependent accumulate */
        result += sequential_dependent(array_c, 256);

        /* Multi-pass */
        if (iter % 100 == 0) {
            multi_pass(array_b, ARRAY_SIZE, 3);
        }

        /* Forward/backward */
        result += forward_backward(array_a, 512);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", (int64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
