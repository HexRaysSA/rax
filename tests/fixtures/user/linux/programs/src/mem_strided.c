/*
 * Strided Memory Access Patterns
 *
 * Tests non-contiguous memory access with regular strides.
 * Exercises cache behavior with various stride patterns.
 *
 * Features exercised:
 *   - Power-of-2 strides
 *   - Non-power-of-2 strides
 *   - Column-major access
 *   - Struct member access
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>
#include <stddef.h>

#define ARRAY_SIZE 4096
#define MATRIX_DIM 64

volatile int64_t sink;

static int32_t linear_array[ARRAY_SIZE];
static int32_t matrix[MATRIX_DIM][MATRIX_DIM];

/* Structure with padding - accessing single field has stride */
typedef struct {
    int32_t x;
    int32_t y;
    int32_t z;
    int32_t w;
} Vec4;

typedef struct {
    int32_t value;
    char padding[60]; /* Force 64-byte stride */
} PaddedInt;

static Vec4 vec_array[ARRAY_SIZE / 4];
static PaddedInt padded_array[1024];

/* Fixed stride access */
__attribute__((noinline))
int64_t stride_2(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 2) {
        sum += arr[i];
    }
    return sum;
}

__attribute__((noinline))
int64_t stride_4(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 4) {
        sum += arr[i];
    }
    return sum;
}

__attribute__((noinline))
int64_t stride_8(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 8) {
        sum += arr[i];
    }
    return sum;
}

__attribute__((noinline))
int64_t stride_16(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 16) {
        sum += arr[i];
    }
    return sum;
}

__attribute__((noinline))
int64_t stride_64(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 64) {
        sum += arr[i];
    }
    return sum;
}

/* Variable stride */
__attribute__((noinline))
int64_t stride_n(const int32_t *arr, size_t len, size_t stride) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += stride) {
        sum += arr[i];
    }
    return sum;
}

/* Non-power-of-2 strides */
__attribute__((noinline))
int64_t stride_3(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 3) {
        sum += arr[i];
    }
    return sum;
}

__attribute__((noinline))
int64_t stride_5(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 5) {
        sum += arr[i];
    }
    return sum;
}

__attribute__((noinline))
int64_t stride_7(const int32_t *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i += 7) {
        sum += arr[i];
    }
    return sum;
}

/* Column-major access (stride = row size) */
__attribute__((noinline))
int64_t column_access(const int32_t mat[MATRIX_DIM][MATRIX_DIM], size_t col) {
    int64_t sum = 0;
    for (size_t row = 0; row < MATRIX_DIM; row++) {
        sum += mat[row][col];
    }
    return sum;
}

/* Diagonal access */
__attribute__((noinline))
int64_t diagonal_access(const int32_t mat[MATRIX_DIM][MATRIX_DIM]) {
    int64_t sum = 0;
    for (size_t i = 0; i < MATRIX_DIM; i++) {
        sum += mat[i][i];
    }
    return sum;
}

/* Anti-diagonal access */
__attribute__((noinline))
int64_t anti_diagonal_access(const int32_t mat[MATRIX_DIM][MATRIX_DIM]) {
    int64_t sum = 0;
    for (size_t i = 0; i < MATRIX_DIM; i++) {
        sum += mat[i][MATRIX_DIM - 1 - i];
    }
    return sum;
}

/* Struct field access - accessing x gives stride of sizeof(Vec4) */
__attribute__((noinline))
int64_t struct_field_x(const Vec4 *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += arr[i].x;
    }
    return sum;
}

__attribute__((noinline))
int64_t struct_field_y(const Vec4 *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += arr[i].y;
    }
    return sum;
}

__attribute__((noinline))
int64_t struct_field_z(const Vec4 *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += arr[i].z;
    }
    return sum;
}

/* Padded struct access - large stride */
__attribute__((noinline))
int64_t padded_access(const PaddedInt *arr, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += arr[i].value;
    }
    return sum;
}

/* Interleaved write with stride */
__attribute__((noinline))
void strided_write(int32_t *arr, size_t len, size_t stride, int32_t value) {
    for (size_t i = 0; i < len; i += stride) {
        arr[i] = value + (int32_t)(i / stride);
    }
}

/* Gather operation - indirect strided access */
__attribute__((noinline))
int64_t gather_strided(const int32_t *arr, const size_t *indices, size_t count) {
    int64_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        sum += arr[indices[i]];
    }
    return sum;
}

/* Scatter operation */
__attribute__((noinline))
void scatter_strided(int32_t *arr, const size_t *indices, const int32_t *values, size_t count) {
    for (size_t i = 0; i < count; i++) {
        arr[indices[i]] = values[i];
    }
}

/* Matrix transpose (strided read, sequential write per column) */
__attribute__((noinline))
void transpose_matrix(int32_t dst[MATRIX_DIM][MATRIX_DIM],
                      const int32_t src[MATRIX_DIM][MATRIX_DIM]) {
    for (size_t i = 0; i < MATRIX_DIM; i++) {
        for (size_t j = 0; j < MATRIX_DIM; j++) {
            dst[j][i] = src[i][j];
        }
    }
}

/* Blocked/tiled strided access */
__attribute__((noinline))
int64_t blocked_stride(const int32_t *arr, size_t len, size_t block_size, size_t stride) {
    int64_t sum = 0;
    for (size_t block = 0; block < len; block += block_size * stride) {
        for (size_t i = 0; i < block_size && block + i * stride < len; i++) {
            sum += arr[block + i * stride];
        }
    }
    return sum;
}

/* Bidirectional strided access */
__attribute__((noinline))
int64_t bidirectional_stride(const int32_t *arr, size_t len, size_t stride) {
    int64_t sum = 0;

    /* Forward */
    for (size_t i = 0; i < len; i += stride) {
        sum += arr[i];
    }

    /* Backward */
    for (size_t i = ((len - 1) / stride) * stride; ; i -= stride) {
        sum += arr[i];
        if (i < stride) break;
    }

    return sum;
}

int main(void) {
    int64_t result = 0;

    /* Initialize arrays */
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        linear_array[i] = (int32_t)i;
    }

    for (size_t i = 0; i < MATRIX_DIM; i++) {
        for (size_t j = 0; j < MATRIX_DIM; j++) {
            matrix[i][j] = (int32_t)(i * MATRIX_DIM + j);
        }
    }

    for (size_t i = 0; i < ARRAY_SIZE / 4; i++) {
        vec_array[i].x = (int32_t)i;
        vec_array[i].y = (int32_t)(i * 2);
        vec_array[i].z = (int32_t)(i * 3);
        vec_array[i].w = (int32_t)(i * 4);
    }

    for (size_t i = 0; i < 1024; i++) {
        padded_array[i].value = (int32_t)i;
    }

    /* Prepare indices for gather/scatter */
    size_t indices[256];
    int32_t values[256];
    for (size_t i = 0; i < 256; i++) {
        indices[i] = i * 16;
        values[i] = (int32_t)(i * 100);
    }

    int32_t transposed[MATRIX_DIM][MATRIX_DIM];

    for (int iter = 0; iter < 4; iter++) { /* rax: was 2000 */
        /* Power-of-2 strides */
        result += stride_2(linear_array, ARRAY_SIZE);
        result += stride_4(linear_array, ARRAY_SIZE);
        result += stride_8(linear_array, ARRAY_SIZE);
        result += stride_16(linear_array, ARRAY_SIZE);
        result += stride_64(linear_array, ARRAY_SIZE);

        /* Variable stride */
        result += stride_n(linear_array, ARRAY_SIZE, (iter % 8) + 1);

        /* Non-power-of-2 strides */
        result += stride_3(linear_array, ARRAY_SIZE);
        result += stride_5(linear_array, ARRAY_SIZE);
        result += stride_7(linear_array, ARRAY_SIZE);

        /* Matrix column access */
        result += column_access(matrix, iter % MATRIX_DIM);

        /* Diagonal accesses */
        result += diagonal_access(matrix);
        result += anti_diagonal_access(matrix);

        /* Struct field access */
        result += struct_field_x(vec_array, ARRAY_SIZE / 4);
        result += struct_field_y(vec_array, ARRAY_SIZE / 4);
        result += struct_field_z(vec_array, ARRAY_SIZE / 4);

        /* Padded access */
        result += padded_access(padded_array, 1024);

        /* Strided write */
        strided_write(linear_array, ARRAY_SIZE, 4, iter);

        /* Gather/scatter */
        result += gather_strided(linear_array, indices, 256);
        scatter_strided(linear_array, indices, values, 256);

        /* Matrix transpose */
        if (iter % 100 == 0) {
            transpose_matrix(transposed, matrix);
            result += transposed[0][0] + transposed[MATRIX_DIM-1][MATRIX_DIM-1];
        }

        /* Blocked stride */
        result += blocked_stride(linear_array, ARRAY_SIZE, 8, 4);

        /* Bidirectional */
        result += bidirectional_stride(linear_array, ARRAY_SIZE, 8);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", (int64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
