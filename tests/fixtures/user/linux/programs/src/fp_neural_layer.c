/*
 * Neural Network Dense Layer
 *
 * Computes y = activation(W * x + b) for a fully-connected layer.
 * Heavy matrix-vector multiply with activation function.
 *
 * Features exercised:
 *   - FP multiply-accumulate (FMA)
 *   - Vectorizable loops
 *   - Non-linear activation (ReLU, tanh approximation)
 */

#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 64 /* rax: was 256 */
#define OUTPUT_SIZE 32 /* rax: was 128 */
#define BATCH_SIZE 4 /* rax: was 32 */

volatile float sink;

static float weights[OUTPUT_SIZE][INPUT_SIZE];
static float bias[OUTPUT_SIZE];
static float input[BATCH_SIZE][INPUT_SIZE];
static float output[BATCH_SIZE][OUTPUT_SIZE];

/* ReLU activation */
static inline float relu(float x) {
    return x > 0.0f ? x : 0.0f;
}

/* Approximate tanh using rational approximation */
static inline float approx_tanh(float x) {
    if (x < -3.0f) return -1.0f;
    if (x > 3.0f) return 1.0f;

    float x2 = x * x;
    float num = x * (27.0f + x2);
    float den = 27.0f + 9.0f * x2;
    return num / den;
}

/* Sigmoid approximation */
static inline float approx_sigmoid(float x) {
    return 0.5f * (approx_tanh(x * 0.5f) + 1.0f);
}

/* Dense layer forward pass with ReLU */
static void dense_relu(const float *x, float *y,
                       const float w[OUTPUT_SIZE][INPUT_SIZE],
                       const float *b) {
    for (size_t i = 0; i < OUTPUT_SIZE; i++) {
        float sum = b[i];
        for (size_t j = 0; j < INPUT_SIZE; j++) {
            sum += w[i][j] * x[j];
        }
        y[i] = relu(sum);
    }
}

/* Dense layer forward pass with tanh */
static void dense_tanh(const float *x, float *y,
                       const float w[OUTPUT_SIZE][INPUT_SIZE],
                       const float *b) {
    for (size_t i = 0; i < OUTPUT_SIZE; i++) {
        float sum = b[i];
        for (size_t j = 0; j < INPUT_SIZE; j++) {
            sum += w[i][j] * x[j];
        }
        y[i] = approx_tanh(sum);
    }
}

/* Batch forward pass */
static void batch_forward_relu(void) {
    for (size_t batch = 0; batch < BATCH_SIZE; batch++) {
        dense_relu(input[batch], output[batch], weights, bias);
    }
}

static void batch_forward_tanh(void) {
    for (size_t batch = 0; batch < BATCH_SIZE; batch++) {
        dense_tanh(input[batch], output[batch], weights, bias);
    }
}

/* Initialize with pseudo-random values */
static void init_weights(void) {
    /* Xavier initialization approximation */
    float scale = 0.1f;
    unsigned int seed = 12345;

    for (size_t i = 0; i < OUTPUT_SIZE; i++) {
        for (size_t j = 0; j < INPUT_SIZE; j++) {
            seed = seed * 1103515245 + 12345;
            int rand_val = (int)((seed >> 16) & 0x7FFF) - 16384;
            weights[i][j] = scale * (float)rand_val / 16384.0f;
        }
    }

    for (size_t i = 0; i < OUTPUT_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        int rand_val = (int)((seed >> 16) & 0x7FFF) - 16384;
        bias[i] = 0.01f * (float)rand_val / 16384.0f;
    }
}

static void init_input(int iter) {
    for (size_t batch = 0; batch < BATCH_SIZE; batch++) {
        for (size_t i = 0; i < INPUT_SIZE; i++) {
            /* Varying input based on iteration */
            input[batch][i] = 0.1f * (float)((batch * INPUT_SIZE + i + iter) % 100);
        }
    }
}

int main(void) {
    init_weights();

    float result_sum = 0.0f;

    for (int iter = 0; iter < 4; iter++) { /* rax: was 1000 */
        init_input(iter);

        /* Alternate between activation functions */
        if (iter % 2 == 0) {
            batch_forward_relu();
        } else {
            batch_forward_tanh();
        }

        /* Accumulate outputs */
        for (size_t batch = 0; batch < BATCH_SIZE; batch++) {
            for (size_t i = 0; i < OUTPUT_SIZE; i++) {
                result_sum += output[batch][i];
            }
        }
    }

    sink = result_sum;
    uint32_t result_sum_bits; /* rax: print the result so that runs can be compared */
    memcpy(&result_sum_bits, &result_sum, sizeof result_sum_bits);
    printf("result_sum=%08" PRIx32 "\n", result_sum_bits);
    return 0;
}
