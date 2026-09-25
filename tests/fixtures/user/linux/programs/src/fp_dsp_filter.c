/*
 * Digital Signal Processing Filter
 *
 * Implements IIR and FIR filters for audio/signal processing.
 * Heavy use of multiply-accumulate operations.
 *
 * Features exercised:
 *   - FP multiply-accumulate (FMA)
 *   - Delay line / circular buffer operations
 *   - Loop unrolling friendly patterns
 */

#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SIGNAL_LENGTH 128 /* rax: was 4096 */
#define FIR_TAPS 64
#define IIR_ORDER 4

volatile float sink;

static float input_signal[SIGNAL_LENGTH];
static float output_signal[SIGNAL_LENGTH];

/* FIR filter coefficients (low-pass) */
static float fir_coeffs[FIR_TAPS];
static float fir_delay[FIR_TAPS];

/* IIR filter coefficients (biquad cascade) */
typedef struct {
    float b0, b1, b2;  /* Feedforward coefficients */
    float a1, a2;      /* Feedback coefficients */
    float z1, z2;      /* State variables */
} Biquad;

static Biquad iir_sections[IIR_ORDER];

/* Initialize FIR filter with sinc-based low-pass */
static void init_fir(float cutoff) {
    /* Generate windowed sinc coefficients */
    int center = FIR_TAPS / 2;
    float sum = 0.0f;

    for (int i = 0; i < FIR_TAPS; i++) {
        int n = i - center;
        if (n == 0) {
            fir_coeffs[i] = cutoff;
        } else {
            /* sinc(n * cutoff) */
            float x = 3.14159f * (float)n * cutoff;
            float sinc;
            /* Taylor series for sin(x)/x */
            float x2 = x * x;
            sinc = 1.0f - x2 / 6.0f + x2 * x2 / 120.0f;
            fir_coeffs[i] = cutoff * sinc;
        }

        /* Hamming window */
        float window = 0.54f - 0.46f * (float)(1.0f - 2.0f * 3.14159f * i / (FIR_TAPS - 1));
        /* Simplified: just use a triangular window approximation */
        window = 1.0f - (float)(i - center) * (float)(i - center) / (float)(center * center);
        if (window < 0.0f) window = 0.0f;

        fir_coeffs[i] *= window;
        sum += fir_coeffs[i];
    }

    /* Normalize */
    for (int i = 0; i < FIR_TAPS; i++) {
        fir_coeffs[i] /= sum;
        fir_delay[i] = 0.0f;
    }
}

/* Initialize IIR biquad cascade (Butterworth-like) */
static void init_iir(void) {
    /* Simple low-pass biquad coefficients */
    for (int i = 0; i < IIR_ORDER; i++) {
        float w0 = 0.1f + 0.05f * i;  /* Varying cutoff per section */

        /* Approximate Butterworth coefficients */
        iir_sections[i].b0 = w0 * w0 / 4.0f;
        iir_sections[i].b1 = 2.0f * iir_sections[i].b0;
        iir_sections[i].b2 = iir_sections[i].b0;
        iir_sections[i].a1 = -2.0f * (1.0f - w0);
        iir_sections[i].a2 = (1.0f - w0) * (1.0f - w0);

        iir_sections[i].z1 = 0.0f;
        iir_sections[i].z2 = 0.0f;
    }
}

/* FIR filter - direct form */
static void fir_filter(const float *input, float *output, size_t length) {
    for (size_t n = 0; n < length; n++) {
        /* Shift delay line */
        for (int i = FIR_TAPS - 1; i > 0; i--) {
            fir_delay[i] = fir_delay[i - 1];
        }
        fir_delay[0] = input[n];

        /* Convolve */
        float sum = 0.0f;
        for (int i = 0; i < FIR_TAPS; i++) {
            sum += fir_coeffs[i] * fir_delay[i];
        }
        output[n] = sum;
    }
}

/* FIR filter - optimized with loop unrolling */
static void fir_filter_unrolled(const float *input, float *output, size_t length) {
    for (size_t n = 0; n < length; n++) {
        /* Shift delay line */
        for (int i = FIR_TAPS - 1; i > 0; i--) {
            fir_delay[i] = fir_delay[i - 1];
        }
        fir_delay[0] = input[n];

        /* Convolve with 4-way unrolling */
        float sum0 = 0.0f, sum1 = 0.0f, sum2 = 0.0f, sum3 = 0.0f;
        int i = 0;
        for (; i + 4 <= FIR_TAPS; i += 4) {
            sum0 += fir_coeffs[i + 0] * fir_delay[i + 0];
            sum1 += fir_coeffs[i + 1] * fir_delay[i + 1];
            sum2 += fir_coeffs[i + 2] * fir_delay[i + 2];
            sum3 += fir_coeffs[i + 3] * fir_delay[i + 3];
        }
        for (; i < FIR_TAPS; i++) {
            sum0 += fir_coeffs[i] * fir_delay[i];
        }
        output[n] = sum0 + sum1 + sum2 + sum3;
    }
}

/* IIR biquad filter - transposed direct form II */
static float biquad_process(Biquad *bq, float input) {
    float output = bq->b0 * input + bq->z1;
    bq->z1 = bq->b1 * input - bq->a1 * output + bq->z2;
    bq->z2 = bq->b2 * input - bq->a2 * output;
    return output;
}

/* Cascaded IIR filter */
static void iir_filter(const float *input, float *output, size_t length) {
    for (size_t n = 0; n < length; n++) {
        float sample = input[n];

        /* Process through each biquad section */
        for (int i = 0; i < IIR_ORDER; i++) {
            sample = biquad_process(&iir_sections[i], sample);
        }

        output[n] = sample;
    }
}

/* Initialize test signal */
static void init_signal(int seed) {
    for (size_t i = 0; i < SIGNAL_LENGTH; i++) {
        /* Mix of frequencies */
        float t = (float)i / SIGNAL_LENGTH;
        float signal = 0.0f;

        /* Low frequency component */
        signal += 0.5f * ((float)((i * 17 + seed) % 1000) / 1000.0f - 0.5f);

        /* High frequency noise */
        signal += 0.3f * ((float)((i * 31 + seed * 7) % 100) / 100.0f - 0.5f);

        input_signal[i] = signal;
    }
}

int main(void) {
    init_fir(0.3f);
    init_iir();

    float result_sum = 0.0f;

    for (int iter = 0; iter < 3; iter++) { /* rax: was 100 */
        init_signal(iter);

        /* Apply FIR filter */
        if (iter % 3 == 0) {
            fir_filter(input_signal, output_signal, SIGNAL_LENGTH);
        } else if (iter % 3 == 1) {
            fir_filter_unrolled(input_signal, output_signal, SIGNAL_LENGTH);
        } else {
            /* Apply IIR filter */
            /* Reset IIR state */
            for (int i = 0; i < IIR_ORDER; i++) {
                iir_sections[i].z1 = 0.0f;
                iir_sections[i].z2 = 0.0f;
            }
            iir_filter(input_signal, output_signal, SIGNAL_LENGTH);
        }

        /* Accumulate output energy */
        for (size_t i = 0; i < SIGNAL_LENGTH; i += 16) {
            result_sum += output_signal[i] * output_signal[i];
        }
    }

    sink = result_sum;
    uint32_t result_sum_bits; /* rax: print the result so that runs can be compared */
    memcpy(&result_sum_bits, &result_sum, sizeof result_sum_bits);
    printf("result_sum=%08" PRIx32 "\n", result_sum_bits);
    return 0;
}
