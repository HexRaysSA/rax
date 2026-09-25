/*
 * Fast Fourier Transform (Radix-2 Cooley-Tukey)
 *
 * Computes FFT of complex signal.
 * Heavy use of trig functions, complex arithmetic.
 *
 * Features exercised:
 *   - FP sin/cos (or table lookup)
 *   - Complex multiply/add
 *   - Bit reversal permutation
 */

#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Simple inline math since we avoid libm dependency */
#define PI 3.14159265358979323846

#define FFT_SIZE 256 /* rax: was 1024 */

volatile double sink;

/* Complex number */
typedef struct {
    double re;
    double im;
} Complex;

static Complex data[FFT_SIZE];
static Complex twiddle[FFT_SIZE / 2];

/* Approximate sine using Taylor series */
static double approx_sin(double x) {
    /* Reduce to [-pi, pi] */
    while (x > PI) x -= 2 * PI;
    while (x < -PI) x += 2 * PI;

    double x2 = x * x;
    double x3 = x2 * x;
    double x5 = x3 * x2;
    double x7 = x5 * x2;
    double x9 = x7 * x2;

    return x - x3 / 6.0 + x5 / 120.0 - x7 / 5040.0 + x9 / 362880.0;
}

/* Approximate cosine using Taylor series */
static double approx_cos(double x) {
    /* Reduce to [-pi, pi] */
    while (x > PI) x -= 2 * PI;
    while (x < -PI) x += 2 * PI;

    double x2 = x * x;
    double x4 = x2 * x2;
    double x6 = x4 * x2;
    double x8 = x6 * x2;

    return 1.0 - x2 / 2.0 + x4 / 24.0 - x6 / 720.0 + x8 / 40320.0;
}

/* Bit reversal */
static unsigned int bit_reverse(unsigned int x, int bits) {
    unsigned int result = 0;
    for (int i = 0; i < bits; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

/* Precompute twiddle factors */
static void init_twiddle(void) {
    for (size_t k = 0; k < FFT_SIZE / 2; k++) {
        double angle = -2.0 * PI * k / FFT_SIZE;
        twiddle[k].re = approx_cos(angle);
        twiddle[k].im = approx_sin(angle);
    }
}

/* In-place FFT */
static void fft(Complex *x, size_t n) {
    int bits = 0;
    size_t temp = n;
    while (temp > 1) {
        temp >>= 1;
        bits++;
    }

    /* Bit-reversal permutation */
    for (size_t i = 0; i < n; i++) {
        size_t j = bit_reverse((unsigned int)i, bits);
        if (i < j) {
            Complex t = x[i];
            x[i] = x[j];
            x[j] = t;
        }
    }

    /* Cooley-Tukey iterative FFT */
    for (size_t len = 2; len <= n; len *= 2) {
        size_t half = len / 2;
        size_t step = n / len;

        for (size_t i = 0; i < n; i += len) {
            for (size_t j = 0; j < half; j++) {
                Complex w = twiddle[j * step];
                Complex *a = &x[i + j];
                Complex *b = &x[i + j + half];

                /* Butterfly operation */
                Complex t;
                t.re = w.re * b->re - w.im * b->im;
                t.im = w.re * b->im + w.im * b->re;

                Complex u = *a;
                a->re = u.re + t.re;
                a->im = u.im + t.im;
                b->re = u.re - t.re;
                b->im = u.im - t.im;
            }
        }
    }
}

/* Inverse FFT */
static void ifft(Complex *x, size_t n) {
    /* Conjugate */
    for (size_t i = 0; i < n; i++) {
        x[i].im = -x[i].im;
    }

    fft(x, n);

    /* Conjugate and scale */
    double scale = 1.0 / n;
    for (size_t i = 0; i < n; i++) {
        x[i].re *= scale;
        x[i].im = -x[i].im * scale;
    }
}

int main(void) {
    init_twiddle();

    double result_sum = 0.0;

    for (int iter = 0; iter < 2; iter++) { /* rax: was 1000 */
        /* Initialize with test signal */
        for (size_t i = 0; i < FFT_SIZE; i++) {
            /* Mix of frequencies */
            double t = (double)i / FFT_SIZE;
            data[i].re = approx_sin(2 * PI * 10 * t)
                       + 0.5 * approx_sin(2 * PI * 50 * t)
                       + 0.25 * approx_sin(2 * PI * 100 * t);
            data[i].im = 0.0;
        }

        /* Forward FFT */
        fft(data, FFT_SIZE);

        /* Accumulate magnitude at some frequencies */
        for (size_t i = 0; i < FFT_SIZE / 2; i += 10) {
            double mag = data[i].re * data[i].re + data[i].im * data[i].im;
            result_sum += mag;
        }

        /* Inverse FFT */
        ifft(data, FFT_SIZE);

        /* Verify reconstruction */
        for (size_t i = 0; i < FFT_SIZE; i += 100) {
            result_sum += data[i].re;
        }
    }

    sink = result_sum;
    uint64_t result_sum_bits; /* rax: print the result so that runs can be compared */
    memcpy(&result_sum_bits, &result_sum, sizeof result_sum_bits);
    printf("result_sum=%016" PRIx64 "\n", result_sum_bits);
    return 0;
}
