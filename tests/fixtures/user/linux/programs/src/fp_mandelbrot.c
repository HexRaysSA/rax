/*
 * Mandelbrot Set Computation
 *
 * Computes Mandelbrot set escape times.
 * Heavy use of floating point multiplication, addition, comparison.
 *
 * Features exercised:
 *   - FP multiply, add, compare
 *   - FP to integer conversion
 *   - Loop-carried dependencies
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

#define WIDTH 12 /* rax: was 256 */
#define HEIGHT 12 /* rax: was 256 */
#define MAX_ITER 100

volatile uint32_t sink;

static uint8_t image[HEIGHT][WIDTH];

/* Compute escape time for a single point */
static int mandelbrot_point(double cr, double ci) {
    double zr = 0.0;
    double zi = 0.0;

    for (int i = 0; i < MAX_ITER; i++) {
        double zr2 = zr * zr;
        double zi2 = zi * zi;

        if (zr2 + zi2 > 4.0) {
            return i;
        }

        zi = 2.0 * zr * zi + ci;
        zr = zr2 - zi2 + cr;
    }

    return MAX_ITER;
}

/* Single precision version */
static int mandelbrot_point_f(float cr, float ci) {
    float zr = 0.0f;
    float zi = 0.0f;

    for (int i = 0; i < MAX_ITER; i++) {
        float zr2 = zr * zr;
        float zi2 = zi * zi;

        if (zr2 + zi2 > 4.0f) {
            return i;
        }

        zi = 2.0f * zr * zi + ci;
        zr = zr2 - zi2 + cr;
    }

    return MAX_ITER;
}

int main(void) {
    /* Region: [-2.5, 1] x [-1, 1] */
    double x_min = -2.5;
    double x_max = 1.0;
    double y_min = -1.0;
    double y_max = 1.0;

    double x_step = (x_max - x_min) / WIDTH;
    double y_step = (y_max - y_min) / HEIGHT;

    uint32_t checksum = 0;

    /* Multiple iterations for timing */
    for (int iter = 0; iter < 2; iter++) { /* rax: was 10 */
        /* Double precision computation */
        for (int py = 0; py < HEIGHT; py++) {
            double ci = y_min + py * y_step;
            for (int px = 0; px < WIDTH; px++) {
                double cr = x_min + px * x_step;
                int escape = mandelbrot_point(cr, ci);
                image[py][px] = (uint8_t)(escape % 256);
            }
        }

        /* Accumulate checksum */
        for (int y = 0; y < HEIGHT; y++) {
            for (int x = 0; x < WIDTH; x++) {
                checksum += image[y][x];
            }
        }

        /* Single precision computation */
        float fx_min = -2.5f;
        float fx_step = 3.5f / WIDTH;
        float fy_min = -1.0f;
        float fy_step = 2.0f / HEIGHT;

        for (int py = 0; py < HEIGHT; py++) {
            float ci = fy_min + py * fy_step;
            for (int px = 0; px < WIDTH; px++) {
                float cr = fx_min + px * fx_step;
                int escape = mandelbrot_point_f(cr, ci);
                image[py][px] = (uint8_t)(escape % 256);
            }
        }

        for (int y = 0; y < HEIGHT; y++) {
            for (int x = 0; x < WIDTH; x++) {
                checksum += image[y][x];
            }
        }
    }

    sink = checksum;
    printf("checksum=%" PRIu32 "\n", checksum); /* rax: print the result so that runs can be compared */
    return 0;
}
