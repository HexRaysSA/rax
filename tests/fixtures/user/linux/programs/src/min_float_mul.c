/*
 * Minimal Floating Point Multiplication Chain
 *
 * Generates sequences dominated by FP multiply instructions.
 * Also includes FMA (fused multiply-add) patterns when available.
 *
 * Expected dominant instructions by architecture:
 *   x86:    mulss, mulsd (SSE), vmulss, vmulsd, vfmadd (AVX/FMA)
 *   ARM:    fmul, fmadd
 *   RISC-V: fmul.s, fmul.d, fmadd.s, fmadd.d
 *   MIPS:   mul.s, mul.d, madd.s, madd.d
 *   PPC:    fmuls, fmul, fmadd, fmsub
 */

#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

volatile double sink_d;
volatile float sink_f;

int main(void) {
    /* Single precision */
    float fa = 1.01f, fb = 1.02f, fc = 1.03f, fd = 1.04f;
    float fe = 0.99f, ff = 0.98f, fg = 0.97f, fh = 0.96f;

    /* Double precision */
    double da = 1.001, db = 1.002, dc = 1.003, dd = 1.004;
    double de = 0.999, df = 0.998, dg = 0.997, dh = 0.996;

    for (int i = 0; i < 8006; i++) { /* rax: was 100000 */
        /* Single precision multiplications */
        fa = fa * fb;
        fb = fb * fc;
        fc = fc * fd;
        fd = fd * fe;

        fe = fe * ff;
        ff = ff * fg;
        fg = fg * fh;
        fh = fh * fa;

        /* FMA patterns: a * b + c */
        fa = fa * fe + 0.001f;
        fb = fb * ff + 0.001f;
        fc = fc * fg + 0.001f;
        fd = fd * fh + 0.001f;

        /* Double precision multiplications */
        da = da * db;
        db = db * dc;
        dc = dc * dd;
        dd = dd * de;

        de = de * df;
        df = df * dg;
        dg = dg * dh;
        dh = dh * da;

        /* FMA patterns */
        da = da * de + 0.0001;
        db = db * df + 0.0001;
        dc = dc * dg + 0.0001;
        dd = dd * dh + 0.0001;

        /* Normalize periodically to stay in reasonable range */
        if (i % 1000 == 0) {
            fa = 1.01f; fb = 1.02f; fc = 1.03f; fd = 1.04f;
            fe = 0.99f; ff = 0.98f; fg = 0.97f; fh = 0.96f;
            da = 1.001; db = 1.002; dc = 1.003; dd = 1.004;
            de = 0.999; df = 0.998; dg = 0.997; dh = 0.996;
        }
    }

    sink_f = fa * fb * fc * fd * fe * ff * fg * fh;
    sink_d = da * db * dc * dd * de * df * dg * dh;
    {
        float vf = sink_f; double vd = sink_d; /* rax: print the result so that runs can be compared */
        uint32_t bf; uint64_t bd;
        memcpy(&bf, &vf, sizeof bf); memcpy(&bd, &vd, sizeof bd);
        printf("sink_f=%08" PRIx32 "\n", bf);
        printf("sink_d=%016" PRIx64 "\n", bd);
    }
    return 0;
}
