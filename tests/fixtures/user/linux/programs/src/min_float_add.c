/*
 * Minimal Floating Point Addition Chain
 *
 * Generates sequences dominated by FP add instructions.
 * Exercises the floating point unit's addition pipeline.
 *
 * Expected dominant instructions by architecture:
 *   x86:    addss, addsd, addps, addpd (SSE), vaddss, vaddsd (AVX)
 *   ARM:    fadd (scalar/vector)
 *   RISC-V: fadd.s, fadd.d
 *   MIPS:   add.s, add.d
 *   PPC:    fadds, fadd
 */

#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

volatile double sink_d;
volatile float sink_f;

int main(void) {
    /* Single precision chain */
    float fa = 1.0f, fb = 0.1f, fc = 0.01f, fd = 0.001f;
    float fe = 0.5f, ff = 0.05f, fg = 0.005f, fh = 0.0005f;

    /* Double precision chain */
    double da = 1.0, db = 0.1, dc = 0.01, dd = 0.001;
    double de = 0.5, df = 0.05, dg = 0.005, dh = 0.0005;

    for (int i = 0; i < 10100; i++) { /* rax: was 100000 */
        /* Single precision additions */
        fa = fa + fb;
        fb = fb + fc;
        fc = fc + fd;
        fd = fd + fa;

        fe = fe + ff;
        ff = ff + fg;
        fg = fg + fh;
        fh = fh + fe;

        fa = fa + fe;
        fb = fb + ff;
        fc = fc + fg;
        fd = fd + fh;

        /* Double precision additions */
        da = da + db;
        db = db + dc;
        dc = dc + dd;
        dd = dd + da;

        de = de + df;
        df = df + dg;
        dg = dg + dh;
        dh = dh + de;

        da = da + de;
        db = db + df;
        dc = dc + dg;
        dd = dd + dh;

        /* Reset periodically to prevent overflow */
        if (i % 10000 == 0) {
            fa = 1.0f; fb = 0.1f; fc = 0.01f; fd = 0.001f;
            fe = 0.5f; ff = 0.05f; fg = 0.005f; fh = 0.0005f;
            da = 1.0; db = 0.1; dc = 0.01; dd = 0.001;
            de = 0.5; df = 0.05; dg = 0.005; dh = 0.0005;
        }
    }

    sink_f = fa + fb + fc + fd + fe + ff + fg + fh;
    sink_d = da + db + dc + dd + de + df + dg + dh;
    {
        float vf = sink_f; double vd = sink_d; /* rax: print the result so that runs can be compared */
        uint32_t bf; uint64_t bd;
        memcpy(&bf, &vf, sizeof bf); memcpy(&bd, &vd, sizeof bd);
        printf("sink_f=%08" PRIx32 "\n", bf);
        printf("sink_d=%016" PRIx64 "\n", bd);
    }
    return 0;
}
