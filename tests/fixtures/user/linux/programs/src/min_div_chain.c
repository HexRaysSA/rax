/*
 * Minimal Integer Division Chain
 *
 * Generates sequences dominated by integer division and modulo.
 * Division encoding varies significantly across ISAs.
 *
 * Expected dominant instructions by architecture:
 *   x86:    div, idiv
 *   ARM:    udiv, sdiv
 *   RISC-V: div, divu, rem, remu (M extension)
 *   MIPS:   div, divu
 *   PPC:    divw, divwu
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

volatile int sink;

int main(void) {
    unsigned int ua = 1000000;
    unsigned int ub = 7;
    unsigned int uc = 13;
    unsigned int ud = 17;

    int sa = 1000000;
    int sb = -7;
    int sc = 13;
    int sd = -17;

    int sum = 0;

    for (int i = 0; i < 2000; i++) { /* rax: was 50000 */
        /* Unsigned division */
        unsigned int q1 = ua / ub;
        unsigned int r1 = ua % ub;
        unsigned int q2 = uc / ud;
        unsigned int r2 = uc % ud;

        sum += (int)(q1 + r1 + q2 + r2);

        /* Signed division */
        int q3 = sa / sb;
        int r3 = sa % sb;
        int q4 = sc / sd;
        int r4 = sc % sd;

        sum += q3 + r3 + q4 + r4;

        /* Division by varying values */
        int divisor = (i % 15) + 2;  /* Avoid div by 0/1 */
        sum += (int)ua / divisor;
        sum += sa / divisor;

        /* Update operands */
        ua = (ua * 7 + 11) % 10000000 + 1000;
        ub = (ub * 3 + 5) % 100 + 2;
        uc = (uc * 11 + 7) % 10000000 + 1000;
        ud = (ud * 13 + 3) % 100 + 2;

        sa = ((sa * 7 + 11) % 10000000) - 5000000;
        sb = ((int)((i * 3) % 98) + 2) * ((i & 1) ? 1 : -1);
        sc = ((sc * 11 + 7) % 10000000) - 5000000;
        sd = ((int)((i * 7) % 98) + 2) * ((i & 2) ? 1 : -1);

        /* Ensure non-zero divisors */
        if (sb == 0) sb = 1;
        if (sd == 0) sd = 1;
    }

    sink = sum;
    printf("sink=%d\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
