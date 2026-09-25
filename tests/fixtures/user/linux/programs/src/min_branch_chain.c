/*
 * Minimal Conditional Branch Chain
 *
 * Generates sequences dominated by compare and branch instructions.
 * Creates many conditional branches with varying outcomes.
 *
 * Expected dominant instructions by architecture:
 *   x86:    cmp, jcc (je, jne, jl, jg, etc.)
 *   ARM:    cmp, b.cc (b.eq, b.ne, b.lt, b.gt, etc.)
 *   RISC-V: beq, bne, blt, bge
 *   MIPS:   beq, bne, slt, slti
 *   PPC:    cmpw, bc
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

volatile int sink;

int main(void) {
    int count = 0;
    int a = 0, b = 1, c = 2;

    for (int i = 0; i < 5000; i++) { /* rax: was 100000 */
        /* Many conditional branches */
        if (a < b) count++;
        if (b > c) count--;
        if (a == 0) count += 2;
        if (c != 0) count -= 1;

        if (a <= b) count++;
        if (b >= c) count--;
        if (a < 100) count += 1;
        if (c > -100) count -= 1;

        /* Update values to vary branch outcomes */
        a = (a + 7) % 200 - 100;
        b = (b + 13) % 200 - 100;
        c = (c + 19) % 200 - 100;

        /* More branches with computed conditions */
        int x = a + b;
        int y = b - c;
        int z = a * c;

        if (x > 0) count++;
        if (y < 0) count--;
        if (z == 0) count += 3;
        if (z != 0) count -= 2;

        if (x > y) count++;
        if (y > z) count--;
        if (x < z) count++;

        /* Nested conditions */
        if (a > 0) {
            if (b > 0) count++;
            else count--;
        } else {
            if (c > 0) count++;
            else count--;
        }
    }

    sink = count;
    printf("sink=%d\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
