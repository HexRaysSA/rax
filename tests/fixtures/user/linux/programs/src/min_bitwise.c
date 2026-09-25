/*
 * Minimal Bitwise Operation Chain
 *
 * Generates sequences dominated by AND, OR, XOR, NOT instructions.
 * Bitwise operations are fundamental and present in all ISAs.
 *
 * Expected dominant instructions by architecture:
 *   x86:    and, or, xor, not
 *   ARM:    and, orr, eor, mvn, bic
 *   RISC-V: and, or, xor, (not via xori -1)
 *   MIPS:   and, or, xor, nor
 *   PPC:    and, or, xor, nor, andc
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

volatile unsigned int sink;

int main(void) {
    unsigned int a = 0xAAAAAAAA;
    unsigned int b = 0x55555555;
    unsigned int c = 0xFF00FF00;
    unsigned int d = 0x00FF00FF;
    unsigned int e = 0xF0F0F0F0;
    unsigned int f = 0x0F0F0F0F;
    unsigned int g = 0xCCCCCCCC;
    unsigned int h = 0x33333333;

    for (int i = 0; i < 11000; i++) { /* rax: was 100000 */
        /* AND operations */
        a = a & b;
        c = c & d;
        e = e & f;
        g = g & h;

        /* OR operations */
        a = a | c;
        b = b | d;
        e = e | g;
        f = f | h;

        /* XOR operations */
        a = a ^ e;
        b = b ^ f;
        c = c ^ g;
        d = d ^ h;

        /* NOT operations */
        e = ~a;
        f = ~b;
        g = ~c;
        h = ~d;

        /* Combined operations */
        a = (a & 0xFF) | (b & 0xFF00);
        b = (c ^ d) & 0xFFFF;
        c = (e | f) ^ (g & h);
        d = ~(a ^ b) & (c | d);

        /* Bit clear patterns (AND with complement) */
        e = a & ~0xFF;
        f = b & ~0xFF00;
        g = c & ~0xFF0000;
        h = d & ~0xFF000000;

        /* Reset periodically */
        if (i % 10000 == 0) {
            a = 0xAAAAAAAA;
            b = 0x55555555;
            c = 0xFF00FF00;
            d = 0x00FF00FF;
            e = 0xF0F0F0F0;
            f = 0x0F0F0F0F;
            g = 0xCCCCCCCC;
            h = 0x33333333;
        }
    }

    sink = a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
    printf("sink=0x%08x\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
