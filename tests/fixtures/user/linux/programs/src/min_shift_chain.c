/*
 * Minimal Shift and Rotate Chain
 *
 * Generates sequences dominated by shift and rotate instructions.
 * Important for detecting ISAs - shift encodings vary significantly.
 *
 * Expected dominant instructions by architecture:
 *   x86:    shl, shr, sar, rol, ror
 *   ARM:    lsl, lsr, asr, ror
 *   RISC-V: sll, srl, sra, (no rotate in base ISA)
 *   MIPS:   sll, srl, sra, rotr
 *   PPC:    slw, srw, sraw, rlwnm
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

volatile unsigned int sink;

/* Rotate left (portable) */
static inline unsigned int rotl(unsigned int x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* Rotate right (portable) */
static inline unsigned int rotr(unsigned int x, int n) {
    return (x >> n) | (x << (32 - n));
}

int main(void) {
    unsigned int a = 0xDEADBEEF;
    unsigned int b = 0xCAFEBABE;
    unsigned int c = 0x12345678;
    unsigned int d = 0x87654321;

    for (int i = 0; i < 10006; i++) { /* rax: was 100000 */
        /* Left shifts */
        a = a << 1;
        b = b << 3;
        c = c << 5;
        d = d << 7;

        /* Right shifts (logical) */
        a = a >> 2;
        b = b >> 4;
        c = c >> 6;
        d = d >> 1;

        /* Variable shifts */
        int shift_amt = (i & 15) + 1;
        a = a << shift_amt;
        b = b >> shift_amt;

        /* Arithmetic right shifts (signed) */
        int sa = (int)a;
        int sb = (int)b;
        sa = sa >> 3;
        sb = sb >> 5;
        a = (unsigned int)sa;
        b = (unsigned int)sb;

        /* Rotates */
        c = rotl(c, 7);
        d = rotr(d, 11);
        a = rotl(a, shift_amt);
        b = rotr(b, shift_amt);

        /* Combined patterns */
        a = (a << 4) | (b >> 28);
        c = (c >> 8) | (d << 24);

        /* Reset periodically */
        if (i % 10000 == 0) {
            a = 0xDEADBEEF;
            b = 0xCAFEBABE;
            c = 0x12345678;
            d = 0x87654321;
        }
    }

    sink = a ^ b ^ c ^ d;
    printf("sink=0x%08x\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
