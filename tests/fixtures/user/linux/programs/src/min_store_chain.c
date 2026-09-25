/*
 * Minimal Memory Store Chain
 *
 * Generates sequences dominated by memory store instructions.
 * Sequential stores to memory with various sizes and patterns.
 *
 * Expected dominant instructions by architecture:
 *   x86:    mov (to memory)
 *   ARM:    str, strb, strh
 *   RISC-V: sw, sd, sb, sh
 *   MIPS:   sw, sd, sb, sh
 *   PPC:    stw, std, stb, sth
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

#define ARRAY_SIZE 4096

volatile int sink;

static int data[ARRAY_SIZE];
static char bytes[ARRAY_SIZE];
static short shorts[ARRAY_SIZE];

int main(void) {
    int val = 42;

    for (int iter = 0; iter < 10; iter++) { /* rax: was 1000 */
        /* Sequential word stores */
        for (int i = 0; i < ARRAY_SIZE; i += 8) {
            data[i]     = val;
            data[i + 1] = val + 1;
            data[i + 2] = val + 2;
            data[i + 3] = val + 3;
            data[i + 4] = val + 4;
            data[i + 5] = val + 5;
            data[i + 6] = val + 6;
            data[i + 7] = val + 7;
            val += 8;
        }

        /* Byte stores */
        for (int i = 0; i < ARRAY_SIZE; i += 8) {
            bytes[i]     = (char)(val & 0xFF);
            bytes[i + 1] = (char)((val + 1) & 0xFF);
            bytes[i + 2] = (char)((val + 2) & 0xFF);
            bytes[i + 3] = (char)((val + 3) & 0xFF);
            bytes[i + 4] = (char)((val + 4) & 0xFF);
            bytes[i + 5] = (char)((val + 5) & 0xFF);
            bytes[i + 6] = (char)((val + 6) & 0xFF);
            bytes[i + 7] = (char)((val + 7) & 0xFF);
            val += 8;
        }

        /* Half-word stores */
        for (int i = 0; i < ARRAY_SIZE; i += 8) {
            shorts[i]     = (short)(val & 0xFFFF);
            shorts[i + 1] = (short)((val + 1) & 0xFFFF);
            shorts[i + 2] = (short)((val + 2) & 0xFFFF);
            shorts[i + 3] = (short)((val + 3) & 0xFFFF);
            shorts[i + 4] = (short)((val + 4) & 0xFFFF);
            shorts[i + 5] = (short)((val + 5) & 0xFFFF);
            shorts[i + 6] = (short)((val + 6) & 0xFFFF);
            shorts[i + 7] = (short)((val + 7) & 0xFFFF);
            val += 8;
        }
    }

    /* Prevent dead code elimination */
    sink = data[0] + bytes[0] + shorts[0];
    printf("sink=%d\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
