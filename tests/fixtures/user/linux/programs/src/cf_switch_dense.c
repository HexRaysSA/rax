/*
 * Dense Switch Statement (Jump Table)
 *
 * Switches with consecutive case values generate jump tables.
 * Tests indirect branching via computed addresses.
 *
 * Features exercised:
 *   - Jump table generation
 *   - Indirect branch instructions
 *   - Table-driven dispatch
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

__attribute__((noinline))
int dense_switch_8(int x) {
    switch (x) {
        case 0: return 100;
        case 1: return 101;
        case 2: return 104;
        case 3: return 109;
        case 4: return 116;
        case 5: return 125;
        case 6: return 136;
        case 7: return 149;
        default: return 0;
    }
}

__attribute__((noinline))
int dense_switch_16(int x) {
    switch (x) {
        case 0: return x * 2;
        case 1: return x * 3;
        case 2: return x * 5;
        case 3: return x * 7;
        case 4: return x * 11;
        case 5: return x * 13;
        case 6: return x * 17;
        case 7: return x * 19;
        case 8: return x * 23;
        case 9: return x * 29;
        case 10: return x * 31;
        case 11: return x * 37;
        case 12: return x * 41;
        case 13: return x * 43;
        case 14: return x * 47;
        case 15: return x * 53;
        default: return -1;
    }
}

__attribute__((noinline))
int dense_switch_32(int x) {
    int result = 0;
    switch (x) {
        case 0: result = 1; break;
        case 1: result = 2; break;
        case 2: result = 4; break;
        case 3: result = 8; break;
        case 4: result = 16; break;
        case 5: result = 32; break;
        case 6: result = 64; break;
        case 7: result = 128; break;
        case 8: result = 256; break;
        case 9: result = 512; break;
        case 10: result = 1024; break;
        case 11: result = 2048; break;
        case 12: result = 4096; break;
        case 13: result = 8192; break;
        case 14: result = 16384; break;
        case 15: result = 32768; break;
        case 16: result = 65536; break;
        case 17: result = 131072; break;
        case 18: result = 262144; break;
        case 19: result = 524288; break;
        case 20: result = 1048576; break;
        case 21: result = 2097152; break;
        case 22: result = 4194304; break;
        case 23: result = 8388608; break;
        case 24: result = 16777216; break;
        case 25: result = 33554432; break;
        case 26: result = 67108864; break;
        case 27: result = 134217728; break;
        case 28: result = 268435456; break;
        case 29: result = 536870912; break;
        case 30: result = 1073741824; break;
        case 31: result = -2147483648; break;
        default: result = 0;
    }
    return result;
}

/* Enum-based switch - common pattern */
typedef enum {
    CMD_NOP,
    CMD_ADD,
    CMD_SUB,
    CMD_MUL,
    CMD_DIV,
    CMD_MOD,
    CMD_AND,
    CMD_OR,
    CMD_XOR,
    CMD_SHL,
    CMD_SHR,
    CMD_NOT,
    CMD_NEG,
    CMD_INC,
    CMD_DEC,
    CMD_HALT,
    CMD_COUNT
} Command;

__attribute__((noinline))
int execute_command(Command cmd, int a, int b) {
    switch (cmd) {
        case CMD_NOP: return a;
        case CMD_ADD: return a + b;
        case CMD_SUB: return a - b;
        case CMD_MUL: return a * b;
        case CMD_DIV: return b != 0 ? a / b : 0;
        case CMD_MOD: return b != 0 ? a % b : 0;
        case CMD_AND: return a & b;
        case CMD_OR: return a | b;
        case CMD_XOR: return a ^ b;
        case CMD_SHL: return a << (b & 31);
        case CMD_SHR: return a >> (b & 31);
        case CMD_NOT: return ~a;
        case CMD_NEG: return -a;
        case CMD_INC: return a + 1;
        case CMD_DEC: return a - 1;
        case CMD_HALT: return 0;
        default: return -1;
    }
}

/* Nested switch */
__attribute__((noinline))
int nested_switch(int category, int subcategory) {
    switch (category) {
        case 0:
            switch (subcategory) {
                case 0: return 100;
                case 1: return 101;
                case 2: return 102;
                default: return 109;
            }
        case 1:
            switch (subcategory) {
                case 0: return 200;
                case 1: return 201;
                case 2: return 202;
                default: return 209;
            }
        case 2:
            switch (subcategory) {
                case 0: return 300;
                case 1: return 301;
                case 2: return 302;
                default: return 309;
            }
        default:
            return 999;
    }
}

/* Character classification switch */
__attribute__((noinline))
int classify_char(char c) {
    switch (c) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return 1; /* digit */
        case 'a': case 'b': case 'c': case 'd': case 'e':
        case 'f': case 'g': case 'h': case 'i': case 'j':
        case 'k': case 'l': case 'm': case 'n': case 'o':
        case 'p': case 'q': case 'r': case 's': case 't':
        case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
            return 2; /* lowercase */
        case 'A': case 'B': case 'C': case 'D': case 'E':
        case 'F': case 'G': case 'H': case 'I': case 'J':
        case 'K': case 'L': case 'M': case 'N': case 'O':
        case 'P': case 'Q': case 'R': case 'S': case 'T':
        case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
            return 3; /* uppercase */
        case ' ': case '\t': case '\n': case '\r':
            return 4; /* whitespace */
        default:
            return 0; /* other */
    }
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 2000; i++) { /* rax: was 100000 */
        result += dense_switch_8(i % 10);
        result += dense_switch_16(i % 20);
        result += dense_switch_32(i % 40);

        result += execute_command((Command)(i % CMD_COUNT), i, i % 10 + 1);

        result += nested_switch(i % 4, i % 5);

        result += classify_char((char)(32 + (i % 95)));
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
