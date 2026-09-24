/* __builtin_trap(): UD2 on x86-64 (SIGILL, 132), BRK #1000 on AArch64
 * (SIGTRAP, 133), UNIMP on RISC-V (SIGILL, 132). */
#include <stdio.h>

int main(void) {
    printf("trapping\n");
    fflush(stdout);
    __builtin_trap();
}
