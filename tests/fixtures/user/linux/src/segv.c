/* Dereferences an unmapped address: the default SIGSEGV action kills the
 * process (shell status 139). */
#include <stdio.h>

int main(void) {
    volatile int *p = (int *)8;
    printf("before\n");
    fflush(stdout);
    return *p;
}
