/* abort() raises SIGABRT with tgkill (shell status 134). */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("aborting\n");
    fflush(stdout);
    abort();
}
