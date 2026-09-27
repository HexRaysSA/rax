/* Arguments, environment, standard output, and the exit status. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    printf("argc=%d\n", argc);
    for (int i = 1; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
    const char *v = getenv("RAX_FIXTURE_VAR");
    printf("RAX_FIXTURE_VAR=%s\n", v ? v : "(unset)");
    fflush(stdout);
    return 7;
}
