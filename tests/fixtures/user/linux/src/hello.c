/* Arguments, environment, and exit status. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {
    printf("argc=%d\n", argc);
    for (int i = 1; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
    const char *v = getenv("RAX_FIXTURE_VAR");
    printf("RAX_FIXTURE_VAR=%s\n", v ? v : "(unset)");
    int n = 0;
    while (envp[n])
        n++;
    printf("environ-nonempty=%d\n", n > 0);
    return 40 + argc;
}
