#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>

int main(void)
{
    const char *path = "/usr/bin/printf";
    char *const argv[] = {"printf", "spawn:%s\n", "installed-libc", NULL};
    char *const envp[] = {"LC_ALL=C", NULL};
    pid_t child;
    int status;
    int error = posix_spawn(&child, path, NULL, NULL, argv, envp);
    if (error != 0) {
        fprintf(stderr, "spawn failed: %d\n", error);
        return 1;
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fputs("child did not exit successfully\n", stderr);
        return 2;
    }
    error = posix_spawn(&child, "/rax-missing-executable", NULL, NULL, argv, envp);
    if (error != ENOENT) {
        fprintf(stderr, "missing executable returned %d\n", error);
        return 3;
    }
    puts("missing:ENOENT");
    return 0;
}
