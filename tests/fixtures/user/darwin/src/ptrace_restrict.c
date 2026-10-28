/* A restricted child asks its same-credential parent to trace it. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int op, void *buffer, size_t size);

int main(int argc, char **argv) {
    int initial = argc == 2 && strcmp(argv[1], "initial") == 0;
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        errno = 0;
        int mark = initial ? -2 : csops(0, 8, NULL, 0);
        int mark_error = errno;
        uint32_t before = 0, after = 0;
        if (!initial && csops(0, 0, &before, sizeof before) != 0) _exit(90);
        errno = 0;
        int trace = ptrace(PT_TRACE_ME, 0, 0, 0);
        int trace_error = errno;
        if (csops(0, 0, &after, sizeof after) != 0) _exit(91);
        printf("mark=%d errno=%d trace=%d errno=%d before=%08x after=%08x\n",
               mark, mark_error, trace, trace_error, before, after);
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 1;
    return WEXITSTATUS(status);
}
