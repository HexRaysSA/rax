/* Code-signing flag changes caused by a child's PT_TRACE_ME. */
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int operation, void *address, size_t size);

enum { CS_OPS_STATUS = 0 };

int main(int argc, char **argv) {
    int lazy = argc == 2 && strcmp(argv[1], "lazy") == 0;
    int markhard = argc == 2 && strcmp(argv[1], "markhard") == 0;
    int pipefd[2], release[2];
    if (pipe(pipefd) != 0 || pipe(release) != 0) return 1;
    uint32_t parent_before = 0, parent_after = 0, child_flags[2] = {0}, external = 0;
    if (!lazy && csops(0, CS_OPS_STATUS, &parent_before, sizeof(parent_before)) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(pipefd[0]);
        close(release[1]);
        if ((!lazy && csops(0, CS_OPS_STATUS, &child_flags[0], sizeof(child_flags[0])) != 0) ||
            ptrace(PT_TRACE_ME, 0, 0, 0) != 0 ||
            (markhard && csops(0, 2, NULL, 0) != 0 && errno != EINVAL) ||
            csops(0, CS_OPS_STATUS, &child_flags[1], sizeof(child_flags[1])) != 0 ||
            write(pipefd[1], child_flags, sizeof(child_flags)) != (ssize_t)sizeof(child_flags)) {
            _exit(1);
        }
        char token;
        if (read(release[0], &token, 1) != 1) _exit(1);
        _exit(0);
    }
    close(pipefd[1]);
    close(release[0]);
    ssize_t count = read(pipefd[0], child_flags, sizeof(child_flags));
    close(pipefd[0]);
    errno = 0;
    int query = csops(child, CS_OPS_STATUS, &external, sizeof(external));
    int query_errno = errno;
    if (write(release[1], "r", 1) != 1) return 1;
    close(release[1]);
    if (csops(0, CS_OPS_STATUS, &parent_after, sizeof(parent_after)) != 0) return 1;
    int status = 0;
    if (waitpid(child, &status, 0) != child || count != (ssize_t)sizeof(child_flags) ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
    printf("parent_before=%08x parent_after=%08x child_before=%08x child_after=%08x\n",
           parent_before, parent_after, child_flags[0], child_flags[1]);
    printf("child_external=%d errno=%d flags=%08x\n", query, query_errno, external);
    return 0;
}
