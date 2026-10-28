/* P_LNOATTACH is cleared on fork and retained by exec. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t signaled;

static void on_segv(int signal_number) {
    (void)signal_number;
    signaled++;
}

static int probe(const char *stage, int expected_signal) {
    signal(SIGSEGV, on_segv);
    errno = 0;
    int result = ptrace(PT_ATTACHEXC, getpid(), 0, 0);
    int error = errno;
    printf("%s %d %d signal=%d\n", stage, result, error, (int)signaled);
    return result != -1 || error != EINVAL || signaled != expected_signal;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc == 2 && strcmp(argv[1], "after-exec") == 0) {
        return probe("exec", 1);
    }
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        if (probe("fork", 0) != 0 || ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0) {
            _exit(90);
        }
        char *args[] = {argv[0], "after-exec", NULL};
        execv(argv[0], args);
        _exit(91);
    }
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("child-exit %d\n", code);
    return code != 0;
}
