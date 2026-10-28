/* A traced process that denies attach exits with ENOTSUP (mach_process.c). */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;

static void timed_out(int signal_number) {
    (void)signal_number;
    if (tracee > 0) {
        kill((pid_t)tracee, SIGKILL);
    }
    _exit(2);
}

int main(void) {
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
            _exit(90);
        }
        errno = 0;
        int result = ptrace(PT_SIGEXC, 0, 0, 0);
        printf("sigexc %d %d\n", result, errno);
        ptrace(PT_DENY_ATTACH, 0, 0, 0);
        _exit(91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return code != ENOTSUP;
}
