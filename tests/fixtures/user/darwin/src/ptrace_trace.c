/* Parent/child tracing through ptrace and wait4 (XNU mach_process.c). */
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
        perror("fork");
        return 1;
    }
    if (child == 0) {
        errno = 0;
        int result = ptrace(PT_TRACE_ME, 0, 0, 0);
        printf("trace-me %d %d\n", result, errno);
        if (result != 0) {
            _exit(90);
        }
        raise(SIGSTOP);
        _exit(42);
    }
    /* A broken tracing implementation must not leave a stopped child. */
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status)) {
        if (got != child && (got >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("first-wait stopped=0 exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }
    printf("first-wait stopped=1 signal=%d\n", WSTOPSIG(status));
    errno = 0;
    int result = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    printf("continue %d %d\n", result, errno);
    if (result != 0) {
        kill(child, SIGKILL);
    }
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    printf("last-wait exit=%d\n", got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return result != 0 || got != child || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}
