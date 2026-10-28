/* PT_STEP stops on SIGTRAP after one instruction (XNU mach_process.c). */
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
        raise(SIGSTOP);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t first = waitpid(child, &status, 0);
    if (first != child || !WIFSTOPPED(status)) {
        if (first != child && (first >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("trace-stop failed\n");
        return 1;
    }
    errno = 0;
    int stepped = ptrace(PT_STEP, child, (caddr_t)1, 0);
    printf("step %d %d\n", stepped, errno);
    if (stepped != 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status)) {
        if (got != child && (got >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("step-stop failed\n");
        return 1;
    }
    printf("step-stop signal=%d\n", WSTOPSIG(status));
    errno = 0;
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    printf("continue %d %d\n", continued, errno);
    if (continued != 0) {
        kill(child, SIGKILL);
    }
    got = waitpid(child, &status, 0);
    /* Native arm64 can report another SIGTRAP after PT_CONTINUE. Keep
     * this lifecycle check bounded; ptrace_step_boundary tests the exact
     * instruction sequence separately. */
    for (int extra = 0; got == child && WIFSTOPPED(status) &&
         WSTOPSIG(status) == SIGTRAP && extra < 16; ++extra) {
        if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) {
            break;
        }
        got = waitpid(child, &status, 0);
    }
    if (got == child && WIFSTOPPED(status)) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return continued != 0 || code != 42;
}
