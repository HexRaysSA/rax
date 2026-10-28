/* PT_SIGEXC without a task exception handler, bsd_exception failure path. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t received;
static void caught(int sig) { (void)sig; received++; }
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
int main(void) {
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        signal(SIGUSR1, caught);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(90);
        errno = 0;
        int result = ptrace(PT_SIGEXC, 0, 0, 0);
        printf("sigexc %d %d\n", result, errno);
        if (result != 0) _exit(91);
        raise(SIGUSR1);
        printf("received %d\n", (int)received);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t got;
    do {
        got = waitpid(child, &status, 0);
    } while (got == child && WIFSTOPPED(status));
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return code != 42;
}
