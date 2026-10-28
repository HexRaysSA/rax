/* SIGKILL sent to a traced stop is delivered after the tracer resumes it. */
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
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
        if (ptrace(PT_TRACE_ME, 0, 0, 0)) _exit(90);
        raise(SIGSTOP);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status)) return 1;
    printf("stop=%d\n", WSTOPSIG(status));
    int killed = kill(child, SIGKILL);
    int early_status = 0;
    pid_t early = waitpid(child, &early_status, WNOHANG);
    printf("kill=%d pending=%d\n", killed, early == 0);
    if (killed || early != 0) return 1;
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    printf("continue=%d\n", continued);
    if (continued) return 1;
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int sig = got == child && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    printf("signal=%d\n", sig);
    return sig != SIGKILL;
}
