/* SIGKILL to a running traced child stops it, then cannot be suppressed. */
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
    int ready[2];
    if (pipe(ready) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(90);
        raise(SIGSTOP);
        if (write(ready[1], "r", 1) != 1) _exit(91);
        for (;;) pause();
    }
    close(ready[1]);
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
        ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) return 1;
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    int killed = kill(child, SIGKILL);
    pid_t got = waitpid(child, &status, 0);
    int stopped = got == child && WIFSTOPPED(status) ? WSTOPSIG(status) : -1;
    int continued = stopped == SIGKILL ? ptrace(PT_CONTINUE, child, (caddr_t)1, 0) : -1;
    if (continued == 0) got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int sig = got == child && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    printf("kill=%d stop=%d continue=%d signal=%d\n", killed, stopped, continued, sig);
    return killed != 0 || stopped != SIGKILL || continued != 0 || sig != SIGKILL;
}
