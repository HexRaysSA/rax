/* EXC_SOFT_SIGNAL can leave a waitable stop while the child keeps running. */
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t child_signals;
static void caught(int sig) { (void)sig; }
static void child_changed(int sig) { (void)sig; child_signals++; }
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
int main(void) {
    setbuf(stdout, NULL);
    int ready[2], release[2];
    if (pipe(ready) || pipe(release)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release[1]);
        signal(SIGUSR1, caught);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) || ptrace(PT_SIGEXC, 0, 0, 0)) _exit(90);
        raise(SIGUSR1);
        if (write(ready[1], "x", 1) != 1) _exit(91);
        char byte;
        _exit(read(release[0], &byte, 1) == 1 ? 42 : 92);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    signal(SIGCHLD, child_changed);
    alarm(60);
    close(ready[1]); close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    int status = 0;
    pid_t got = waitpid(child, &status, WNOHANG);
    printf("wait=%d stopped=%d signal=%d sigchld=%d\n", got == child, WIFSTOPPED(status),
           WIFSTOPPED(status) ? WSTOPSIG(status) : 0, (int)child_signals);
    (void)write(release[1], "x", 1);
    do { got = waitpid(child, &status, 0); } while (got == child && WIFSTOPPED(status));
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", code);
    return code != 42;
}
