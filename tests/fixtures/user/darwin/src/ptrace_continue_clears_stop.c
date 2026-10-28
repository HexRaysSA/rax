/* XNU keeps the stopped signal's properties after a signal substitution. */
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee, received;
static void caught(int sig) { (void)sig; received++; }
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
int main(void) {
    setbuf(stdout, NULL);
    int release[2];
    if (pipe(release)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(release[1]);
        signal(SIGUSR1, caught);
        if (ptrace(PT_TRACE_ME, 0, 0, 0)) _exit(90);
        raise(SIGUSR1);
        char byte;
        if (read(release[0], &byte, 1) != 1) _exit(91);
        printf("received=%d\n", (int)received);
        _exit(42);
    }
    tracee = child;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, timed_out);
    alarm(60);
    close(release[0]);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status) || kill(child, SIGSTOP)) goto fail;
    int result = ptrace(PT_CONTINUE, child, (caddr_t)1, SIGCONT);
    printf("continue=%d\n", result);
    if (result) goto fail;
    (void)write(release[1], "x", 1);
    got = waitpid(child, &status, 0);
    if (got == child && WIFSTOPPED(status)) goto fail;
    tracee = 0;
    alarm(0);
    int sig = got == child && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    printf("signal=%d\n", sig);
    return sig != SIGCONT;
fail:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    tracee = 0;
    return 1;
}
