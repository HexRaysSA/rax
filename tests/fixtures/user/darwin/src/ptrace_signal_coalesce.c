/* A queued signal and an identical PT_CONTINUE signal coalesce. */
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
        raise(SIGSTOP);
        char byte;
        if (read(release[0], &byte, 1) != 1) _exit(91);
        printf("received=%d\n", (int)received);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(release[0]);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status) || kill(child, SIGUSR1)) goto fail;
    int result = ptrace(PT_CONTINUE, child, (caddr_t)1, SIGUSR1);
    printf("continue=%d\n", result);
    if (result || write(release[1], "x", 1) != 1) goto fail;
    got = waitpid(child, &status, 0);
    if (got == child && WIFSTOPPED(status)) goto fail;
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", code);
    return code != 42;
fail:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    tracee = 0;
    return 1;
}
