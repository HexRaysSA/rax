/* A trace stop reports CLD_TRAPPED even with SA_NOCLDSTOP. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee, observed, code, status, uid, sender;
static void child_changed(int sig, siginfo_t *info, void *context) {
    (void)sig; (void)context;
    code = info->si_code;
    status = info->si_status;
    uid = (sig_atomic_t)info->si_uid;
    sender = (sig_atomic_t)info->si_pid;
    observed = 1;
}
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
int main(void) {
    setbuf(stdout, NULL);
    struct sigaction action = {0};
    action.sa_sigaction = child_changed;
    action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_RESTART;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(90);
        raise(SIGUSR1);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int st = 0;
    pid_t got;
    do { got = waitpid(child, &st, 0); } while (got < 0 && errno == EINTR);
    if (got != child || !WIFSTOPPED(st)) goto fail;
    sigset_t blocked, old, suspend_mask;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &blocked, &old) != 0) goto fail;
    suspend_mask = old;
    sigdelset(&suspend_mask, SIGCHLD);
    while (!observed) sigsuspend(&suspend_mask);
    if (sigprocmask(SIG_SETMASK, &old, NULL) != 0) goto fail;
    printf("code=%d status=%d uid-match=%d pid-match=%d\n", (int)code, (int)status,
           (uid_t)uid == getuid(), (pid_t)sender == child);
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) goto fail;
    do { got = waitpid(child, &st, 0); } while (got < 0 && errno == EINTR);
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", got == child && WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return got != child || !WIFEXITED(st) || WEXITSTATUS(st) != 42;
fail:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    tracee = 0;
    return 1;
}
