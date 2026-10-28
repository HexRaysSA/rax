/* A no-attach tracee also signals a second attach attempt's caller. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t received;

static void on_segv(int sig) {
    (void)sig;
    received++;
}

static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) {
        kill((pid_t)tracee, SIGKILL);
    }
    _exit(2);
}

int main(void) {
    setbuf(stdout, NULL);
    signal(SIGSEGV, on_segv);
    signal(SIGALRM, timed_out);
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        if (ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0 ||
            ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
            _exit(90);
        }
        raise(SIGSTOP);
        _exit(0);
    }
    tracee = child;
    alarm(60);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
        return 1;
    }
    errno = 0;
    int result = ptrace(PT_ATTACH, child, 0, 0);
    int error = errno;
    printf("attach=%d errno=%d sigsegv=%d\n", result, error, (int)received);
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    if (continued != 0) {
        kill(child, SIGKILL);
    }
    pid_t waited = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    return result != -1 || error != EBUSY || received != 1 || continued != 0 ||
        waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
