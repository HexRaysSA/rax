/* PT_KILL terminates a traced, stopped child with SIGKILL. */
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
        _exit(91);
    }
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
        printf("trace-stop failed\n");
        return 1;
    }
    errno = 0;
    int result = ptrace(PT_KILL, child, 0, 0);
    printf("kill %d %d\n", result, errno);
    if (result != 0) {
        kill(child, SIGKILL);
    }
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int signum = got == child && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    printf("signal %d\n", signum);
    return result != 0 || signum != SIGKILL;
}
