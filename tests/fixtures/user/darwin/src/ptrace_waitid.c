/* Ignored signals still stop a traced process; WNOWAIT preserves the stop. */
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
        signal(SIGUSR1, SIG_IGN);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(90);
        raise(SIGUSR1);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    siginfo_t info;
    for (int i = 0; i != 3; ++i) {
        int options = WSTOPPED | (i < 2 ? WNOWAIT : 0);
        int result = waitid(P_PID, (id_t)child, &info, options);
        if (result != 0) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            tracee = 0;
            return 1;
        }
        printf("waitid code=%d signal=%d\n", info.si_code, info.si_status);
    }
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    if (continued != 0) kill(child, SIGKILL);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return continued != 0 || code != 42;
}
