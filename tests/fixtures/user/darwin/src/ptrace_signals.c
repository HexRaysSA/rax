/* Signals sent by a tracer are intercepted without stopping its emulator. */
#include <errno.h>
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
    int ready[2], release[2];
    if (pipe(ready) || pipe(release)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release[1]);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) || write(ready[1], "r", 1) != 1) _exit(90);
        char byte;
        ssize_t got;
        do { got = read(release[0], &byte, 1); } while (got < 0 && errno == EINTR);
        _exit(got == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) goto fail;
    int status = 0;
    for (int i = 0; i < 3; ++i) {
        int sig = i == 0 ? SIGCONT : i == 1 ? SIGSTOP : SIGUSR1;
        if (kill(child, sig) != 0) goto fail;
        pid_t got = waitpid(child, &status, 0);
        /* WIFSTOPPED excludes the SIGCONT-shaped 0x137f status. */
        if (got != child || (status & 0xff) != 0x7f) goto fail;
        printf("stop signal=%d\n", (status >> 8) & 0xff);
        if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) goto fail;
    }
    if (write(release[1], "x", 1) != 1) goto fail;
    pid_t got = waitpid(child, &status, 0);
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
