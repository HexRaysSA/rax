/* PT_DENY_ATTACH refuses an attach and signals the would-be tracer. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t signaled;
static volatile sig_atomic_t tracee;

static void on_segv(int signal_number) {
    (void)signal_number;
    signaled++;
}

static void timed_out(int signal_number) {
    (void)signal_number;
    if (tracee > 0) {
        kill((pid_t)tracee, SIGKILL);
    }
    _exit(2);
}

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], release[2];
    if (pipe(ready) != 0 || pipe(release) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        if (ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0 || write(ready[1], "x", 1) != 1) {
            _exit(90);
        }
        char byte;
        _exit(read(release[0], &byte, 1) == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    signal(SIGSEGV, on_segv);
    alarm(60);
    close(ready[1]);
    close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    errno = 0;
    int result = ptrace(PT_ATTACHEXC, child, 0, 0);
    int error = errno;
    printf("attach %d %d signal=%d\n", result, error, (int)signaled);
    if (result == 0) {
        kill(child, SIGKILL);
    } else {
        write(release[1], "x", 1);
    }
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return result != -1 || error != EBUSY || signaled != 1 || code != 42;
}
