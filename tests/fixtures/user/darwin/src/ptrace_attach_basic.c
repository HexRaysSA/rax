/* Attach to a running child, observe its stop, and continue it. */
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int op, void *buffer, size_t size);
static volatile sig_atomic_t tracee;

static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int restricted = argc == 2 && strcmp(argv[1], "restrict") == 0;
    int sigexc = argc == 2 && strcmp(argv[1], "sigexc") == 0;
    int ready[2], release[2];
    if (pipe(ready) != 0 || pipe(release) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        if (restricted && csops(0, 8, NULL, 0) != 0) _exit(90);
        char byte = 'r';
        if (write(ready[1], &byte, 1) != 1) _exit(91);
        ssize_t count;
        do {
            count = read(release[0], &byte, 1);
        } while (count < 0 && errno == EINTR);
        _exit(count == 1 ? 42 : 92);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]);
    close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    errno = 0;
    int attached = ptrace(sigexc ? PT_ATTACHEXC : PT_ATTACH, child, 0, 0);
    int error = errno;
    printf("attach=%d errno=%d\n", attached, error);
    if (attached != 0) {
        write(release[1], "r", 1);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    int status = 0;
    pid_t got;
    if (sigexc) {
        do {
            got = waitpid(child, &status, WNOHANG);
            if (got == 0) usleep(1000);
        } while (got == 0);
    } else {
        got = waitpid(child, &status, 0);
    }
    int stopped = got == child && WIFSTOPPED(status);
    printf("stop=%d signal=%d\n", stopped, stopped ? WSTOPSIG(status) : 0);
    if (!stopped) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    uint32_t child_flags = 0, parent_flags = 0;
    if (csops(child, 0, &child_flags, sizeof child_flags) != 0 ||
        csops(0, 0, &parent_flags, sizeof parent_flags) != 0) return 1;
    printf("flags child=%08x parent=%08x\n", child_flags, parent_flags);
    errno = 0;
    int again = ptrace(PT_ATTACH, child, 0, 0);
    error = errno;
    printf("again=%d errno=%d\n", again, error);
    errno = 0;
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    error = errno;
    printf("continue=%d errno=%d\n", continued, error);
    if (continued != 0) kill(child, SIGKILL);
    else if (write(release[1], "r", 1) != 1) return 1;
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", code);
    return again != -1 || continued != 0 || code != 42;
}
