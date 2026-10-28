/* A sibling tracer owns the guest child until its first exit wait; the
 * original parent then receives the zombie and performs the final reap. */
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t owned_target, owned_tracer;
static void cleanup(void) {
    if (owned_tracer > 0) { kill(owned_tracer, SIGKILL); waitpid(owned_tracer, NULL, 0); }
    if (owned_target > 0) { kill(owned_target, SIGKILL); waitpid(owned_target, NULL, 0); }
}
static void finish(int signal) { (void)signal; _exit(42); }
static int byte(int fd, int send) {
    char value = 'x';
    return (send ? write(fd, &value, 1) : read(fd, &value, 1)) == 1;
}
static int parent_is(pid_t child, pid_t expected) {
    struct proc_bsdinfo info;
    return proc_pidinfo(child, PROC_PIDTBSDINFO, 1, &info, sizeof(info)) == sizeof(info)
        && info.pbi_ppid == expected;
}
int main(int argc, char **argv) {
    int signal_from_parent = argc == 2;
    int retained_job = signal_from_parent && strcmp(argv[1], "job") == 0;
    setbuf(stdout, NULL);
    alarm(30);
    int ready[2], event[2], gate[2];
    if (pipe(ready) || pipe(event) || pipe(gate)) return 1;
    pid_t target = fork();
    if (target < 0) return 2;
    if (!target) {
        signal(SIGUSR1, finish);
        if (!byte(ready[1], 1)) _exit(3);
        if (retained_job) raise(SIGSTOP);
        for (;;) pause();
    }
    owned_target = target;
    atexit(cleanup);
    if (!byte(ready[0], 0)) return 4;
    if (retained_job) {
        siginfo_t info = {0};
        if (waitid(P_PID, target, &info, WSTOPPED | WNOWAIT) || info.si_status != SIGSTOP) return 19;
    }
    pid_t tracer = fork();
    if (tracer < 0) return 5;
    if (!tracer) {
        int status = 0;
        if (ptrace(PT_ATTACH, target, 0, 0)) _exit(6);
        if (waitpid(target, &status, 0) != target || !WIFSTOPPED(status)) _exit(7);
        if (!byte(event[1], 1) || !byte(gate[0], 0)) _exit(8);
        if (ptrace(PT_CONTINUE, target, (caddr_t)1, signal_from_parent ? 0 : SIGUSR1)) _exit(9);
        if (signal_from_parent) {
            if (waitpid(target, &status, 0) != target || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGUSR1) _exit(20);
            printf("parent_signal_stop=1 signal=%d\n", WSTOPSIG(status));
            if (ptrace(PT_CONTINUE, target, (caddr_t)1, SIGUSR1)) _exit(21);
        }
        if (waitpid(target, &status, 0) != target || status != (42 << 8)) _exit(10);
        if (!byte(event[1], 1) || !byte(gate[0], 0)) _exit(11);
        _exit(0);
    }
    owned_tracer = tracer;
    int status = 0;
    if (!byte(event[0], 0)) return 12;
    errno = 0;
    pid_t result = waitpid(target, &status, WNOHANG | WUNTRACED);
    printf("foreign=%d errno=%d parent=%d\n", result == -1, errno, parent_is(target, tracer));
    if (result != -1 || errno != ECHILD || !parent_is(target, tracer)) return 13;
    if (signal_from_parent && kill(target, SIGUSR1)) return 22;
    if (!byte(gate[1], 1) || !byte(event[0], 0)) return 14;
    printf("returned_parent=%d\n", parent_is(target, getpid()));
    if (!parent_is(target, getpid())) return 15;
    result = waitpid(target, &status, WNOHANG);
    printf("reap=%d status=%x\n", result == target, status);
    if (result != target || status != (42 << 8)) return 16;
    owned_target = 0;
    if (!byte(gate[1], 1)) return 17;
    if (waitpid(tracer, &status, 0) != tracer || status != 0) return 18;
    owned_tracer = 0;
    return 0;
}
