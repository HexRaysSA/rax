/* A traced exec posts SIGTRAP before the new image runs (kern_exec.c). */
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int op, void *buffer, size_t size);

static volatile sig_atomic_t tracee;

static void timed_out(int signal_number) {
    (void)signal_number;
    if (tracee > 0) {
        kill((pid_t)tracee, SIGKILL);
    }
    _exit(2);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "after-exec") == 0) {
        int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
        struct kinfo_proc info = {0};
        size_t size = sizeof info;
        if (sysctl(mib, 4, &info, &size, NULL, 0) != 0 || size != sizeof info) return 92;
        uint32_t flags = 0;
        if (csops(0, 0, &flags, sizeof flags) != 0) return 93;
        printf("child cs=%08x\n", flags);
        printf("exec traced=%d oppid=%d\n", !!(info.kp_proc.p_flag & P_TRACED),
               info.kp_proc.p_oppid == getppid());
        return 42;
    }
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
        char *args[] = {argv[0], "after-exec", NULL};
        execv(argv[0], args);
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
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status)) {
        if (got != child && (got >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("exec-stop failed\n");
        return 1;
    }
    printf("exec-stop signal=%d\n", WSTOPSIG(status));
    uint32_t flags = 0;
    if (csops(child, 0, &flags, sizeof flags) != 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    printf("stop cs=%08x\n", flags);
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    if (continued != 0) {
        kill(child, SIGKILL);
    }
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return continued != 0 || code != 42;
}
