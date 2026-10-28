/* ptrace's self-directed requests and validation order (XNU mach_process.c). */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>

static volatile sig_atomic_t signaled;

static void on_segv(int signal_number) {
    (void)signal_number;
    signaled++;
}

static void probe(const char *name, int request, pid_t pid) {
    errno = 0;
    int result = ptrace(request, pid, (caddr_t)1, 0);
    printf("%s %d %d\n", name, result, errno);
}

int main(void) {
    probe("sigexc", PT_SIGEXC, 0);
    probe("low-pid", PT_CONTINUE, 1);
    probe("negative-pid", PT_CONTINUE, -1);
    probe("missing-pid", PT_CONTINUE, INT_MAX);
    probe("unknown-missing", -1, INT_MAX);
    probe("self", PT_CONTINUE, getpid());
    probe("unknown-self", -1, getpid());
    probe("attach-self", PT_ATTACHEXC, getpid());
    probe("force-quota", PT_FORCEQUOTA, 0);
    probe("deny", PT_DENY_ATTACH, 0);
    probe("deny-again", PT_DENY_ATTACH, 0);
    probe("deny-ignores-pid", PT_DENY_ATTACH, -1);
    signal(SIGSEGV, on_segv);
    probe("attach-denied-self", PT_ATTACHEXC, getpid());
    printf("attach-denied-self-signal %d\n", (int)signaled);
    return 0;
}
