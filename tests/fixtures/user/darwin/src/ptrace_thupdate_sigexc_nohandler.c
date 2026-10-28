/* A PT_SIGEXC stop remains reportable after an unhandled exception returns. */
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static void caught(int sig) { (void)sig; }
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}

static int report(const char *label, pid_t pid) {
    struct proc_bsdinfo info = {0};
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    struct kinfo_proc process = {0};
    size_t size = sizeof process;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof info) != sizeof info ||
        sysctl(mib, 4, &process, &size, NULL, 0) != 0 || size != sizeof process) return 1;
    printf("%s status=%u xstatus=%u sysctl=%d xstatus=%u\n", label,
           info.pbi_status, info.pbi_xstatus, process.kp_proc.p_stat,
           (unsigned)process.kp_proc.p_xstat);
    return 0;
}

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], release[2];
    if (pipe(ready) != 0 || pipe(release) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release[1]);
        signal(SIGUSR1, caught);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0 || ptrace(PT_SIGEXC, 0, 0, 0) != 0) _exit(90);
        raise(SIGUSR1);
        char byte;
        if (write(ready[1], "r", 1) != 1 || read(release[0], &byte, 1) != 1) _exit(91);
        _exit(42);
    }
    close(ready[1]); close(release[0]);
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    int status = 0;
    pid_t got = waitpid(child, &status, WNOHANG);
    int stopped = got == child && WIFSTOPPED(status);
    printf("stopped=%d sig=%d\n", stopped, stopped ? WSTOPSIG(status) : 0);
    if (report("before", child)) return 1;
    errno = 0;
    int updated = ptrace(PT_THUPDATE, child, (caddr_t)(uintptr_t)mach_thread_self(), 0);
    int error = errno;
    printf("update=%d errno=%d\n", updated, error);
    if (updated != 0 || report("after", child) || write(release[1], "r", 1) != 1) {
        kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1;
    }
    do {
        got = waitpid(child, &status, 0);
    } while (got == child && WIFSTOPPED(status));
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", code);
    return !stopped || error != 0 || code != 42;
}
