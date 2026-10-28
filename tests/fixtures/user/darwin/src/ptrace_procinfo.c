/* Self process-info views must reflect the guest trace relationship. */
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
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
    struct proc_bsdinfo full = {0};
    struct proc_bsdshortinfo short_info = {0};
    struct proc_taskallinfo all = {0};
    struct kinfo_proc info = {0};
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t length = sizeof info;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &full, sizeof full) != sizeof full ||
        proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &short_info, sizeof short_info) != sizeof short_info ||
        proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &all, sizeof all) != sizeof all ||
        sysctl(mib, 4, &info, &length, NULL, 0) != 0 || length != sizeof info) return 1;
    printf("%s state=%u,%u,%u,%d xstatus=%u,%u,%u\n", label,
           full.pbi_status, short_info.pbsi_status, all.pbsd.pbi_status,
           info.kp_proc.p_stat, full.pbi_xstatus, all.pbsd.pbi_xstatus,
           (unsigned)info.kp_proc.p_xstat);
    pid_t expected_parent = pid == getpid() ? getppid() : getpid();
    printf("%s full=%d short=%d all=%d sysctl=%d oppid=%d\n", label,
           !!(full.pbi_flags & PROC_FLAG_TRACED),
           !!(short_info.pbsi_flags & PROC_FLAG_TRACED),
           !!(all.pbsd.pbi_flags & PROC_FLAG_TRACED),
           !!(info.kp_proc.p_flag & P_TRACED),
           info.kp_proc.p_oppid == expected_parent);
    return 0;
}

int main(void) {
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        signal(SIGUSR1, caught);
        if (report("before", getpid()) || ptrace(PT_TRACE_ME, 0, 0, 0) != 0 ||
            report("traced", getpid())) _exit(90);
        raise(SIGUSR1);
        if (report("detached", getpid())) _exit(91);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status) || report("parent", child) ||
        ptrace(PT_DETACH, child, (caddr_t)1, 0) != 0) return 1;
    pid_t got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    return got != child || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}
