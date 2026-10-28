/* exit1 clears the trace flag before a zombie is reaped. */
#include <signal.h>
#include <stdio.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(90);
        _exit(42);
    }
    siginfo_t info = {0};
    if (waitid(P_PID, child, &info, WEXITED | WNOWAIT) != 0 || info.si_pid != child) return 1;
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, child };
    struct kinfo_proc process = {0};
    size_t size = sizeof process;
    if (sysctl(mib, 4, &process, &size, NULL, 0) != 0 || size != sizeof process) return 1;
    printf("exit=%d traced=%d oppid=%d\n", info.si_status,
           !!(process.kp_proc.p_flag & P_TRACED), process.kp_proc.p_oppid == getpid());
    int status = 0;
    return waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}
