/* XNU kern_exit.c: copyout precedes reap_child_locked; p_oppid returns
 * even a PT_TRACE_ME zombie to its original (also tracing) parent. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    setbuf(stdout, NULL);
    alarm(20);
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        if (ptrace(PT_TRACE_ME, 0, 0, 0)) _exit(2);
        raise(SIGSTOP);
        _exit(42);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 3;
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0)) return 4;
    siginfo_t info = {0};
    if (waitid(P_PID, child, &info, WEXITED | WNOWAIT) || info.si_status != 42) return 5;
    errno = 0;
    int zero_pid = waitid(P_PID, 0, &info, WEXITED | WNOHANG);
    printf("zero_pid=%d errno=%d\n", zero_pid, errno);
    if (zero_pid != -1 || errno != ECHILD) return 11;
    errno = 0;
    int zero_group = waitid(P_PGID, 0, &info, WEXITED | WNOHANG);
    printf("zero_group=%d errno=%d\n", zero_group, errno);
    if (zero_group != -1 || errno != ECHILD) return 12;
    errno = 0;
    pid_t result = wait4(child, (int *)1, 0, NULL);
    printf("status_fault=%d errno=%d\n", result == -1, errno);
    if (result != -1 || errno != EFAULT) return 6;
    errno = 0;
    result = wait4(child, &status, 0, (struct rusage *)1);
    printf("usage_fault=%d errno=%d status=%x\n", result == -1, errno, status);
    if (result != -1 || errno != EFAULT || status != (42 << 8)) return 7;
    result = wait4(child, &status, 0, NULL);
    printf("first=%d status=%x\n", result == child, status);
    if (result != child || status != (42 << 8)) return 8;
    result = wait4(child, &status, WNOHANG, NULL);
    printf("second=%d status=%x\n", result == child, status);
    if (result != child || status != (42 << 8)) return 9;
    errno = 0;
    result = wait4(child, &status, WNOHANG, NULL);
    printf("third=%d errno=%d\n", result == -1, errno);
    return result == -1 && errno == ECHILD ? 0 : 10;
}
