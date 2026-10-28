/* Tracee-state and request validation order (XNU mach_process.c). */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;

static void timed_out(int signal_number) {
    (void)signal_number;
    if (tracee > 0) {
        kill((pid_t)tracee, SIGKILL);
    }
    _exit(2);
}

static void probe(const char *name, int request, pid_t pid, caddr_t address, int data) {
    errno = 0;
    int result = ptrace(request, pid, address, data);
    printf("%s %d %d\n", name, result, errno);
}

int main(void) {
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
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t first = waitpid(child, &status, 0);
    if (first != child || !WIFSTOPPED(status)) {
        if (first != child && (first >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("trace-stop failed\n");
        return 1;
    }
    probe("attach-traced", PT_ATTACHEXC, child, 0, 0);
    probe("read-data", PT_READ_D, child, 0, 0);
    probe("unknown", -1, child, 0, 0);
    probe("continue-address", PT_CONTINUE, child, 0, 0);
    probe("continue-signal", PT_CONTINUE, child, (caddr_t)1, 32);
    probe("thread-update-signal", PT_THUPDATE, child, 0, 32);
    probe("thread-update-port", PT_THUPDATE, child, 0, 0);
    probe("thread-update-invalid", PT_THUPDATE, child, (caddr_t)(uintptr_t)0xdeadbeef, 0);
    probe("thread-update-task", PT_THUPDATE, child, (caddr_t)(uintptr_t)mach_task_self(), 0);
    errno = 0;
    int detached = ptrace(PT_DETACH, child, 0, 0);
    printf("detach %d %d\n", detached, errno);
    if (detached != 0) {
        kill(child, SIGKILL);
    } else {
        /* The detached child can enter a job-control stop after detach. */
        pid_t changed = waitpid(child, &status, WUNTRACED);
        if (changed == child && WIFEXITED(status)) {
            tracee = 0;
            alarm(0);
            printf("last-wait exit=%d\n", WEXITSTATUS(status));
            return WEXITSTATUS(status) != 42;
        }
        if (changed == child && WIFSTOPPED(status)) {
            kill(child, SIGCONT);
        } else {
            kill(child, SIGKILL);
        }
    }
    pid_t got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    printf("last-wait exit=%d\n", got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return detached != 0 || got != child || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}
