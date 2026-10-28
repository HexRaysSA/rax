/* PT_THUPDATE accepts a thread right owned by the tracer. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "zero") != 0)) {
        return 2;
    }
    int requested = argc == 2 ? 0 : SIGUSR1;
    setbuf(stdout, NULL);
    pid_t debugger = fork();
    if (debugger < 0) {
        return 1;
    }
    if (debugger == 0) {
        sigset_t blocked, pending;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGUSR1);
        if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) {
            _exit(90);
        }
        pid_t child = fork();
        if (child < 0) {
            _exit(91);
        }
        if (child == 0) {
            if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
                _exit(92);
            }
            raise(SIGSTOP);
            _exit(93);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
            _exit(94);
        }
        mach_port_t thread = mach_thread_self();
        errno = 0;
        int updated = ptrace(PT_THUPDATE, child, (caddr_t)(uintptr_t)thread, requested);
        int update_error = errno;
        if (sigpending(&pending) != 0) {
            _exit(95);
        }
        errno = 0;
        int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
        int continue_error = errno;
        int is_pending = sigismember(&pending, SIGUSR1);
        printf("update=%d errno=%d pending=%d continue=%d errno=%d\n",
               updated, update_error, is_pending, continued, continue_error);
        /* Exiting the tracer causes XNU to kill its still-suspended tracee. */
        _exit(updated != 0 || is_pending != (requested != 0) ||
              continued != -1 || continue_error != EBUSY);
    }
    int status = 0;
    return waitpid(debugger, &status, 0) != debugger || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
