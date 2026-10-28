/* A traced child can grant its parent a task control right at a stop. */
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(91);
        raise(SIGSTOP);
        _exit(42);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 1;
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), child, &task);
    printf("task=%d valid=%d\n", result, task != MACH_PORT_NULL);
    if (task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0 || waitpid(child, &status, 0) != child) return 1;
    return result || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}
