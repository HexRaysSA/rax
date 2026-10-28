/* PT_THUPDATE accepts a thread control right obtained from the tracee. */
#include <errno.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    setbuf(stdout, NULL);
    pid_t debugger = fork();
    if (debugger < 0) return 1;
    if (debugger == 0) {
        int ready[2], gate[2];
        if (pipe(ready) || pipe(gate)) _exit(90);
        pid_t child = fork();
        if (child < 0) _exit(91);
        if (child == 0) {
            close(ready[0]); close(gate[1]);
            char byte;
            if (write(ready[1], "r", 1) != 1 || read(gate[0], &byte, 1) != 1) _exit(92);
            _exit(93);
        }
        close(ready[1]); close(gate[0]);
        char byte;
        int status;
        if (read(ready[0], &byte, 1) != 1 || ptrace(PT_ATTACH, child, 0, 0) != 0 ||
            waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) _exit(94);
        mach_port_t task = MACH_PORT_NULL;
        thread_act_array_t threads = NULL;
        mach_msg_type_number_t count = 0;
        if (task_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS ||
            task_threads(task, &threads, &count) != KERN_SUCCESS || count == 0) _exit(95);
        errno = 0;
        int updated = ptrace(PT_THUPDATE, child, (caddr_t)(uintptr_t)threads[0], SIGUSR1);
        int update_error = errno;
        errno = 0;
        int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
        int continue_error = errno;
        printf("update=%d errno=%d continue=%d errno=%d\n",
               updated, update_error, continued, continue_error);
        _exit(updated != 0 || continued != -1 || continue_error != EBUSY);
    }
    int status = 0;
    return waitpid(debugger, &status, 0) != debugger || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
