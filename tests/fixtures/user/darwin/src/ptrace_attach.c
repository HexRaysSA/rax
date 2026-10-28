/* PT_ATTACH to a running, get-task-allow child and its continuation. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
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

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], release[2];
    if (pipe(ready) != 0 || pipe(release) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        if (write(ready[1], "x", 1) != 1) {
            _exit(90);
        }
        char byte;
        ssize_t n;
        do {
            n = read(release[0], &byte, 1);
        } while (n < 0 && errno == EINTR);
        _exit(n == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]);
    close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    errno = 0;
    int attached = ptrace(PT_ATTACH, child, 0, 0);
    printf("attach %d %d\n", attached, errno);
    if (attached != 0) {
        write(release[1], "x", 1);
        waitpid(child, NULL, 0);
        tracee = 0;
        return 1;
    }
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status)) {
        if (got != child && (got >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("attach-stop failed\n");
        return 1;
    }
    printf("attach-stop signal=%d\n", WSTOPSIG(status));
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(mach_task_self(), child, &task);
    printf("task-for-pid %d port=%d\n", task_result, task != MACH_PORT_NULL);
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t threads_result = task_result == KERN_SUCCESS
        ? task_threads(task, &threads, &count) : KERN_FAILURE;
    printf("task-threads %d nonempty=%d\n", threads_result, count != 0);
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    if (threads != NULL) {
        vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    }
    if (task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), task);
    }
    errno = 0;
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    printf("continue %d %d\n", continued, errno);
    if (continued != 0) {
        kill(child, SIGKILL);
    } else {
        write(release[1], "x", 1);
    }
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return task_result != KERN_SUCCESS || threads_result != KERN_SUCCESS || count == 0
        || continued != 0 || code != 42;
}
