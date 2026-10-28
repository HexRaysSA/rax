/* Clear an installed exception action through an attached child's task port. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        mach_port_t handler = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &handler) ||
            mach_port_insert_right(mach_task_self(), handler, handler, MACH_MSG_TYPE_MAKE_SEND) ||
            task_set_exception_ports(mach_task_self(), EXC_MASK_SOFTWARE, handler,
                                     EXCEPTION_DEFAULT, THREAD_STATE_NONE)) _exit(92);
        char byte;
        if (write(ready[1], "r", 1) != 1) _exit(90);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        mach_msg_type_number_t count = EXC_TYPES_COUNT;
        kern_return_t query = task_get_exception_ports(mach_task_self(), EXC_MASK_SOFTWARE,
                                                       masks, &count, ports, behaviors, flavors);
        int cleared = query == KERN_SUCCESS && count == 1 && ports[0] == MACH_PORT_NULL;
        printf("exception-cleared=%d\n", cleared);
        _exit(n == 1 && cleared ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(gate[0]);
    char byte;
    int status;
    if (read(ready[0], &byte, 1) != 1 || ptrace(PT_ATTACH, child, 0, 0) ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) goto fail;
    exception_mask_t info_masks[EXC_TYPES_COUNT];
    exception_handler_info_t infos[EXC_TYPES_COUNT];
    exception_behavior_t info_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t info_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t info_count = EXC_TYPES_COUNT;
    kern_return_t info = task_get_exception_ports_info(task, EXC_MASK_SOFTWARE, info_masks,
                                                       &info_count, infos, info_behaviors, info_flavors);
    int live = info == KERN_SUCCESS && info_count == 1 && infos[0].iip_port_object != 0 &&
               infos[0].iip_receiver_object != 0;
    printf("exception-info=%d live=%d\n", info, live);
    kern_return_t invalid = task_set_exception_ports(task, UINT32_MAX, MACH_PORT_NULL,
                                                     EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    kern_return_t clear = task_set_exception_ports(task, EXC_MASK_SOFTWARE, MACH_PORT_NULL,
                                                   EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    printf("exception-invalid=%d clear=%d\n", invalid, clear);
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t query = task_get_exception_ports(task, EXC_MASK_SOFTWARE, masks, &count,
                                                   ports, behaviors, flavors);
    int null = query == KERN_SUCCESS && count == 1 && ports[0] == MACH_PORT_NULL;
    printf("exception-query=%d null=%d\n", query, null);
    if (!live || invalid != KERN_INVALID_ARGUMENT || clear || !null || ptrace(PT_CONTINUE, child, (caddr_t)1, 0) ||
        write(gate[1], "x", 1) != 1 || waitpid(child, &status, 0) != child) goto fail;
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    tracee = 0;
    alarm(0);
    return 1;
}
