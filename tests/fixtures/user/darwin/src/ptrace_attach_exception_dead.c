/* A dead-name exception handler can be installed and queried remotely. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile sig_atomic_t tracee;
static void timeout(int sig) {
    (void)sig;
    if (tracee > 0)
        kill(tracee, SIGKILL);
    _exit(124);
}
static pid_t wait_stop(pid_t p, int *s) {
    pid_t r;
    do {
        r = waitpid(p, s, WNOHANG);
        if (!r)
            usleep(1000);
    } while (!r);
    return r;
}
int main(void) {
    setbuf(stdout, NULL);
    signal(SIGALRM, timeout);
    alarm(60);
    int gate[2];
    if (pipe(gate))
        return 1;
    pid_t p = fork();
    if (p < 0)
        return 2;
    if (!p) {
        close(gate[1]);
        char c;
        ssize_t count;
        do {
            count = read(gate[0], &c, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1)
            _exit(90);
        _exit(42);
    }
    tracee = p;
    close(gate[0]);
    int status = 0;
    if (ptrace(PT_ATTACH, p, 0, 0) || wait_stop(p, &status) != p ||
        !WIFSTOPPED(status))
        goto fail;
    mach_port_t task = 0, port = 0;
    mach_port_type_t type = 0;
    kern_return_t kr = task_for_pid(mach_task_self(), p, &task);
    if (kr)
        goto fail;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) ||
        mach_port_insert_right(mach_task_self(), port, port,
                               MACH_MSG_TYPE_MAKE_SEND) ||
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE,
                           -1) ||
        mach_port_type(mach_task_self(), port, &type))
        goto fail;
    kern_return_t invalid = task_set_exception_ports(
        task, EXC_MASK_SOFTWARE, port, EXCEPTION_DEFAULT, 0x7fffffff);
    kr = task_set_exception_ports(task, EXC_MASK_SOFTWARE, port,
                                  EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    kern_return_t literal =
        task_set_exception_ports(task, EXC_MASK_SOFTWARE, MACH_PORT_DEAD,
                                 EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    printf("type=%x invalid=%d set=%d literal=%d\n", type, invalid, kr,
           literal);
    exception_mask_t masks[32] = {0};
    mach_port_t ports[32] = {0};
    exception_behavior_t behaviors[32] = {0};
    thread_state_flavor_t flavors[32] = {0};
    mach_msg_type_number_t count = 32;
    kern_return_t get = task_get_exception_ports(
        task, EXC_MASK_SOFTWARE, masks, &count, ports, behaviors, flavors);
    printf("get=%d count=%u mask=%x port=%x behavior=%d flavor=%d\n", get,
           count, count ? masks[0] : 0, count ? ports[0] : 0,
           count ? behaviors[0] : 0, count ? flavors[0] : 0);
    int valid = invalid == KERN_INVALID_ARGUMENT && kr == KERN_SUCCESS &&
                literal == KERN_SUCCESS && get == KERN_SUCCESS && count == 1 &&
                masks[0] == EXC_MASK_SOFTWARE && ports[0] == MACH_PORT_DEAD &&
                behaviors[0] == EXCEPTION_DEFAULT &&
                flavors[0] == THREAD_STATE_NONE;
    count = 32;
    kern_return_t swapped = task_swap_exception_ports(
        task, EXC_MASK_SOFTWARE, MACH_PORT_NULL, EXCEPTION_DEFAULT,
        THREAD_STATE_NONE, masks, &count, ports, behaviors, flavors);
    printf("swap=%d count=%u old=%x\n", swapped, count, count ? ports[0] : 0);
    valid = valid && swapped == KERN_SUCCESS && count == 1 &&
            ports[0] == MACH_PORT_DEAD;
    count = 32;
    get = task_get_exception_ports(task, EXC_MASK_SOFTWARE, masks, &count,
                                   ports, behaviors, flavors);
    printf("after=%d count=%u null=%d\n", get, count,
           count == 1 && ports[0] == MACH_PORT_NULL);
    valid = valid && get == KERN_SUCCESS && count == 1 &&
            ports[0] == MACH_PORT_NULL;
    if (ptrace(PT_CONTINUE, p, (caddr_t)1, 0) || write(gate[1], "x", 1) != 1 ||
        waitpid(p, &status, 0) != p)
        goto fail;
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !valid || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(p, SIGKILL);
    ptrace(PT_KILL, p, (caddr_t)1, 0);
    waitpid(p, NULL, 0);
    tracee = 0;
    return 1;
}
