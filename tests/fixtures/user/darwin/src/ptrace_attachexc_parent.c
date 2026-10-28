/* Install a debugger-owned exception port on an attached child. */
#include <errno.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

struct observation { int exception; int count; int code; int signal; };
static int report_fd, reply_fd;
static mach_port_t port;
static volatile sig_atomic_t tracee;
static void caught(int sig) {
    (void)sig;
}

static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}

static void *server(void *unused) {
    (void)unused;
    struct { __Request__exception_raise_t request; mach_msg_trailer_t trailer; } message = {0};
    kern_return_t kr = mach_msg(&message.request.Head, MACH_RCV_MSG, 0,
        sizeof message, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return (void *)1;
    __Request__exception_raise_t *req = &message.request;
    struct observation result = { req->exception, (int)req->codeCnt, req->code[0], req->code[1] };
    char byte;
    if (write(report_fd, &result, sizeof result) != sizeof result ||
        read(reply_fd, &byte, 1) != 1) return (void *)1;
    __Reply__exception_raise_t reply = {0};
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.Head.msgh_size = sizeof reply;
    reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
    reply.Head.msgh_id = req->Head.msgh_id + 100;
    reply.NDR = NDR_record;
    reply.RetCode = KERN_SUCCESS;
    kr = mach_msg(&reply.Head, MACH_SEND_MSG, sizeof reply, 0,
        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), req->thread.name);
    mach_port_deallocate(mach_task_self(), req->task.name);
    return (void *)(uintptr_t)(kr != KERN_SUCCESS);
}

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], report[2], reply[2], release[2];
    if (pipe(ready) || pipe(report) || pipe(reply) || pipe(release)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(report[0]); close(reply[1]); close(release[1]);
        report_fd = report[1]; reply_fd = reply[0];
        signal(SIGUSR1, caught);
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS ||
            mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS ||
            task_set_exception_ports(mach_task_self(), EXC_MASK_SOFTWARE, port,
                                     EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS) _exit(90);
        pthread_t thread;
        if (pthread_create(&thread, NULL, server, NULL) != 0 || write(ready[1], "r", 1) != 1) _exit(91);
        char byte;
        ssize_t count;
        do { count = read(release[0], &byte, 1); } while (count < 0 && errno == EINTR);
        void *result = NULL;
        if (count != 1 || pthread_join(thread, &result) != 0 || result != NULL) _exit(92);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(report[1]); close(reply[0]); close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    errno = 0;
    int attached = ptrace(PT_ATTACHEXC, child, 0, 0);
    int error = errno;
    printf("attach=%d errno=%d\n", attached, error);
    if (attached != 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1; }
    struct observation observed;
    if (read(report[0], &observed, sizeof observed) != sizeof observed) return 1;
    printf("exception=%d count=%d code=%d signal=%d\n",
           observed.exception, observed.count, observed.code, observed.signal);
    int status = 0;
    pid_t got = waitpid(child, &status, WNOHANG);
    int stopped = got == child && WIFSTOPPED(status);
    printf("stop=%d signal=%d\n", stopped, stopped ? WSTOPSIG(status) : 0);
    mach_port_t target = MACH_PORT_NULL, debugger_port = MACH_PORT_NULL;
    kern_return_t tf = task_for_pid(mach_task_self(), child, &target);
    kern_return_t pa = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &debugger_port);
    kern_return_t pi = mach_port_insert_right(mach_task_self(), debugger_port, debugger_port,
                                             MACH_MSG_TYPE_MAKE_SEND);
    kern_return_t se = task_set_exception_ports(target, EXC_MASK_SOFTWARE, debugger_port,
                                               EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    printf("task=%d allocate=%d insert=%d set=%d\n", tf, pa, pi, se);
    if (tf || pa || pi || se) { kill(child, SIGKILL); _exit(95); }
    errno = 0;
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    error = errno;
    printf("continue=%d errno=%d\n", continued, error);
    if (continued != 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1; }
    if (write(reply[1], "r", 1) != 1 || kill(child, SIGUSR1) != 0) return 1;
    struct { __Request__exception_raise_t request; mach_msg_trailer_t trailer; } second = {0};
    kern_return_t kr = mach_msg(&second.request.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                sizeof second, debugger_port, 5000, MACH_PORT_NULL);
    printf("receive=%d exception=%d code=%d signal=%d\n", kr, second.request.exception,
           second.request.code[0], second.request.code[1]);
    if (kr != KERN_SUCCESS) { kill(child, SIGKILL); _exit(96); }
    int exception_pid = -1;
    kern_return_t identity = pid_for_task(second.request.task.name, &exception_pid);
    printf("identity=%d matches=%d\n", identity, exception_pid == child);
    errno = 0;
    int c2 = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    printf("continue2=%d errno=%d\n", c2, errno);
    if (c2) { kill(child, SIGKILL); _exit(97); }
    __Reply__exception_raise_t reply2 = {0};
    reply2.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply2.Head.msgh_size = sizeof reply2;
    reply2.Head.msgh_remote_port = second.request.Head.msgh_remote_port;
    reply2.Head.msgh_id = second.request.Head.msgh_id + 100;
    reply2.NDR = NDR_record;
    reply2.RetCode = KERN_SUCCESS;
    kr = mach_msg(&reply2.Head, MACH_SEND_MSG, sizeof reply2, 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("reply2=%d\n", kr);
    mach_port_deallocate(mach_task_self(), second.request.thread.name);
    mach_port_deallocate(mach_task_self(), second.request.task.name);
    if (kr != KERN_SUCCESS || write(release[1], "r", 1) != 1) return 1;
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", code);
    return !stopped || code != 42;
}
