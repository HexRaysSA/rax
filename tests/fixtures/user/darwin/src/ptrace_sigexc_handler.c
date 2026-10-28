/* EXC_SOFT_SIGNAL is sent only to the task exception action. */
#include <mach/mach.h>
#include <mach/exc.h>
#include <mach/exception_types.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t received;
static mach_port_t port;
static void caught(int sig) { (void)sig; received++; }
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
static void *server(void *arg) {
    (void)arg;
    struct { __Request__exception_raise_t request; mach_msg_trailer_t trailer; } message = {0};
    kern_return_t kr = mach_msg(&message.request.Head, MACH_RCV_MSG, 0,
        sizeof(message), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return (void *)1;
    __Request__exception_raise_t *req = &message.request;
    printf("exception type=%d count=%u code=%d signal=%d\n",
        req->exception, req->codeCnt, req->code[0], req->code[1]);
    __Reply__exception_raise_t reply = {0};
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.Head.msgh_size = sizeof(reply);
    reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
    reply.Head.msgh_id = req->Head.msgh_id + 100;
    reply.NDR = NDR_record;
    reply.RetCode = KERN_SUCCESS;
    kr = mach_msg(&reply.Head, MACH_SEND_MSG, sizeof(reply), 0,
        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), req->thread.name);
    mach_port_deallocate(mach_task_self(), req->task.name);
    return (void *)(uintptr_t)(kr != KERN_SUCCESS);
}
int main(void) {
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        signal(SIGUSR1, caught);
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS ||
            mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS ||
            task_set_exception_ports(mach_task_self(), EXC_MASK_SOFTWARE, port,
                                     EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS) _exit(90);
        pthread_t thread;
        if (pthread_create(&thread, NULL, server, NULL) != 0) _exit(91);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0 || ptrace(PT_SIGEXC, 0, 0, 0) != 0) _exit(92);
        raise(SIGUSR1);
        void *result = NULL;
        if (pthread_join(thread, &result) != 0 || result != NULL) _exit(93);
        printf("received %d\n", (int)received);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t got;
    do {
        got = waitpid(child, &status, 0);
    } while (got == child && WIFSTOPPED(status));
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit %d\n", code);
    return code != 42;
}
