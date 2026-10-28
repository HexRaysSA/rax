/* EXC_SOFT_SIGNAL is sent only to the task exception action. */
#include <errno.h>
#include <mach/mach.h>
#include <mach/exc.h>
#include <mach/exception_types.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t received;
static mach_port_t port;
static int ready[2], release[2];
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
    char byte;
    if (write(ready[1], "x", 1) != 1 || read(release[0], &byte, 1) != 1) return (void *)1;
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
int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "update") != 0)) return 2;
    setbuf(stdout, NULL);
    if (pipe(ready) != 0 || pipe(release) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release[1]);
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
    close(ready[1]); close(release[0]);
    signal(SIGALRM, timed_out);
    alarm(60);
    char byte;
    if (read(ready[0], &byte, 1) != 1) {
        kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1;
    }
    int status = 0;
    pid_t stopped = waitpid(child, &status, WNOHANG);
    printf("stop=%d signal=%d\n", stopped == child && WIFSTOPPED(status),
           stopped == child && WIFSTOPPED(status) ? WSTOPSIG(status) : 0);
    if (argc == 2) {
        int updated = ptrace(PT_THUPDATE, child, (caddr_t)(uintptr_t)mach_thread_self(), 0);
        printf("update=%d\n", updated);
        if (updated != 0) {
            kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1;
        }
    }
    int killed = kill(child, SIGKILL);
    printf("kill=%d\n", killed);
    int early_status = 0;
    pid_t early = waitpid(child, &early_status, WNOHANG);
    printf("pending=%d\n", early == 0);
    if (early != 0) printf("early=%d errno=%d status=%x\n", early < 0 ? -1 : 1, errno, early_status);
    if (killed != 0 || early != 0 || write(release[1], "x", 1) != 1) {
        kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1;
    }
    pid_t got;
    do {
        got = waitpid(child, &status, 0);
    } while (got == child && WIFSTOPPED(status));
    tracee = 0;
    alarm(0);
    int sig = got == child && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    printf("signal %d\n", sig);
    return sig != SIGKILL;
}
