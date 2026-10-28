/* PT_ATTACHEXC sends the initial SIGSTOP to the task exception port. */
#include <errno.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

struct observation { int exception; int count; int code; int signal; };
static int report_fd, reply_fd;
static mach_port_t port;
static volatile sig_atomic_t tracee;

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

int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "suspendkill"))) return 1;
    setbuf(stdout, NULL);
    int ready[2], report[2], reply[2], release[2];
    if (pipe(ready) || pipe(report) || pipe(reply) || pipe(release)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(report[0]); close(reply[1]); close(release[1]);
        report_fd = report[1]; reply_fd = reply[0];
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
    if (argc == 2) {
        mach_port_t task = MACH_PORT_NULL;
        thread_act_array_t threads = NULL;
        mach_msg_type_number_t count = 0;
        if (task_for_pid(mach_task_self(), child, &task) || task_threads(task, &threads, &count) || !count)
            goto suspend_fail;
        for (mach_msg_type_number_t i = 0; i < count; i++) if (thread_suspend(threads[i])) goto suspend_fail;
        errno = 0;
        int killed = ptrace(PT_KILL, child, (caddr_t)1, 0);
        int error2 = errno;
        if (killed) goto suspend_fail;
        usleep(200000);
        got = waitpid(child, &status, WNOHANG);
        int early = got == child && WIFSIGNALED(status);
        printf("kill=%d errno=%d early=%d\n", killed, error2, early);
        if (!early) {
            for (mach_msg_type_number_t i = 0; i < count; i++) if (thread_resume(threads[i])) goto suspend_fail;
            if (write(reply[1], "r", 1) != 1) goto suspend_fail;
            got = waitpid(child, &status, 0);
        }
        tracee = 0;
        alarm(0);
        int death = got == child && WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        printf("signal=%d\n", death);
        return !stopped || killed || early || death != SIGKILL;
suspend_fail:
        for (mach_msg_type_number_t i = 0; i < count; i++) thread_resume(threads[i]);
        write(reply[1], "r", 1);
        kill(child, SIGKILL);
        ptrace(PT_KILL, child, (caddr_t)1, 0);
        waitpid(child, NULL, 0);
        tracee = 0;
        alarm(0);
        return 1;
    }
    errno = 0;
    int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    error = errno;
    printf("continue=%d errno=%d\n", continued, error);
    if (continued != 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); tracee = 0; return 1; }
    if (write(reply[1], "r", 1) != 1 || write(release[1], "r", 1) != 1) return 1;
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", code);
    return !stopped || code != 42;
}
