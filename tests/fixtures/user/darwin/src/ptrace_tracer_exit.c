/* A tracer's exit kills a child blocked in a task exception handler. */
#include <mach/mach.h>
#include <mach/exc.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracer_pid, tracee_pid;
static int alive[2], notice[2], ready[2], hold[2];
static mach_port_t exception_port;
static void timed_out(int sig) {
    (void)sig;
    if (tracee_pid > 0) kill((pid_t)tracee_pid, SIGKILL);
    if (tracer_pid > 0) kill((pid_t)tracer_pid, SIGKILL);
    _exit(2);
}
static void *server(void *arg) {
    (void)arg;
    struct { __Request__exception_raise_t request; mach_msg_trailer_t trailer; } message = {0};
    if (mach_msg(&message.request.Head, MACH_RCV_MSG, 0, sizeof(message),
                 exception_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != KERN_SUCCESS) _exit(90);
    if (write(ready[1], "x", 1) != 1) _exit(91);
    char byte;
    (void)read(hold[0], &byte, 1);
    _exit(92);
}
int main(void) {
    setbuf(stdout, NULL);
    if (pipe(alive) || pipe(notice) || pipe(ready) || pipe(hold)) return 1;
    pid_t tracer = fork();
    if (tracer < 0) return 1;
    if (tracer == 0) {
        close(alive[0]); close(notice[0]); close(hold[1]);
        pid_t child = fork();
        if (child < 0) _exit(80);
        if (child == 0) {
            close(notice[1]); close(ready[0]);
            if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port) ||
                mach_port_insert_right(mach_task_self(), exception_port, exception_port,
                                       MACH_MSG_TYPE_MAKE_SEND) ||
                task_set_exception_ports(mach_task_self(), EXC_MASK_SOFTWARE, exception_port,
                                         EXCEPTION_DEFAULT, THREAD_STATE_NONE)) _exit(81);
            pthread_t handler;
            if (pthread_create(&handler, NULL, server, NULL)) _exit(82);
            if (ptrace(PT_TRACE_ME, 0, 0, 0) || ptrace(PT_SIGEXC, 0, 0, 0)) _exit(83);
            raise(SIGUSR1);
            _exit(84);
        }
        close(alive[1]); close(ready[1]); close(hold[0]);
        if (write(notice[1], &child, sizeof(child)) != sizeof(child)) _exit(85);
        char byte;
        if (read(ready[0], &byte, 1) != 1) _exit(86);
        int status = 0;
        pid_t got = 0;
        for (int i = 0; i < 1000 && got == 0; ++i) {
            got = waitpid(child, &status, WNOHANG);
            if (got == 0) usleep(1000);
        }
        if (got != child || !WIFSTOPPED(status)) _exit(87);
        if (write(notice[1], "s", 1) != 1) _exit(88);
        _exit(0);
    }
    tracer_pid = tracer;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(alive[1]); close(notice[1]); close(ready[0]); close(ready[1]); close(hold[0]);
    pid_t child = 0;
    char byte;
    ssize_t count = read(notice[0], &child, sizeof(child));
    tracee_pid = child;
    if (count != sizeof(child) || read(notice[0], &byte, 1) != 1) return 1;
    int status = 0;
    if (waitpid(tracer, &status, 0) != tracer || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    tracer_pid = 0;
    ssize_t eof = read(alive[0], &byte, 1);
    tracee_pid = 0;
    alarm(0);
    printf("tracer-exit=%d tracee-pipe-eof=%d\n", WEXITSTATUS(status), eof == 0);
    return eof != 0;
}
