/* PT_THUPDATE targets a different thread in the tracer's task. */
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static int ready[2], release_worker[2];
static _Atomic mach_port_t worker_port;
static int worker_pending = -1;

static void *worker(void *unused) {
    (void)unused;
    sigset_t blocked, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &blocked, NULL) != 0) {
        return NULL;
    }
    atomic_store_explicit(&worker_port, mach_thread_self(), memory_order_release);
    char byte;
    if (write(ready[1], "r", 1) == 1 && read(release_worker[0], &byte, 1) == 1 &&
        sigpending(&pending) == 0) {
        worker_pending = sigismember(&pending, SIGUSR1);
    }
    return NULL;
}

int main(void) {
    setbuf(stdout, NULL);
    pid_t debugger = fork();
    if (debugger < 0) {
        return 1;
    }
    if (debugger == 0) {
        pid_t child = fork();
        if (child < 0) {
            _exit(90);
        }
        if (child == 0) {
            if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
                _exit(91);
            }
            raise(SIGSTOP);
            _exit(92);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
            pipe(ready) != 0 || pipe(release_worker) != 0) {
            _exit(93);
        }
        pthread_t thread;
        char byte;
        if (pthread_create(&thread, NULL, worker, NULL) != 0 || read(ready[0], &byte, 1) != 1) {
            _exit(94);
        }
        errno = 0;
        mach_port_t port = atomic_load_explicit(&worker_port, memory_order_acquire);
        int updated = ptrace(PT_THUPDATE, child, (caddr_t)(uintptr_t)port, SIGUSR1);
        int update_error = errno;
        if (write(release_worker[1], "r", 1) != 1 || pthread_join(thread, NULL) != 0) {
            _exit(95);
        }
        errno = 0;
        int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
        int continue_error = errno;
        printf("update=%d errno=%d pending=%d continue=%d errno=%d\n",
               updated, update_error, worker_pending, continued, continue_error);
        _exit(updated != 0 || worker_pending != 1 || continued != -1 || continue_error != EBUSY);
    }
    int status = 0;
    return waitpid(debugger, &status, 0) != debugger || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
