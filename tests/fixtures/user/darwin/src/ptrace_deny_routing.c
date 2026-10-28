/* A denied attach posts SIGSEGV to the process, not the calling thread. */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static int ready[2], release_child[2], worker_ready[2], observed[2], worker_exit[2];
static void on_segv(int sig) {
    (void)sig;
    (void)write(observed[1], "s", 1);
}
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
static void *worker(void *arg) {
    (void)arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);
    if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) return (void *)1;
    if (write(worker_ready[1], "r", 1) != 1) return (void *)1;
    char byte;
    while (read(worker_exit[0], &byte, 1) < 0 && errno == EINTR) {}
    return NULL;
}
int main(void) {
    setbuf(stdout, NULL);
    if (pipe(ready) || pipe(release_child) || pipe(worker_ready) || pipe(observed) || pipe(worker_exit)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release_child[1]);
        if (ptrace(PT_DENY_ATTACH, 0, 0, 0) || write(ready[1], "x", 1) != 1) _exit(90);
        char byte;
        _exit(read(release_child[0], &byte, 1) == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(release_child[0]);
    struct sigaction action = {0};
    action.sa_handler = on_segv;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL)) goto fail;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL)) goto fail;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) goto fail;
    char byte;
    if (read(ready[0], &byte, 1) != 1 || read(worker_ready[0], &byte, 1) != 1) goto fail;
    errno = 0;
    int result = ptrace(PT_ATTACHEXC, child, 0, 0);
    int error = errno;
    if (read(observed[0], &byte, 1) != 1) goto fail;
    printf("attach=%d errno=%d worker-signal=%d\n", result, error, byte == 's');
    (void)write(worker_exit[1], "x", 1);
    (void)write(release_child[1], "x", 1);
    void *worker_result = NULL;
    if (pthread_join(thread, &worker_result) || worker_result) goto fail;
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    int exit_code = got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("exit=%d\n", exit_code);
    return result != -1 || error != EBUSY || exit_code != 42;
fail:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    tracee = 0;
    return 1;
}
