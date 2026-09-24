/* How a multithreaded process ends, selected by argv[1]:
 *   leader  the main thread exits (SYS_exit 7) before the last thread
 *           (SYS_exit 9): the last thread's code becomes the group's
 *           (synchronize_group_exit), 9.
 *   group   a thread calls exit_group(5) while the main thread waits.
 *   segv    a thread faults: the whole process dies of SIGSEGV.
 *   kill    a thread blocks nothing and SIGTERM is sent to the process
 *           while the main thread blocks it: the process dies of SIGTERM.
 * Output is written with write(2) so no stdio buffer is lost. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void say(const char *s) { write(1, s, strlen(s)); }

static void *last(void *arg) {
    (void)arg;
    struct timespec t = {0, 50000000};
    nanosleep(&t, 0);
    say("last thread\n");
    syscall(SYS_exit, 9);
    return 0;
}

static void *group(void *arg) {
    (void)arg;
    say("exit_group from a thread\n");
    syscall(SYS_exit_group, 5);
    return 0;
}

static void *fault(void *arg) {
    (void)arg;
    say("faulting\n");
    *(volatile int *)arg = 1;
    return 0;
}

static void *unblocked(void *arg) {
    (void)arg;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGTERM);
    pthread_sigmask(SIG_UNBLOCK, &s, 0);
    say("worker takes SIGTERM\n");
    kill(getpid(), SIGTERM);
    for (;;) pause();
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    pthread_t t;
    if (!strcmp(mode, "leader")) {
        pthread_create(&t, 0, last, 0);
        say("leader exits\n");
        syscall(SYS_exit, 7);
    } else if (!strcmp(mode, "group")) {
        pthread_create(&t, 0, group, 0);
        pthread_join(t, 0);
        say("not reached\n");
    } else if (!strcmp(mode, "segv")) {
        pthread_create(&t, 0, fault, 0);
        pthread_join(t, 0);
        say("not reached\n");
    } else if (!strcmp(mode, "kill")) {
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &s, 0);
        pthread_create(&t, 0, unblocked, 0);
        pthread_join(t, 0);
        say("not reached\n");
    }
    return 1;
}
