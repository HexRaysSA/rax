// Threads sleeping on the same descriptor: one in poll and one in read on
// a pipe that the main thread, then a forked child, writes; two threads
// in read on one pipe; and a kqueue watching one socket for reading and
// for writing, which reports only the direction that is ready.
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int fds[2];

// Each thread's result, printed once both are joined.
static void *poller(void *arg) {
    struct pollfd p = {fds[0], POLLIN, 0};
    int n = poll(&p, 1, -1);
    *(int *)arg = n == 1 && (p.revents & POLLIN);
    return NULL;
}

static void *reader(void *arg) {
    char c = 0;
    *(int *)arg = (int)read(fds[0], &c, 1);
    return NULL;
}

static void two_waiters(int from_child) {
    pipe(fds);
    pthread_t a, b;
    int polled = -1, got = -1;
    pthread_create(&a, NULL, poller, &polled);
    pthread_create(&b, NULL, reader, &got);
    usleep(50000);
    pid_t pid = from_child ? fork() : 0;
    if (pid == 0) {
        // Two bytes: the reader takes one, and the poller still sees one.
        write(fds[1], "xy", 2);
        if (from_child) _exit(0);
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("poll readable %d, read %d\n", polled, got);
    if (from_child) waitpid(pid, NULL, 0);
    close(fds[0]), close(fds[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("written by this process\n");
    two_waiters(0);
    printf("written by a child\n");
    two_waiters(1);

    printf("two readers\n");
    pipe(fds);
    pthread_t a, b;
    int one = -1, two = -1;
    pthread_create(&a, NULL, reader, &one);
    pthread_create(&b, NULL, reader, &two);
    usleep(50000);
    pid_t pid = fork();
    if (pid == 0) {
        write(fds[1], "xy", 2);
        _exit(0);
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("reads %d %d\n", one, two);
    waitpid(pid, NULL, 0);

    // One socket watched both ways: writable, then readable too.
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int kq = kqueue();
    struct kevent ch[2];
    EV_SET(&ch[0], sv[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&ch[1], sv[0], EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    kevent(kq, ch, 2, NULL, 0, NULL);
    for (int round = 0; round < 2; round++) {
        if (round) write(sv[1], "z", 1);
        struct kevent ev[4];
        struct timespec zero = {0, 0};
        int n = kevent(kq, NULL, 0, ev, 4, &zero);
        int r = 0, w = 0;
        for (int i = 0; i < n; i++) r |= ev[i].filter == EVFILT_READ, w |= ev[i].filter == EVFILT_WRITE;
        printf("kqueue round %d: %d events, read %d write %d\n", round, n, r, w);
    }
    return 0;
}
