// Waits that end while another thread keeps the CPU busy (it spins without
// entering the kernel): sleeps, a condition variable's timeout, a Mach
// receive's timeout, kevent and poll timeouts, and a read that another
// sleeping thread's write completes.
#include <errno.h>
#include <mach/mach.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/event.h>
#include <time.h>
#include <unistd.h>

static volatile int go;
static int pfd[2];

static void *spin(void *a) {
    while (!go) {
    }
    return a;
}

static void *writer(void *a) {
    usleep(20000);
    write(pfd[1], "w", 1);
    return a;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t spinner, w;
    pthread_create(&spinner, NULL, spin, NULL);
    usleep(10000);

    printf("usleep: %d\n", usleep(30000));
    struct timespec ts = {0, 30000000};
    printf("nanosleep: %d\n", nanosleep(&ts, NULL));

    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t c = PTHREAD_COND_INITIALIZER;
    struct timespec rel = {0, 30000000};
    pthread_mutex_lock(&m);
    int r = pthread_cond_timedwait_relative_np(&c, &m, &rel);
    pthread_mutex_unlock(&m);
    printf("condition timeout: %s\n", r == ETIMEDOUT ? "ETIMEDOUT" : "other");

    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    struct {
        mach_msg_header_t h;
        char pad[64];
    } msg;
    kern_return_t kr = mach_msg(&msg.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof msg, p, 30, 0);
    printf("mach receive: %#x\n", kr);

    int kq = kqueue();
    struct kevent ev;
    struct timespec kt = {0, 30000000};
    printf("kevent: %d\n", kevent(kq, NULL, 0, &ev, 1, &kt));

    pipe(pfd);
    struct pollfd pf = {pfd[0], POLLIN, 0};
    printf("poll: %d\n", poll(&pf, 1, 30));

    pthread_create(&w, NULL, writer, NULL);
    char b = 0;
    ssize_t n = read(pfd[0], &b, 1);
    printf("read: %zd %c\n", n, b);
    pthread_join(w, NULL);

    go = 1;
    pthread_join(spinner, NULL);
    printf("done\n");
    return 0;
}
