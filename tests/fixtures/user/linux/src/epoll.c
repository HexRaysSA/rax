/* epoll: instances and their checks; level-triggered, edge-triggered, and
 * one-shot reporting over pipes, eventfd, timerfd, and signalfd; the
 * ready-list order and maxevents; interest items that outlive a dup'd
 * descriptor's close; nested instances and loops; epoll_pwait's mask and
 * epoll_pwait2's timeout; EINTR without restart; and an epoll descriptor in
 * poll. Timing checks use generous bounds. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void sleep_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&t, &t) != 0) {
    }
}

static int add(int ep, int fd, uint32_t events, uint64_t data) {
    struct epoll_event e = {.events = events, .data.u64 = data};
    return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
}

static int mod(int ep, int fd, uint32_t events, uint64_t data) {
    struct epoll_event e = {.events = events, .data.u64 = data};
    return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &e);
}

/* epoll_wait with no timeout, returning the count and the data of the
 * first event. */
static int wait1(int ep, uint64_t *data, uint32_t *events) {
    struct epoll_event e[8];
    int n = epoll_wait(ep, e, 8, 0);
    if (n > 0) {
        if (data) *data = e[0].data.u64;
        if (events) *events = e[0].events;
    }
    return n;
}

static void put(int fd, uint64_t v) { write(fd, &v, 8); }

static void creation(void) {
    CHECK_ERR("create-size", epoll_create(0), EINVAL);
    CHECK_ERR("create1-flags", epoll_create1(1), EINVAL);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK("create1", ep >= 0 && (fcntl(ep, F_GETFD) & FD_CLOEXEC));
    struct stat st;
    char link[64] = {0}, path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", ep);
    readlink(path, link, sizeof link - 1);
    CHECK("anon-inode", fstat(ep, &st) == 0 && (st.st_mode & 07777) == 0600 &&
                            !strcmp(link, "anon_inode:[eventpoll]"));
    CHECK_ERR("read", read(ep, link, 8), EINVAL);
    CHECK_ERR("write", write(ep, link, 8), EINVAL);
    close(ep);
}

static void ctl_checks(void) {
    int ep = epoll_create1(0), p[2];
    pipe(p);
    struct epoll_event e = {.events = EPOLLIN};
    CHECK_ERR("ctl-bad-event", epoll_ctl(ep, EPOLL_CTL_ADD, p[0], (void *)8), EFAULT);
    CHECK_ERR("ctl-bad-epfd", epoll_ctl(99, EPOLL_CTL_ADD, p[0], &e), EBADF);
    CHECK_ERR("ctl-bad-fd", epoll_ctl(ep, EPOLL_CTL_ADD, 99, &e), EBADF);
    CHECK_ERR("ctl-not-epoll", epoll_ctl(p[0], EPOLL_CTL_ADD, p[1], &e), EINVAL);
    CHECK_ERR("ctl-itself", epoll_ctl(ep, EPOLL_CTL_ADD, ep, &e), EINVAL);
    CHECK_ERR("ctl-bad-op", epoll_ctl(ep, 99, p[0], &e), EINVAL);
    CHECK_ERR("ctl-del-missing", epoll_ctl(ep, EPOLL_CTL_DEL, p[0], 0), ENOENT);
    CHECK_ERR("ctl-mod-missing", epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &e), ENOENT);
    CHECK("ctl-add", add(ep, p[0], EPOLLIN, 1) == 0);
    CHECK_ERR("ctl-add-twice", add(ep, p[0], EPOLLIN, 1), EEXIST);
    e.events = EPOLLIN | EPOLLEXCLUSIVE;
    CHECK_ERR("ctl-mod-exclusive", epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &e), EINVAL);
    e.events = EPOLLIN | EPOLLEXCLUSIVE | EPOLLRDHUP;
    CHECK_ERR("ctl-exclusive-bits", epoll_ctl(ep, EPOLL_CTL_ADD, p[1], &e), EINVAL);
    CHECK("ctl-del", epoll_ctl(ep, EPOLL_CTL_DEL, p[0], 0) == 0);
    /* The same description under two descriptors: two items. */
    int d = dup(p[0]);
    CHECK("ctl-dup-items", add(ep, p[0], EPOLLIN, 1) == 0 && add(ep, d, EPOLLIN, 2) == 0);
    close(d);
    close(p[0]);
    close(p[1]);
    close(ep);
}

static void level_and_edge(void) {
    int ep = epoll_create1(0), p[2];
    pipe(p);
    uint64_t data;
    uint32_t ev;
    CHECK("empty", add(ep, p[0], EPOLLIN, 7) == 0 && wait1(ep, 0, 0) == 0);
    write(p[1], "ab", 2);
    /* Level-triggered: reported while readable. */
    CHECK("level", wait1(ep, &data, &ev) == 1 && data == 7 && ev == EPOLLIN &&
                       wait1(ep, 0, 0) == 1);
    char b[8];
    read(p[0], b, 2);
    CHECK("level-drained", wait1(ep, 0, 0) == 0);
    /* Edge-triggered: once per arrival. */
    CHECK("edge-mod", mod(ep, p[0], EPOLLIN | EPOLLET, 8) == 0);
    write(p[1], "c", 1);
    CHECK("edge", wait1(ep, &data, 0) == 1 && data == 8 && wait1(ep, 0, 0) == 0);
    write(p[1], "d", 1);
    CHECK("edge-new-data", wait1(ep, 0, 0) == 1 && wait1(ep, 0, 0) == 0);
    read(p[0], b, 2);
    /* One-shot: reported once, then disabled until re-armed. */
    CHECK("oneshot-mod", mod(ep, p[0], EPOLLIN | EPOLLONESHOT, 9) == 0);
    write(p[1], "e", 1);
    CHECK("oneshot", wait1(ep, &data, 0) == 1 && data == 9 && wait1(ep, 0, 0) == 0);
    CHECK("oneshot-rearm", mod(ep, p[0], EPOLLIN | EPOLLONESHOT, 10) == 0 &&
                               wait1(ep, &data, 0) == 1 && data == 10);
    read(p[0], b, 1);
    /* Hang-up is always reported. */
    CHECK("hup-mod", mod(ep, p[0], EPOLLIN, 11) == 0);
    close(p[1]);
    CHECK("hup", wait1(ep, 0, &ev) == 1 && ev == EPOLLHUP);
    /* The write end: EPOLLOUT; with the reader gone, EPOLLERR. */
    int q[2];
    pipe(q);
    CHECK("out", add(ep, q[1], EPOLLOUT, 12) == 0);
    struct epoll_event e[4];
    int n = epoll_wait(ep, e, 4, 0);
    CHECK("out-ready", n == 2);
    close(q[0]);
    epoll_ctl(ep, EPOLL_CTL_DEL, p[0], 0);
    CHECK("err", wait1(ep, 0, &ev) == 1 && ev == (EPOLLOUT | EPOLLERR));
    close(q[1]);
    close(p[0]);
    close(ep);
}

static void order_and_maxevents(void) {
    int ep = epoll_create1(0), p[4][2];
    for (int i = 0; i < 4; i++) {
        pipe(p[i]);
        add(ep, p[i][0], EPOLLIN, i);
    }
    /* Ready in the order 2, 0, 3: reported in that order. */
    write(p[2][1], "x", 1);
    write(p[0][1], "x", 1);
    write(p[3][1], "x", 1);
    struct epoll_event e[4];
    int n = epoll_wait(ep, e, 4, 0);
    CHECK("ready-order", n == 3 && e[0].data.u64 == 2 && e[1].data.u64 == 0 &&
                             e[2].data.u64 == 3);
    /* maxevents takes from the front; the rest come next, then the
     * level-triggered ones reported before. */
    n = epoll_wait(ep, e, 1, 0);
    CHECK("maxevents", n == 1 && e[0].data.u64 == 2);
    n = epoll_wait(ep, e, 4, 0);
    CHECK("round-robin", n == 3 && e[0].data.u64 == 0 && e[1].data.u64 == 3 &&
                             e[2].data.u64 == 2);
    CHECK_ERR("maxevents-zero", epoll_wait(ep, e, 0, 0), EINVAL);
    CHECK_ERR("wait-bad-buffer", epoll_wait(ep, (void *)8, 4, 0), EFAULT);
    CHECK_ERR("wait-not-epoll", epoll_wait(p[0][0], e, 4, 0), EINVAL);
    for (int i = 0; i < 4; i++) close(p[i][0]), close(p[i][1]);
    close(ep);
}

static void closed_descriptors(void) {
    int ep = epoll_create1(0), p[2];
    pipe(p);
    int d = dup(p[0]);
    add(ep, p[0], EPOLLIN, 5);
    /* Closing one descriptor of the description leaves the item. */
    close(p[0]);
    write(p[1], "x", 1);
    uint64_t data;
    CHECK("item-outlives-close", wait1(ep, &data, 0) == 1 && data == 5);
    CHECK_ERR("item-by-closed-fd", epoll_ctl(ep, EPOLL_CTL_DEL, p[0], 0), EBADF);
    /* Closing the last one removes it. */
    close(d);
    CHECK("item-removed", wait1(ep, 0, 0) == 0);
    close(p[1]);
    close(ep);
}

static void descriptor_kinds(void) {
    int ep = epoll_create1(0);
    int e = eventfd(0, EFD_NONBLOCK);
    int t = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, 0);
    int s = signalfd(-1, &m, SFD_NONBLOCK);
    add(ep, e, EPOLLIN | EPOLLET, 1);
    add(ep, t, EPOLLIN, 2);
    add(ep, s, EPOLLIN, 3);
    CHECK("kinds-idle", wait1(ep, 0, 0) == 0);
    put(e, 1);
    uint64_t data;
    CHECK("eventfd-edge", wait1(ep, &data, 0) == 1 && data == 1 && wait1(ep, 0, 0) == 0);
    put(e, 1);
    CHECK("eventfd-each-write", wait1(ep, 0, 0) == 1);
    uint64_t v;
    read(e, &v, 8);
    struct itimerspec soon = {{0, 0}, {0, 20000000}};
    timerfd_settime(t, 0, &soon, 0);
    struct epoll_event ev[4];
    double t0 = now();
    int n = epoll_wait(ep, ev, 4, 2000);
    CHECK("timerfd-wakes", n == 1 && ev[0].data.u64 == 2 && now() - t0 > 0.01);
    read(t, &v, 8);
    raise(SIGUSR1);
    CHECK("signalfd", wait1(ep, &data, 0) == 1 && data == 3);
    struct signalfd_siginfo si;
    read(s, &si, sizeof si);
    CHECK("kinds-drained", wait1(ep, 0, 0) == 0);
    sigprocmask(SIG_UNBLOCK, &m, 0);
    close(e);
    close(t);
    close(s);
    close(ep);
}

static void *write_later(void *arg) {
    sleep_ms(50);
    write(*(int *)arg, "y", 1);
    return 0;
}

static volatile sig_atomic_t hits;
static void on_usr2(int sig) {
    (void)sig;
    hits++;
}

static void waiting(void) {
    int ep = epoll_create1(0), p[2];
    pipe(p);
    add(ep, p[0], EPOLLIN, 4);
    struct epoll_event e[2];
    /* A blocking wait ends when another thread writes. */
    pthread_t th;
    pthread_create(&th, 0, write_later, &p[1]);
    double t0 = now();
    int n = epoll_wait(ep, e, 2, 5000);
    CHECK("wait-wakes", n == 1 && e[0].data.u64 == 4 && now() - t0 > 0.02);
    pthread_join(th, 0);
    char b;
    read(p[0], &b, 1);
    /* A timeout. */
    t0 = now();
    CHECK("timeout", epoll_wait(ep, e, 2, 30) == 0 && now() - t0 > 0.02);
    struct timespec ts = {0, 30000000};
    t0 = now();
    CHECK("pwait2-timeout", syscall(SYS_epoll_pwait2, ep, e, 2, &ts, 0, 8) == 0 &&
                                now() - t0 > 0.02);
    ts.tv_nsec = 1000000000;
    CHECK_ERR("pwait2-bad-time", syscall(SYS_epoll_pwait2, ep, e, 2, &ts, 0, 8), EINVAL);
    /* A handler interrupts the wait: EINTR even with SA_RESTART. */
    struct sigaction sa = {0};
    sa.sa_handler = on_usr2;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, 0);
    struct itimerspec it = {{0, 0}, {0, 30000000}};
    timer_t tm;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR2;
    timer_create(CLOCK_MONOTONIC, &sev, &tm);
    timer_settime(tm, 0, &it, 0);
    CHECK_ERR("eintr", epoll_wait(ep, e, 2, 5000), EINTR);
    CHECK("eintr-handler", hits == 1);
    /* epoll_pwait's mask blocks it for the wait. */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR2);
    timer_settime(tm, 0, &it, 0);
    t0 = now();
    CHECK("pwait-mask", epoll_pwait(ep, e, 2, 100, &block) == 0 && now() - t0 > 0.08 &&
                            hits == 2);
    CHECK_ERR("pwait-mask-size", syscall(SYS_epoll_pwait, ep, e, 2, 0, &block, 4), EINVAL);
    timer_delete(tm);
    close(p[0]);
    close(p[1]);
    close(ep);
}

static void nesting(void) {
    int outer = epoll_create1(0), inner = epoll_create1(0), p[2];
    pipe(p);
    add(inner, p[0], EPOLLIN, 1);
    CHECK("nest", add(outer, inner, EPOLLIN, 2) == 0);
    CHECK_ERR("nest-loop", add(inner, outer, EPOLLIN, 3), ELOOP);
    uint64_t data;
    CHECK("nest-idle", wait1(outer, 0, 0) == 0);
    write(p[1], "z", 1);
    CHECK("nest-ready", wait1(outer, &data, 0) == 1 && data == 2);
    struct pollfd pf = {inner, POLLIN, 0};
    CHECK("poll-epoll", poll(&pf, 1, 0) == 1 && pf.revents == POLLIN);
    /* Four levels of nesting are allowed, five are a loop. */
    int e[6];
    e[0] = epoll_create1(0);
    add(e[0], p[0], EPOLLIN, 0);
    int ok = 1;
    for (int i = 1; i <= 4; i++) {
        e[i] = epoll_create1(0);
        ok &= add(e[i], e[i - 1], EPOLLIN, i) == 0;
    }
    e[5] = epoll_create1(0);
    CHECK("nest-depth", ok);
    CHECK_ERR("nest-too-deep", add(e[5], e[4], EPOLLIN, 5), ELOOP);
    for (int i = 0; i < 6; i++) close(e[i]);
    close(p[0]);
    close(p[1]);
    close(inner);
    close(outer);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    creation();
    ctl_checks();
    level_and_edge();
    order_and_maxevents();
    closed_descriptors();
    descriptor_kinds();
    waiting();
    nesting();
    FINISH();
}
