/* Event, timer, and signal descriptors and POSIX timers: eventfd counters and
 * semaphores, their limits and readiness, across threads and processes;
 * timerfd one-shot and periodic expiry, tick counts, TFD_IOC_SET_TICKS, and
 * gettime/settime; signalfd reads of blocked signals, mask updates, and
 * readiness; timer_create notification kinds, overruns, one pending signal
 * per timer, gettime/settime/delete, and the error cases of each call.
 * Timing checks use generous bounds, so the output does not depend on
 * scheduling. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#ifndef TFD_IOC_SET_TICKS
#define TFD_IOC_SET_TICKS _IOW('T', 0, uint64_t)
#endif

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

static int readable(int fd, int ms) {
    struct pollfd p = {fd, POLLIN, 0};
    return poll(&p, 1, ms) == 1 && (p.revents & POLLIN);
}

static short revents(int fd, short events) {
    struct pollfd p = {fd, events, 0};
    poll(&p, 1, 0);
    return p.revents;
}

/* The name /proc/self/fd/N links to. */
static int link_is(int fd, const char *want) {
    char path[64], buf[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, buf, sizeof buf - 1);
    if (n < 0) return 0;
    buf[n] = 0;
    return !strcmp(buf, want);
}

static int anon_inode(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0600 && (st.st_mode & S_IFMT) == 0 &&
           st.st_nlink == 1 && st.st_size == 0 && st.st_uid == geteuid();
}

static uint64_t get(int fd) {
    uint64_t v = 0;
    return read(fd, &v, 8) == 8 ? v : (uint64_t)-1;
}

static int put(int fd, uint64_t v) { return write(fd, &v, 8) == 8; }

static void *write_later(void *arg) {
    sleep_ms(50);
    put(*(int *)arg, 5);
    return 0;
}

static void eventfds(void) {
    CHECK_ERR("eventfd-flags", eventfd(0, 0x10), EINVAL);
    int e = eventfd(3, EFD_NONBLOCK);
    CHECK("eventfd-anon-inode", anon_inode(e) && link_is(e, "anon_inode:[eventfd]"));
    CHECK("eventfd-flags-rdwr", fcntl(e, F_GETFL) == (O_RDWR | O_NONBLOCK));
    CHECK("eventfd-initial", get(e) == 3);
    CHECK_ERR("eventfd-empty", read(e, &(uint64_t){0}, 8), EAGAIN);
    CHECK_ERR("eventfd-short-read", read(e, &(uint32_t){0}, 4), EINVAL);
    CHECK_ERR("eventfd-short-write", write(e, "1234567", 7), EINVAL);
    CHECK_ERR("eventfd-max-write", write(e, &(uint64_t){UINT64_MAX}, 8), EINVAL);
    CHECK("eventfd-idle-poll", revents(e, POLLIN | POLLOUT) == POLLOUT);
    put(e, 1);
    put(e, 2);
    CHECK("eventfd-sum", revents(e, POLLIN | POLLOUT) == (POLLIN | POLLOUT) && get(e) == 3);
    /* A larger buffer still moves eight bytes. */
    put(e, 9);
    uint64_t big[2] = {0, 0};
    CHECK("eventfd-long-read", read(e, big, 16) == 8 && big[0] == 9);
    /* The counter tops out at UINT64_MAX - 1. */
    CHECK("eventfd-fill", put(e, UINT64_MAX - 1));
    CHECK("eventfd-full-poll", revents(e, POLLIN | POLLOUT) == POLLIN);
    CHECK_ERR("eventfd-overflow", write(e, &(uint64_t){1}, 8), EAGAIN);
    CHECK("eventfd-zero-write", put(e, 0));
    CHECK("eventfd-drain", get(e) == UINT64_MAX - 1);
    /* No position: lseek reports 0, pread has none. */
    CHECK("eventfd-lseek", lseek(e, 5, SEEK_SET) == 0);
    CHECK_ERR("eventfd-pread", pread(e, &(uint64_t){0}, 8, 0), ESPIPE);
    CHECK_ERR("eventfd-zero-read", read(e, big, 0), EINVAL);
    CHECK_ERR("eventfd-fionread", ioctl(e, FIONREAD, &(int){0}), ENOTTY);
    close(e);

    int s = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    CHECK("eventfd-semaphore", get(s) == 1 && get(s) == 1);
    CHECK_ERR("eventfd-semaphore-empty", read(s, &(uint64_t){0}, 8), EAGAIN);
    close(s);

    /* A blocking read sleeps until another thread writes. */
    int b = eventfd(0, 0);
    pthread_t t;
    pthread_create(&t, 0, write_later, &b);
    double t0 = now();
    uint64_t v = get(b);
    CHECK("eventfd-blocking-read", v == 5 && now() - t0 > 0.02);
    pthread_join(t, 0);

    /* A child process shares the counters: it signals on one and waits
     * on the other. */
    int reply = eventfd(0, 0);
    pid_t p = fork();
    if (p == 0) {
        put(b, 7);
        _exit(get(reply) == 1 ? 0 : 1);
    }
    CHECK("eventfd-across-fork", get(b) == 7);
    put(reply, 1);
    int st;
    CHECK("eventfd-child-read", waitpid(p, &st, 0) == p && WIFEXITED(st) && !WEXITSTATUS(st));
    close(b);
    close(reply);
}

static void timerfds(void) {
    CHECK_ERR("timerfd-clock", timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0), EINVAL);
    CHECK_ERR("timerfd-flags", timerfd_create(CLOCK_MONOTONIC, 1), EINVAL);
    int t = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK("timerfd-anon-inode", anon_inode(t) && link_is(t, "anon_inode:[timerfd]"));
    CHECK("timerfd-flags-rdwr", fcntl(t, F_GETFL) == (O_RDWR | O_NONBLOCK));
    struct itimerspec cur;
    CHECK("timerfd-disarmed", timerfd_gettime(t, &cur) == 0 && !cur.it_value.tv_sec &&
                                  !cur.it_value.tv_nsec && !cur.it_interval.tv_nsec);
    CHECK_ERR("timerfd-unexpired", read(t, &(uint64_t){0}, 8), EAGAIN);
    CHECK_ERR("timerfd-short-read", read(t, &(uint32_t){0}, 4), EINVAL);
    CHECK_ERR("timerfd-write", write(t, &(uint64_t){1}, 8), EINVAL);
    struct itimerspec bad = {{0, 0}, {0, 1000000000}};
    CHECK_ERR("timerfd-bad-nsec", timerfd_settime(t, 0, &bad, 0), EINVAL);
    struct itimerspec one = {{0, 0}, {0, 30000000}};
    CHECK_ERR("timerfd-settime-flags", timerfd_settime(t, 4, &one, 0), EINVAL);
    CHECK_ERR("timerfd-settime-badf", timerfd_settime(99, 0, &one, 0), EBADF);
    CHECK_ERR("timerfd-settime-not-timerfd", timerfd_settime(0, 0, &one, 0), EINVAL);
    CHECK_ERR("timerfd-gettime-not-timerfd", timerfd_gettime(0, &cur), EINVAL);

    /* One-shot: one tick, then disarmed. */
    timerfd_settime(t, 0, &one, 0);
    CHECK("timerfd-armed", timerfd_gettime(t, &cur) == 0 && cur.it_value.tv_nsec > 0 &&
                               cur.it_value.tv_nsec <= 30000000);
    CHECK("timerfd-oneshot-poll", readable(t, 2000));
    CHECK("timerfd-oneshot-ticks", get(t) == 1);
    CHECK("timerfd-oneshot-done", timerfd_gettime(t, &cur) == 0 && !cur.it_value.tv_sec &&
                                      !cur.it_value.tv_nsec && !readable(t, 50));

    /* Periodic: missed periods add up; the old setting comes back. */
    struct itimerspec every = {{0, 20000000}, {0, 20000000}}, old;
    timerfd_settime(t, 0, &every, 0);
    sleep_ms(130);
    /* At least six 20 ms periods pass in 130 ms. */
    uint64_t n = get(t);
    CHECK("timerfd-periodic-ticks", n >= 6 && n < 1000);
    CHECK("timerfd-periodic-gettime",
          timerfd_gettime(t, &cur) == 0 && cur.it_interval.tv_nsec == 20000000 &&
              cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0);
    struct itimerspec off = {{0, 0}, {0, 0}};
    CHECK("timerfd-old-setting", timerfd_settime(t, 0, &off, &old) == 0 &&
                                     old.it_interval.tv_nsec == 20000000 &&
                                     old.it_value.tv_nsec > 0);

    /* An absolute time already past fires without delay (on the next
     * timer interrupt, so poll for it). */
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    struct itimerspec past = {{0, 0}, {mono.tv_sec, mono.tv_nsec}};
    CHECK("timerfd-abstime-past", timerfd_settime(t, TFD_TIMER_ABSTIME, &past, 0) == 0 &&
                                      readable(t, 2000) && get(t) == 1);

    /* TFD_IOC_SET_TICKS sets the count; zero is refused. */
    CHECK_ERR("timerfd-set-ticks-zero", ioctl(t, TFD_IOC_SET_TICKS, &(uint64_t){0}), EINVAL);
    CHECK("timerfd-set-ticks", ioctl(t, TFD_IOC_SET_TICKS, &(uint64_t){42}) == 0 && get(t) == 42);
    CHECK_ERR("timerfd-other-ioctl", ioctl(t, FIONREAD, &(int){0}), ENOTTY);

    /* A blocking read waits for the expiry. */
    fcntl(t, F_SETFL, 0);
    struct itimerspec soon = {{0, 0}, {0, 40000000}};
    timerfd_settime(t, 0, &soon, 0);
    double t0 = now();
    CHECK("timerfd-blocking-read", get(t) == 1 && now() - t0 > 0.02);

    /* CLOCK_REALTIME with TFD_TIMER_CANCEL_ON_SET and a settled clock. */
    int r = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    struct timespec real;
    clock_gettime(CLOCK_REALTIME, &real);
    struct itimerspec later = {{0, 0}, {real.tv_sec + 100, 0}};
    CHECK("timerfd-cancel-on-set",
          timerfd_settime(r, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &later, 0) == 0);
    CHECK_ERR("timerfd-realtime-pending", read(r, &(uint64_t){0}, 8), EAGAIN);
    close(r);
    close(t);
}

static void signalfds(void) {
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &m, 0);
    CHECK_ERR("signalfd-size", syscall(SYS_signalfd4, -1, &m, 4, 0), EINVAL);
    CHECK_ERR("signalfd-flags", signalfd(-1, &m, 1), EINVAL);
    int s = signalfd(-1, &m, SFD_NONBLOCK);
    CHECK("signalfd-anon-inode", anon_inode(s) && link_is(s, "anon_inode:[signalfd]"));
    CHECK("signalfd-flags-rdwr", fcntl(s, F_GETFL) == (O_RDWR | O_NONBLOCK));
    struct signalfd_siginfo si[3];
    CHECK_ERR("signalfd-empty", read(s, si, sizeof si), EAGAIN);
    CHECK_ERR("signalfd-short-read", read(s, si, sizeof si[0] - 1), EINVAL);
    CHECK("signalfd-idle-poll", revents(s, POLLIN | POLLOUT) == 0);
    CHECK_ERR("signalfd-write", write(s, si, sizeof si[0]), EINVAL);

    /* Queued signals come out in order with their siginfo. */
    raise(SIGUSR1);
    union sigval val = {.sival_int = 77};
    sigqueue(getpid(), SIGRTMIN, val);
    sigqueue(getpid(), SIGRTMIN, val);
    CHECK("signalfd-ready", revents(s, POLLIN) == POLLIN);
    ssize_t n = read(s, si, sizeof si);
    CHECK("signalfd-read-three", n == 3 * (ssize_t)sizeof si[0]);
    CHECK("signalfd-kill-info", si[0].ssi_signo == SIGUSR1 && si[0].ssi_code == SI_TKILL &&
                                    si[0].ssi_pid == (uint32_t)getpid() &&
                                    si[0].ssi_uid == getuid());
    CHECK("signalfd-queue-info", si[1].ssi_signo == (uint32_t)SIGRTMIN &&
                                     si[1].ssi_code == SI_QUEUE && si[1].ssi_int == 77 &&
                                     si[2].ssi_signo == (uint32_t)SIGRTMIN);
    CHECK("signalfd-drained", revents(s, POLLIN) == 0);

    /* Only the mask's signals; a new mask applies to the descriptor. */
    sigset_t other;
    sigemptyset(&other);
    sigaddset(&other, SIGUSR2);
    sigprocmask(SIG_BLOCK, &other, 0);
    raise(SIGUSR2);
    CHECK_ERR("signalfd-not-in-mask", read(s, si, sizeof si[0]), EAGAIN);
    CHECK("signalfd-new-mask", signalfd(s, &other, 0) == s && read(s, si, sizeof si[0]) > 0 &&
                                   si[0].ssi_signo == SIGUSR2);
    CHECK_ERR("signalfd-mask-not-signalfd", signalfd(0, &other, 0), EINVAL);
    CHECK_ERR("signalfd-mask-badf", signalfd(99, &other, 0), EBADF);

    /* SIGKILL and SIGSTOP are silently left out of the mask. */
    sigset_t all;
    sigfillset(&all);
    int a = signalfd(-1, &all, SFD_NONBLOCK);
    CHECK("signalfd-full-mask", a >= 0);
    close(a);

    /* A blocking read sleeps until a signal is sent. */
    fcntl(s, F_SETFL, 0);
    signalfd(s, &m, 0);
    pid_t p = fork();
    if (p == 0) {
        sleep_ms(50);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    CHECK("signalfd-blocking-read", read(s, si, sizeof si[0]) > 0 && si[0].ssi_signo == SIGUSR1 &&
                                        si[0].ssi_code == SI_USER &&
                                        si[0].ssi_pid == (uint32_t)p);
    waitpid(p, 0, 0);
    close(s);
    sigprocmask(SIG_UNBLOCK, &m, 0);
    sigprocmask(SIG_UNBLOCK, &other, 0);
}

static volatile sig_atomic_t timer_hits, timer_overrun, timer_code, timer_value;

static void on_timer(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    timer_hits++;
    timer_code = si->si_code;
    timer_value = si->si_value.sival_int;
    timer_overrun = si->si_overrun;
}

static void posix_timers(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_timer;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN + 1, &sa, 0);

    timer_t id;
    struct sigevent ev = {0};
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGRTMIN + 1;
    ev.sigev_value.sival_int = 1234;
    CHECK_ERR("timer-bad-clock", timer_create(99, &ev, &id), EINVAL);
    ev.sigev_notify = 99;
    int kid;
    CHECK_ERR("timer-bad-notify", syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &kid), EINVAL);
    CHECK_ERR("timer-raw-clock", syscall(SYS_timer_create, CLOCK_MONOTONIC_RAW, 0, &kid),
              EOPNOTSUPP);
    CHECK_ERR("timer-bad-id-pointer", syscall(SYS_timer_create, CLOCK_MONOTONIC, 0, 0), EFAULT);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = 0;
    CHECK_ERR("timer-bad-signal", timer_create(CLOCK_MONOTONIC, &ev, &id), EINVAL);
    ev.sigev_signo = SIGRTMIN + 1;
    CHECK("timer-create", timer_create(CLOCK_MONOTONIC, &ev, &id) == 0);
    CHECK_ERR("timer-gettime-bad-id", syscall(SYS_timer_gettime, 12345, &(struct itimerspec){0}),
              EINVAL);
    CHECK_ERR("timer-delete-bad-id", syscall(SYS_timer_delete, 12345), EINVAL);

    /* A one-shot timer: one signal with the timer's value and no overrun. */
    struct itimerspec one = {{0, 0}, {0, 20000000}};
    CHECK("timer-settime", timer_settime(id, 0, &one, 0) == 0);
    for (int i = 0; i < 2000 && !timer_hits; i++) sleep_ms(1);
    CHECK("timer-oneshot", timer_hits == 1 && timer_code == SI_TIMER && timer_value == 1234 &&
                               timer_overrun == 0);
    struct itimerspec cur;
    CHECK("timer-oneshot-disarmed",
          timer_gettime(id, &cur) == 0 && !cur.it_value.tv_sec && !cur.it_value.tv_nsec);
    CHECK_ERR("timer-bad-nsec", timer_settime(id, 0, &(struct itimerspec){{0, 0}, {0, -1}}, 0),
              EINVAL);

    /* While blocked, a periodic timer queues one signal; the periods that
     * pass meanwhile are its overrun count (at least 11 of 10 ms in
     * 120 ms), reported with it and by timer_getoverrun. */
    sigset_t b;
    sigemptyset(&b);
    sigaddset(&b, SIGRTMIN + 1);
    sigprocmask(SIG_BLOCK, &b, 0);
    struct itimerspec every = {{0, 10000000}, {0, 10000000}};
    timer_settime(id, 0, &every, 0);
    sleep_ms(120);
    siginfo_t si;
    struct timespec zero = {0, 0};
    CHECK("timer-overrun", sigtimedwait(&b, &si, &zero) == SIGRTMIN + 1 &&
                               si.si_code == SI_TIMER && si.si_value.sival_int == 1234 &&
                               si.si_overrun >= 11 && si.si_overrun < 100000 &&
                               timer_getoverrun(id) == si.si_overrun);
    /* The dequeue re-armed it; its next expiry queues the signal again,
     * and a new setting makes that signal stale: dequeueing drops it. */
    sleep_ms(30);
    sigset_t pend;
    sigpending(&pend);
    CHECK("timer-requeued", sigismember(&pend, SIGRTMIN + 1));
    struct itimerspec off = {{0, 0}, {0, 0}}, old;
    CHECK("timer-old-setting", timer_settime(id, 0, &off, &old) == 0 &&
                                   old.it_interval.tv_nsec == 10000000 &&
                                   old.it_value.tv_nsec > 0);
    CHECK_ERR("timer-stale-dropped", sigtimedwait(&b, &si, &zero), EAGAIN);
    CHECK("timer-overrun-reset", timer_getoverrun(id) == 0);
    sigprocmask(SIG_UNBLOCK, &b, 0);
    CHECK("timer-delete", timer_delete(id) == 0);
    CHECK_ERR("timer-deleted", timer_gettime(id, &cur), EINVAL);

    /* No sigevent: SIGALRM carrying the timer's ID. */
    sigset_t alrm;
    sigemptyset(&alrm);
    sigaddset(&alrm, SIGALRM);
    sigprocmask(SIG_BLOCK, &alrm, 0);
    timer_t d;
    CHECK("timer-default-event", timer_create(CLOCK_REALTIME, 0, &d) == 0);
    timer_settime(d, 0, &one, 0);
    siginfo_t info;
    struct timespec wait = {2, 0};
    CHECK("timer-default-sigalrm", sigtimedwait(&alrm, &info, &wait) == SIGALRM &&
                                       info.si_code == SI_TIMER &&
                                       info.si_value.sival_int == (int)(intptr_t)d);
    timer_delete(d);

    /* SIGEV_NONE: no signal, but gettime shows the countdown and then
     * zero. */
    struct sigevent none = {0};
    none.sigev_notify = SIGEV_NONE;
    timer_t q;
    CHECK("timer-sigev-none", timer_create(CLOCK_MONOTONIC, &none, &q) == 0);
    timer_settime(q, 0, &one, 0);
    CHECK("timer-none-counting", timer_gettime(q, &cur) == 0 && cur.it_value.tv_nsec > 0);
    sleep_ms(40);
    CHECK("timer-none-expired", timer_gettime(q, &cur) == 0 && !cur.it_value.tv_sec &&
                                    !cur.it_value.tv_nsec);
    timer_delete(q);

    /* SIGEV_THREAD_ID must name a thread of this process. */
    struct sigevent tid = {0};
    tid.sigev_notify = SIGEV_THREAD_ID;
    tid.sigev_signo = SIGRTMIN + 1;
    tid.sigev_notify_thread_id = 0x7ffffff0;
    CHECK_ERR("timer-thread-id-other", timer_create(CLOCK_MONOTONIC, &tid, &q), EINVAL);
    tid.sigev_notify_thread_id = syscall(SYS_gettid);
    CHECK("timer-thread-id", timer_create(CLOCK_MONOTONIC, &tid, &q) == 0 && timer_delete(q) == 0);

    /* Timers are not inherited: the child has none of its parent's. */
    timer_t kept;
    timer_create(CLOCK_MONOTONIC, &none, &kept);
    pid_t p = fork();
    if (p == 0) _exit(timer_gettime(kept, &cur) == -1 && errno == EINVAL ? 0 : 1);
    int st;
    CHECK("timer-not-inherited", waitpid(p, &st, 0) == p && WIFEXITED(st) && !WEXITSTATUS(st));
    timer_delete(kept);
    sigprocmask(SIG_UNBLOCK, &alrm, 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    eventfds();
    timerfds();
    signalfds();
    posix_timers();
    FINISH();
}
