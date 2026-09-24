/* Interval timers, blocking calls interrupted by signals, and system-call
 * restart. Handlers only record; main prints booleans, so the output does
 * not depend on timing beyond generous bounds. */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static volatile sig_atomic_t ticks;
static volatile int wake_fd = -1, wake_at, alrm_code;

static void on_alarm(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    ticks++;
    alrm_code = si->si_code;
    if (wake_fd >= 0 && ticks == wake_at) write(wake_fd, "x", 1);
}

static void handle(int flags) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_alarm;
    sa.sa_flags = SA_SIGINFO | flags;
    sigaction(SIGALRM, &sa, NULL);
}

static void arm(long first_us, long every_us) {
    struct itimerval it = {{every_us / 1000000, every_us % 1000000},
                           {first_us / 1000000, first_us % 1000000}};
    setitimer(ITIMER_REAL, &it, NULL);
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* alarm + pause: the handler runs, pause returns EINTR. */
    handle(0);
    alarm(1);
    double t0 = now();
    CHECK_ERR("pause", pause(), EINTR);
    double dt = now() - t0;
    CHECK("alarm-fired", ticks == 1 && dt > 0.8 && dt < 5);
    CHECK("alarm-code-kernel", alrm_code == SI_KERNEL);

    /* A periodic ITIMER_REAL keeps firing. */
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGALRM);
    sigprocmask(SIG_BLOCK, &block, &old);
    ticks = 0;
    arm(10000, 10000);
    while (ticks < 5) sigsuspend(&old);
    arm(0, 0);
    sigprocmask(SIG_SETMASK, &old, NULL);
    CHECK("periodic", ticks == 5);

    /* getitimer reports the time left. */
    arm(2000000, 0);
    struct itimerval cur;
    getitimer(ITIMER_REAL, &cur);
    long left = cur.it_value.tv_sec * 1000000 + cur.it_value.tv_usec;
    CHECK("getitimer", left > 1500000 && left <= 2000000 && cur.it_interval.tv_sec == 0);
    arm(0, 0);
    getitimer(ITIMER_REAL, &cur);
    CHECK("disarmed", cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0);

    /* nanosleep interrupted by a handled signal: EINTR with the rest. */
    ticks = 0;
    arm(50000, 0);
    struct timespec req = {5, 0}, rem = {0, 0};
    CHECK_ERR("nanosleep-eintr", nanosleep(&req, &rem), EINTR);
    CHECK("nanosleep-remaining", ticks == 1 && rem.tv_sec >= 4 && rem.tv_sec < 5);

    /* A pipe read without SA_RESTART returns EINTR... */
    int p[2];
    pipe(p);
    char c;
    ticks = 0;
    arm(30000, 0);
    CHECK_ERR("read-eintr", read(p[0], &c, 1), EINTR);
    /* ...and with SA_RESTART it resumes until the second tick's handler
     * writes a byte. */
    handle(SA_RESTART);
    ticks = 0;
    wake_fd = p[1];
    wake_at = 2;
    arm(30000, 30000);
    ssize_t n = read(p[0], &c, 1);
    arm(0, 0);
    wake_fd = -1;
    CHECK("read-restarted", n == 1 && c == 'x' && ticks >= 2);

    /* poll is never restarted after a handler, even with SA_RESTART. */
    ticks = 0;
    arm(30000, 0);
    struct pollfd pfd = {p[0], POLLIN, 0};
    CHECK_ERR("poll-eintr", poll(&pfd, 1, 5000), EINTR);

    /* pselect6 writes the time left back (libc select wrappers may hand
     * the kernel a copy, so the system call is made directly). */
    handle(0);
    ticks = 0;
    arm(100000, 0);
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(p[0], &rd);
    struct timespec ts = {1, 500000000};
    CHECK_ERR("pselect-eintr", syscall(SYS_pselect6, p[0] + 1, &rd, NULL, NULL, &ts, NULL), EINTR);
    long ts_left = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
    CHECK("pselect-time-left", ts_left > 900000 && ts_left < 1500000);

    /* sigtimedwait takes a blocked timer signal without a handler. */
    sigprocmask(SIG_BLOCK, &block, NULL);
    arm(20000, 0);
    siginfo_t si;
    struct timespec wait = {5, 0};
    int sig = sigtimedwait(&block, &si, &wait);
    CHECK("sigtimedwait-timer", sig == SIGALRM && si.si_code == SI_KERNEL);
    sigprocmask(SIG_UNBLOCK, &block, NULL);

    /* The thread CPU clock cannot be slept on (kernel EOPNOTSUPP; the libc
     * wrapper would substitute its own error). */
    struct timespec tiny = {0, 1000};
    CHECK_ERR("clock-nanosleep-thread-cpu",
              syscall(SYS_clock_nanosleep, CLOCK_THREAD_CPUTIME_ID, 0, &tiny, NULL),
              EOPNOTSUPP);
    CHECK("clock-nanosleep-mono", clock_nanosleep(CLOCK_MONOTONIC, 0, &tiny, NULL) == 0);
    FINISH();
}
