/* Threads: creation and joining, synchronization objects, thread-local
 * storage, timed waits, thread-directed and process-directed signals,
 * robust and priority-inheritance mutexes, cancellation of blocked calls,
 * /proc thread views, and the clone/futex system calls directly. Only the
 * main thread prints, and every observation is independent of how the
 * threads interleave. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif

static long gettid_(void) { return syscall(SYS_gettid); }

static long futex(volatile uint32_t *uaddr, int op, uint32_t val, const struct timespec *ts,
                  volatile uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, ts, uaddr2, val3);
}

/* A timespec `ms` milliseconds from now on `clock`. */
static struct timespec after_ms(clockid_t clock, long ms) {
    struct timespec t;
    clock_gettime(clock, &t);
    t.tv_nsec += (ms % 1000) * 1000000;
    t.tv_sec += ms / 1000 + t.tv_nsec / 1000000000;
    t.tv_nsec %= 1000000000;
    return t;
}

/* ---------------------------------------------------------- basics */

static long ids[8];

static void *square(void *arg) {
    long i = (long)arg;
    ids[i] = gettid_();
    return (void *)(i * i);
}

static void basics(void) {
    pthread_t t[8];
    for (long i = 0; i < 8; i++) pthread_create(&t[i], 0, square, (void *)i);
    long sum = 0;
    for (int i = 0; i < 8; i++) {
        void *r;
        pthread_join(t[i], &r);
        sum += (long)r;
    }
    CHECK("create-join", sum == 140);
    int unique = 1;
    for (int i = 0; i < 8; i++) {
        if (ids[i] == getpid() || ids[i] <= 0) unique = 0;
        for (int j = 0; j < i; j++) unique &= ids[i] != ids[j];
    }
    CHECK("thread-ids", unique && gettid_() == getpid());
}

/* -------------------------------------------------------- mutexes */

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long counter;

/* Increments per thread; yielding inside the critical section keeps the
 * lock contended. */
#define ADDS 5000

static void *add(void *arg) {
    pthread_mutex_t *m = arg;
    for (int i = 0; i < ADDS; i++) {
        pthread_mutex_lock(m);
        long v = counter;
        if (i % 29 == 0) sched_yield();
        counter = v + 1;
        pthread_mutex_unlock(m);
    }
    return 0;
}

static void contend(const char *name, pthread_mutex_t *m) {
    pthread_t t[4];
    counter = 0;
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, add, m);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    CHECK(name, counter == 4 * ADDS);
}

/* --------------------------------------------- condition variables */

static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t notfull = PTHREAD_COND_INITIALIZER, notempty = PTHREAD_COND_INITIALIZER;
static int queue[4], head, count;

static void *producer(void *arg) {
    (void)arg;
    for (int i = 1; i <= 2000; i++) {
        pthread_mutex_lock(&qlock);
        while (count == 4) pthread_cond_wait(&notfull, &qlock);
        queue[(head + count++) % 4] = i;
        pthread_cond_signal(&notempty);
        pthread_mutex_unlock(&qlock);
    }
    return 0;
}

static void condvar(void) {
    pthread_t p;
    pthread_create(&p, 0, producer, 0);
    int ordered = 1, next = 1;
    long sum = 0;
    while (next <= 2000) {
        pthread_mutex_lock(&qlock);
        while (count == 0) pthread_cond_wait(&notempty, &qlock);
        int v = queue[head];
        head = (head + 1) % 4;
        count--;
        pthread_cond_signal(&notfull);
        pthread_mutex_unlock(&qlock);
        ordered &= v == next++;
        sum += v;
    }
    pthread_join(p, 0);
    CHECK("condvar-queue", ordered && sum == 2001000);
}

/* ------------------------------------------------- barriers, rwlock */

static pthread_barrier_t bar;
static volatile int serials[5];

static void *barrier_worker(void *arg) {
    (void)arg;
    for (int r = 0; r < 5; r++) {
        if (pthread_barrier_wait(&bar) == PTHREAD_BARRIER_SERIAL_THREAD)
            __atomic_add_fetch(&serials[r], 1, __ATOMIC_SEQ_CST);
    }
    return 0;
}

static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
static long pa, pb;
static volatile int torn;

static void *writer(void *arg) {
    (void)arg;
    for (int i = 0; i < 3000; i++) {
        pthread_rwlock_wrlock(&rw);
        pa++;
        if (i % 50 == 0) sched_yield();
        pb++;
        pthread_rwlock_unlock(&rw);
    }
    return 0;
}

static void *reader(void *arg) {
    (void)arg;
    for (int i = 0; i < 3000; i++) {
        pthread_rwlock_rdlock(&rw);
        if (pa != pb) torn = 1;
        pthread_rwlock_unlock(&rw);
    }
    return 0;
}

static void barrier_rwlock(void) {
    pthread_t t[4];
    pthread_barrier_init(&bar, 0, 4);
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, barrier_worker, 0);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    int one_each = 1;
    for (int r = 0; r < 5; r++) one_each &= serials[r] == 1;
    CHECK("barrier", one_each);
    pthread_t w[2], r[3];
    for (int i = 0; i < 2; i++) pthread_create(&w[i], 0, writer, 0);
    for (int i = 0; i < 3; i++) pthread_create(&r[i], 0, reader, 0);
    for (int i = 0; i < 2; i++) pthread_join(w[i], 0);
    for (int i = 0; i < 3; i++) pthread_join(r[i], 0);
    CHECK("rwlock", !torn && pa == 6000 && pb == 6000);
}

/* ------------------------------------------------ thread-local data */

static __thread long tls = 42;

static void *tls_worker(void *arg) {
    long id = (long)arg;
    long initial = tls;
    tls = id;
    for (int i = 0; i < 200; i++) sched_yield();
    return (void *)(long)(initial == 42 && tls == id);
}

static void thread_local(void) {
    pthread_t t[4];
    for (long i = 0; i < 4; i++) pthread_create(&t[i], 0, tls_worker, (void *)(i + 100));
    int ok = 1;
    for (int i = 0; i < 4; i++) {
        void *r;
        pthread_join(t[i], &r);
        ok &= r != 0;
    }
    CHECK("tls", ok && tls == 42);
}

/* --------------------------------------------------- detach, timing */

static sem_t done;

static void *detached(void *arg) {
    (void)arg;
    sem_post(&done);
    return 0;
}

static pthread_mutex_t held = PTHREAD_MUTEX_INITIALIZER;
static sem_t held_ready, held_release;

static void *holder(void *arg) {
    (void)arg;
    pthread_mutex_lock(&held);
    sem_post(&held_ready);
    sem_wait(&held_release);
    pthread_mutex_unlock(&held);
    return 0;
}

static void timed(void) {
    sem_init(&done, 0, 0);
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, detached, 0);
    CHECK("detached", sem_wait(&done) == 0);

    struct timespec at = after_ms(CLOCK_REALTIME, 30);
    CHECK_ERR("sem-timedwait", sem_timedwait(&done, &at), ETIMEDOUT);

    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_t cv;
    pthread_cond_init(&cv, &ca);
    pthread_mutex_lock(&m);
    at = after_ms(CLOCK_MONOTONIC, 30);
    int r = pthread_cond_timedwait(&cv, &m, &at);
    pthread_mutex_unlock(&m);
    CHECK("cond-timedwait", r == ETIMEDOUT);

    sem_init(&held_ready, 0, 0);
    sem_init(&held_release, 0, 0);
    pthread_create(&t, 0, holder, 0);
    sem_wait(&held_ready);
    at = after_ms(CLOCK_REALTIME, 30);
    CHECK("mutex-timedlock", pthread_mutex_timedlock(&held, &at) == ETIMEDOUT);
    CHECK("mutex-trylock-busy", pthread_mutex_trylock(&held) == EBUSY);
    sem_post(&held_release);
    pthread_join(t, 0);
    CHECK("mutex-after-release", pthread_mutex_trylock(&held) == 0);
    pthread_mutex_unlock(&held);
}

/* ------------------------------------------------------------ signals */

static volatile long handler_tid;
static volatile sig_atomic_t go;

static void record_tid(int sig) {
    (void)sig;
    handler_tid = gettid_();
}

static volatile long waiting_tid;

static void *wait_for_go(void *arg) {
    int unblock = (long)arg;
    if (unblock) {
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, unblock);
        pthread_sigmask(SIG_UNBLOCK, &s, 0);
    }
    waiting_tid = gettid_();
    while (!go) pause();
    return 0;
}

static void *sigwaiter(void *arg) {
    sigset_t *set = arg;
    int sig = 0;
    sigwait(set, &sig);
    return (void *)(long)sig;
}

static void signals(void) {
    signal(SIGUSR1, record_tid);
    signal(SIGUSR2, record_tid);

    /* pthread_kill: the handler runs on the target thread. */
    pthread_t t;
    waiting_tid = 0;
    go = 0;
    pthread_create(&t, 0, wait_for_go, 0);
    while (!waiting_tid) sched_yield();
    long target = waiting_tid;
    handler_tid = 0;
    pthread_kill(t, SIGUSR1);
    while (!handler_tid) sched_yield();
    go = 1;
    pthread_kill(t, SIGUSR1);
    pthread_join(t, 0);
    CHECK("pthread-kill", handler_tid == target);

    /* A process signal goes to the only thread that does not block it. */
    sigset_t s, old;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &s, &old);
    waiting_tid = 0;
    go = 0;
    pthread_create(&t, 0, wait_for_go, (void *)(long)SIGUSR2);
    while (!waiting_tid) sched_yield();
    target = waiting_tid;
    handler_tid = 0;
    kill(getpid(), SIGUSR2);
    while (!handler_tid) sched_yield();
    go = 1;
    pthread_kill(t, SIGUSR2);
    pthread_join(t, 0);
    pthread_sigmask(SIG_SETMASK, &old, 0);
    CHECK("process-signal-target", handler_tid == target);

    /* sigwait in a dedicated thread, every thread blocking the signal. */
    sigset_t w;
    sigemptyset(&w);
    sigaddset(&w, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &w, &old);
    pthread_create(&t, 0, sigwaiter, &w);
    kill(getpid(), SIGUSR1);
    void *got;
    pthread_join(t, &got);
    pthread_sigmask(SIG_SETMASK, &old, 0);
    CHECK("sigwait-thread", (long)got == SIGUSR1);
}

/* -------------------------------------------- robust and PI mutexes */

static pthread_mutex_t robust;

static void *die_holding(void *arg) {
    (void)arg;
    pthread_mutex_lock(&robust);
    return 0;
}

static void robust_pi(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    /* musl asks get_robust_list whether the kernel supports robust lists. */
    int robust_ok = pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST) == 0;
    CHECK("robust-attr", robust_ok);
    if (robust_ok) {
        pthread_mutex_init(&robust, &a);
        pthread_t t;
        pthread_create(&t, 0, die_holding, 0);
        pthread_join(t, 0);
        int r = pthread_mutex_lock(&robust);
        CHECK("robust-owner-died", r == EOWNERDEAD);
        CHECK("robust-consistent", pthread_mutex_consistent(&robust) == 0);
        pthread_mutex_unlock(&robust);
        CHECK("robust-relock", pthread_mutex_lock(&robust) == 0);
        pthread_mutex_unlock(&robust);
    }

    pthread_mutexattr_t pa;
    pthread_mutexattr_init(&pa);
    pthread_mutexattr_setprotocol(&pa, PTHREAD_PRIO_INHERIT);
    pthread_mutex_t pi;
    pthread_mutex_init(&pi, &pa);
    contend("pi-mutex", &pi);
}

/* ------------------------------------------------------ cancellation */

static int cancel_pipe[2];
static pthread_mutex_t cm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cc = PTHREAD_COND_INITIALIZER;
static volatile int blocked_in;

static void *read_forever(void *arg) {
    (void)arg;
    char c;
    blocked_in = 1;
    read(cancel_pipe[0], &c, 1);
    return 0;
}

static void *wait_forever(void *arg) {
    (void)arg;
    pthread_mutex_lock(&cm);
    blocked_in = 2;
    for (;;) pthread_cond_wait(&cc, &cm);
    return 0;
}

static void unlock_cm(void *arg) {
    (void)arg;
    pthread_mutex_unlock(&cm);
}

static void *wait_forever_cleanup(void *arg) {
    void *r;
    pthread_cleanup_push(unlock_cm, 0);
    r = wait_forever(arg);
    pthread_cleanup_pop(0);
    return r;
}

static void *sleep_forever(void *arg) {
    (void)arg;
    blocked_in = 3;
    for (;;) sleep(100);
    return 0;
}

static void cancellation(void) {
    pipe(cancel_pipe);
    void *(*fns[3])(void *) = {read_forever, wait_forever_cleanup, sleep_forever};
    const char *names[3] = {"cancel-read", "cancel-cond-wait", "cancel-sleep"};
    for (int i = 0; i < 3; i++) {
        pthread_t t;
        blocked_in = 0;
        pthread_create(&t, 0, fns[i], 0);
        while (blocked_in != i + 1) sched_yield();
        /* Let it reach the blocking call; cancellation of a thread about
         * to block acts at the call either way. */
        for (int k = 0; k < 50; k++) sched_yield();
        pthread_cancel(t);
        void *r;
        pthread_join(t, &r);
        CHECK(names[i], r == PTHREAD_CANCELED);
    }
    CHECK("cond-mutex-released", pthread_mutex_trylock(&cm) == 0);
    pthread_mutex_unlock(&cm);
}

/* ----------------------------------------------------- /proc threads */

static pthread_barrier_t hold;

static void *park(void *arg) {
    (void)arg;
    pthread_barrier_wait(&hold);
    pthread_barrier_wait(&hold);
    return 0;
}

static int count_tasks(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)))
        if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

static int status_threads(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int n = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "Threads: %d", &n) == 1) break;
    fclose(f);
    return n;
}

static void proc_threads(void) {
    pthread_barrier_init(&hold, 0, 4);
    pthread_t t[3];
    for (int i = 0; i < 3; i++) pthread_create(&t[i], 0, park, 0);
    pthread_barrier_wait(&hold);
    CHECK("proc-task-entries", count_tasks() == 4);
    CHECK("proc-status-threads", status_threads() == 4);
    CHECK("setname-other", pthread_setname_np(t[1], "worker-one") == 0);
    char name[16] = {0};
    CHECK("getname-other", pthread_getname_np(t[1], name, sizeof name) == 0 &&
                               strcmp(name, "worker-one") == 0);
    prctl(PR_SET_NAME, "main-thread");
    char self[16] = {0};
    prctl(PR_GET_NAME, self);
    char other[16] = {0};
    pthread_getname_np(t[0], other, sizeof other);
    CHECK("names-are-per-thread",
          strcmp(self, "main-thread") == 0 && strcmp(other, "threads") == 0);
    pthread_barrier_wait(&hold);
    for (int i = 0; i < 3; i++) pthread_join(t[i], 0);
    /* A joined thread may finish exiting just after the join returns. */
    for (int i = 0; i < 2000 && count_tasks() != 1; i++) usleep(1000);
    CHECK("proc-task-after-join", count_tasks() == 1);
}

/* ------------------------------------------------ clone, directly */

struct clone_args_ {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls,
        set_tid, set_tid_size, cgroup, extra;
};

static long clone3_(struct clone_args_ *a, size_t size) {
    return syscall(SYS_clone3, a, size);
}

static void clone_errors(void) {
    /* Flag combinations copy_process refuses. These return before any
     * thread exists. */
    CHECK_ERR("clone-thread-without-sighand", syscall(SYS_clone, CLONE_THREAD | CLONE_VM, 0, 0, 0, 0),
              EINVAL);
    CHECK_ERR("clone-sighand-without-vm", syscall(SYS_clone, CLONE_SIGHAND, 0, 0, 0, 0), EINVAL);
    struct clone_args_ a = {0};
    CHECK_ERR("clone3-too-small", clone3_(&a, 32), EINVAL);
    CHECK_ERR("clone3-too-large", clone3_(&a, 8192), E2BIG);
    a.extra = 1;
    CHECK_ERR("clone3-nonzero-tail", clone3_(&a, sizeof a), E2BIG);
    a.extra = 0;
    a.flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
    a.exit_signal = SIGCHLD;
    CHECK_ERR("clone3-thread-exit-signal", clone3_(&a, 88), EINVAL);
    a.exit_signal = 0;
    a.stack = 0x10000;
    CHECK_ERR("clone3-stack-without-size", clone3_(&a, 88), EINVAL);
    a.stack = 0;
    a.flags = 1ull << 40;
    CHECK_ERR("clone3-unknown-flag", clone3_(&a, 88), EINVAL);
    a.flags = CLONE_DETACHED;
    CHECK_ERR("clone3-detached", clone3_(&a, 88), EINVAL);
    a.flags = 0;
    a.exit_signal = 65;
    CHECK_ERR("clone3-bad-exit-signal", clone3_(&a, 88), EINVAL);
}

/* ------------------------------------------------- futex, directly */

static volatile uint32_t fa, fb, fx[2] __attribute__((aligned(8)));
/* Waiters that returned: a probe loop stops when one returns early (for
 * example on a kernel without the call) instead of waiting forever. */
static volatile int returned;

static void *futex_waiter(void *arg) {
    (void)arg;
    long r = futex(&fa, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    __atomic_add_fetch(&returned, 1, __ATOMIC_SEQ_CST);
    return (void *)r;
}

static void *waitv_waiter(void *arg) {
    (void)arg;
    struct {
        uint64_t val, uaddr;
        uint32_t flags, reserved;
    } v[2] = {{0, (uintptr_t)&fx[0], FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0},
              {0, (uintptr_t)&fx[1], FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0}};
    long r = syscall(SYS_futex_waitv, v, 2, 0, 0, 0);
    __atomic_add_fetch(&returned, 1, __ATOMIC_SEQ_CST);
    return (void *)r;
}

static void futexes(void) {
    uint32_t w = 1;
    struct timespec ms10 = {0, 10000000};
    CHECK_ERR("futex-wait-mismatch", futex(&w, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0), EAGAIN);
    CHECK_ERR("futex-wait-timeout", futex(&w, FUTEX_WAIT_PRIVATE, 1, &ms10, 0, 0), ETIMEDOUT);
    CHECK("futex-wake-none", futex(&w, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) == 0);
    CHECK_ERR("futex-misaligned", futex((uint32_t *)((char *)&w + 1), FUTEX_WAIT, 1, 0, 0, 0),
              EINVAL);
    CHECK_ERR("futex-wait-realtime", futex(&w, FUTEX_WAIT | FUTEX_CLOCK_REALTIME, 1, &ms10, 0, 0),
              ENOSYS);
    CHECK_ERR("futex-bitset-zero", futex(&w, FUTEX_WAIT_BITSET, 1, 0, 0, 0), EINVAL);
    CHECK_ERR("futex-unknown-op", futex(&w, 99, 1, 0, 0, 0), ENOSYS);
    /* Below mmap_min_addr nothing is mapped: a private key needs only a
     * user address, a shared one the page. */
    CHECK("futex-wake-unmapped-private",
          futex((uint32_t *)0x1000, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) == 0);
    CHECK_ERR("futex-wake-unmapped-shared", futex((uint32_t *)0x1000, FUTEX_WAKE, 1, 0, 0, 0),
              EFAULT);
    uint32_t w2 = 5;
    long n = futex(&w, FUTEX_WAKE_OP_PRIVATE, 1, (void *)1, &w2,
                   FUTEX_OP(FUTEX_OP_SET, 7, FUTEX_OP_CMP_EQ, 5));
    CHECK("futex-wake-op", n == 0 && w2 == 7);
    CHECK_ERR("futex-cmp-requeue-mismatch",
              futex(&w, FUTEX_CMP_REQUEUE_PRIVATE, 1, (void *)1, &w2, 0), EAGAIN);

    /* Three waiters: count them by requeueing to fb and back until all
     * three sleep, then wake one and requeue one. */
    pthread_t t[3];
    returned = 0;
    for (int i = 0; i < 3; i++) pthread_create(&t[i], 0, futex_waiter, 0);
    while (!returned) {
        long moved = futex(&fa, FUTEX_CMP_REQUEUE_PRIVATE, 0, (void *)INT_MAX, &fb, 0);
        futex(&fb, FUTEX_CMP_REQUEUE_PRIVATE, 0, (void *)INT_MAX, &fa, 0);
        if (moved == 3) break;
        sched_yield();
    }
    n = futex(&fa, FUTEX_CMP_REQUEUE_PRIVATE, 1, (void *)1, &fb, 0);
    long on_b = futex(&fb, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0);
    long on_a = futex(&fa, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0);
    int woken = 1;
    for (int i = 0; i < 3; i++) {
        void *r;
        pthread_join(t[i], &r);
        woken &= r == 0;
    }
    CHECK("futex-requeue-counts", n == 2 && on_b == 1 && on_a == 1 && woken);

    /* futex_waitv: woken through its second futex. */
    pthread_t v;
    returned = 0;
    pthread_create(&v, 0, waitv_waiter, 0);
    while (!returned && futex(&fx[1], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) != 1) sched_yield();
    void *idx;
    pthread_join(v, &idx);
    CHECK("futex-waitv-index", (long)idx == 1);
    struct {
        uint64_t val, uaddr;
        uint32_t flags, reserved;
    } one = {1, (uintptr_t)&fx[0], FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0};
    CHECK_ERR("futex-waitv-mismatch", syscall(SYS_futex_waitv, &one, 1, 0, 0, 0), EAGAIN);
    one.val = 0;
    struct timespec at = after_ms(CLOCK_MONOTONIC, 20);
    CHECK_ERR("futex-waitv-timeout", syscall(SYS_futex_waitv, &one, 1, 0, &at, CLOCK_MONOTONIC),
              ETIMEDOUT);

    /* PI futexes: ownership words. */
    uint32_t pi = 0;
    long me = gettid_();
    CHECK("futex-lock-pi", futex(&pi, FUTEX_LOCK_PI_PRIVATE, 0, 0, 0, 0) == 0 && pi == me);
    CHECK_ERR("futex-lock-pi-deadlock", futex(&pi, FUTEX_LOCK_PI_PRIVATE, 0, 0, 0, 0), EDEADLK);
    CHECK("futex-unlock-pi", futex(&pi, FUTEX_UNLOCK_PI_PRIVATE, 0, 0, 0, 0) == 0 && pi == 0);
    CHECK_ERR("futex-unlock-pi-not-owner", futex(&pi, FUTEX_UNLOCK_PI_PRIVATE, 0, 0, 0, 0), EPERM);
    pi = 0x3ffffffe;
    CHECK_ERR("futex-lock-pi-no-owner", futex(&pi, FUTEX_LOCK_PI_PRIVATE, 0, 0, 0, 0), ESRCH);
    CHECK("futex-lock-pi-waiters-bit", pi == (0x3ffffffe | FUTEX_WAITERS));
}

/* -------------------------------------------------------- yielding */

static volatile int turn;

static void *pong(void *arg) {
    (void)arg;
    for (int i = 0; i < 500; i++) {
        while (__atomic_load_n(&turn, __ATOMIC_ACQUIRE) != 1) sched_yield();
        __atomic_store_n(&turn, 0, __ATOMIC_RELEASE);
    }
    return 0;
}

static void yielding(void) {
    pthread_t t;
    pthread_create(&t, 0, pong, 0);
    for (int i = 0; i < 500; i++) {
        while (__atomic_load_n(&turn, __ATOMIC_ACQUIRE) != 0) sched_yield();
        __atomic_store_n(&turn, 1, __ATOMIC_RELEASE);
    }
    pthread_join(t, 0);
    CHECK("sched-yield-ping-pong", turn == 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    basics();
    contend("mutex-counter", &lock);
    condvar();
    barrier_rwlock();
    thread_local();
    timed();
    signals();
    robust_pi();
    cancellation();
    proc_threads();
    clone_errors();
    futexes();
    yielding();
    FINISH();
}
