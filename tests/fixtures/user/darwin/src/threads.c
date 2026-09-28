// POSIX threads: creation with attributes, joining and return values,
// detached threads, mutexes (normal, recursive, error-checking, try-lock),
// condition variables (signal, broadcast, timed waits), read-write locks,
// once, thread-specific data, thread identity and the main thread's QoS,
// signal masks and pthread_kill between threads, cancellation, and a
// lock-contended counter.
// Everything printed is independent of scheduling order.
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define N 4

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t key;
static long counter;
static int ready, go, once_runs, dtor_runs, readers_seen;
static volatile sig_atomic_t usr1_thread_ok;
static pthread_t usr1_target;

static void once_fn(void) { once_runs++; }

static void dtor(void *v) {
    pthread_mutex_lock(&lock);
    dtor_runs += (int)(intptr_t)v;
    pthread_mutex_unlock(&lock);
}

static void *adder(void *arg) {
    long n = (long)arg;
    pthread_once(&once, once_fn);
    pthread_setspecific(key, (void *)(intptr_t)1);
    for (long i = 0; i < n; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return (void *)(n * 2);
}

static void *waiter(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);
    ready++;
    pthread_cond_broadcast(&cond);
    while (!go) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    pthread_rwlock_rdlock(&rw);
    pthread_mutex_lock(&lock);
    readers_seen++;
    pthread_mutex_unlock(&lock);
    pthread_rwlock_unlock(&rw);
    return NULL;
}

static void on_usr1(int sig) {
    (void)sig;
    usr1_thread_ok = pthread_equal(pthread_self(), usr1_target);
}

static void *sleeper(void *arg) {
    (void)arg;
    // Inherits the creator's mask (SIGUSR2 blocked).
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    intptr_t usr2 = sigismember(&cur, SIGUSR2);
    pthread_mutex_lock(&lock);
    ready++;
    pthread_cond_broadcast(&cond);
    while (!go) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    return (void *)usr2;
}

static void *cancelled(void *arg) {
    (void)arg;
    for (;;) {
        pause();
    }
    return NULL;
}

static void *detached(void *arg) {
    pthread_mutex_lock(&lock);
    ready++;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    return arg;
}

int main(void) {
    pthread_t t[N];
    void *ret;

    pthread_key_create(&key, dtor);
    printf("main is main: %d\n", pthread_main_np());
    // The main thread runs at the QoS the process was started with.
    printf("main thread qos: %#x %#x\n", qos_class_self(), qos_class_main());
    printf("self equal: %d\n", pthread_equal(pthread_self(), pthread_self()));

    // Workers contend for one mutex.
    for (long i = 0; i < N; i++) {
        pthread_create(&t[i], NULL, adder, (void *)(1000 * (i + 1)));
    }
    long sum = 0;
    for (int i = 0; i < N; i++) {
        pthread_join(t[i], &ret);
        sum += (long)ret;
    }
    printf("counter=%ld sum=%ld once=%d dtor=%d\n", counter, sum, once_runs, dtor_runs);

    // Condition variables: every waiter wakes on a broadcast.
    ready = go = 0;
    for (int i = 0; i < N; i++) {
        pthread_create(&t[i], NULL, waiter, NULL);
    }
    pthread_mutex_lock(&lock);
    while (ready < N) {
        pthread_cond_wait(&cond, &lock);
    }
    go = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < N; i++) {
        pthread_join(t[i], NULL);
    }
    printf("cond: ready=%d\n", ready);

    // A timed wait that times out.
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 20 * 1000 * 1000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }
    pthread_mutex_lock(&lock);
    int r = pthread_cond_timedwait(&cond, &lock, &ts);
    pthread_mutex_unlock(&lock);
    printf("timedwait: %s\n", r == ETIMEDOUT ? "ETIMEDOUT" : strerror(r));

    // Mutex types.
    pthread_mutexattr_t ma;
    pthread_mutex_t m;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&m, &ma);
    printf("recursive: %d %d %d %d\n", pthread_mutex_lock(&m), pthread_mutex_lock(&m),
           pthread_mutex_unlock(&m), pthread_mutex_unlock(&m));
    pthread_mutex_destroy(&m);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&m, &ma);
    printf("errorcheck: %d %s %d %s\n", pthread_mutex_lock(&m),
           pthread_mutex_lock(&m) == EDEADLK ? "EDEADLK" : "?", pthread_mutex_unlock(&m),
           pthread_mutex_unlock(&m) == EPERM ? "EPERM" : "?");
    pthread_mutex_destroy(&m);
    pthread_mutex_lock(&lock);
    printf("trylock busy: %s\n", pthread_mutex_trylock(&lock) == EBUSY ? "EBUSY" : "?");
    pthread_mutex_unlock(&lock);

    // Read-write locks: readers proceed together once the writer leaves.
    pthread_rwlock_wrlock(&rw);
    for (int i = 0; i < N; i++) {
        pthread_create(&t[i], NULL, reader, NULL);
    }
    usleep(10000);
    pthread_mutex_lock(&lock);
    int seen_while_writing = readers_seen;
    pthread_mutex_unlock(&lock);
    pthread_rwlock_unlock(&rw);
    for (int i = 0; i < N; i++) {
        pthread_join(t[i], NULL);
    }
    printf("rwlock: while_writing=%d after=%d\n", seen_while_writing, readers_seen);

    // Signal masks are inherited; pthread_kill targets one thread.
    signal(SIGUSR1, on_usr1);
    sigset_t s, old;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &s, &old);
    ready = go = 0;
    pthread_create(&usr1_target, NULL, sleeper, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    pthread_mutex_lock(&lock);
    while (ready < 1) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    pthread_kill(usr1_target, SIGUSR1);
    usleep(10000);
    pthread_mutex_lock(&lock);
    go = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    pthread_join(usr1_target, &ret);
    printf("sigmask inherited=%ld usr1 on target=%d\n", (long)ret, usr1_thread_ok);

    // Cancellation of a thread blocked in pause().
    pthread_t c;
    pthread_create(&c, NULL, cancelled, NULL);
    usleep(10000);
    pthread_cancel(c);
    pthread_join(c, &ret);
    printf("cancel: %s\n", ret == PTHREAD_CANCELED ? "PTHREAD_CANCELED" : "?");

    // A detached thread.
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&a, 1 << 20);
    ready = 0;
    pthread_create(&c, &a, detached, NULL);
    pthread_mutex_lock(&lock);
    while (ready < 1) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    printf("detached: ran=%d\n", ready);

    // Thread count from the kernel.
    thread_act_array_t acts;
    mach_msg_type_number_t n;
    task_threads(mach_task_self(), &acts, &n);
    printf("threads at end: %s\n", n >= 1 ? "some" : "none");
    return 0;
}
