// psynch under contention: first-fit and fair-share mutexes, a bounded
// producer/consumer queue on two condition variables, broadcast rounds, a
// directed signal (pthread_cond_signal_thread_np), and a read-write lock
// shared by readers and writers. Only totals are printed.
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define THREADS 6
#define ITERS 3000

static pthread_mutex_t first_fit, fair_share;
static long ff_count, fs_count;

static void *count(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&first_fit);
        ff_count++;
        pthread_mutex_unlock(&first_fit);
        pthread_mutex_lock(&fair_share);
        fs_count++;
        if (i % 97 == 0) {
            sched_yield();
        }
        pthread_mutex_unlock(&fair_share);
    }
    return NULL;
}

// A bounded queue.
#define CAP 4
#define ITEMS 2000
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t not_full = PTHREAD_COND_INITIALIZER;
static pthread_cond_t not_empty = PTHREAD_COND_INITIALIZER;
static int queue[CAP], head, tail, size;
static long consumed_sum, consumed_n;

static void *producer(void *arg) {
    long base = (long)arg;
    for (int i = 1; i <= ITEMS; i++) {
        pthread_mutex_lock(&qlock);
        while (size == CAP) {
            pthread_cond_wait(&not_full, &qlock);
        }
        queue[tail] = (int)(base + i);
        tail = (tail + 1) % CAP;
        size++;
        pthread_cond_signal(&not_empty);
        pthread_mutex_unlock(&qlock);
    }
    return NULL;
}

static void *consumer(void *arg) {
    long want = (long)arg;
    for (long i = 0; i < want; i++) {
        pthread_mutex_lock(&qlock);
        while (size == 0) {
            pthread_cond_wait(&not_empty, &qlock);
        }
        consumed_sum += queue[head];
        consumed_n++;
        head = (head + 1) % CAP;
        size--;
        pthread_cond_signal(&not_full);
        pthread_mutex_unlock(&qlock);
    }
    return NULL;
}

// Broadcast rounds: every worker waits for each round.
#define ROUNDS 200
static pthread_mutex_t rlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t rdone = PTHREAD_COND_INITIALIZER;
static int round_no, arrived;
static long round_work;

static void *rounder(void *arg) {
    (void)arg;
    for (int r = 1; r <= ROUNDS; r++) {
        pthread_mutex_lock(&rlock);
        while (round_no < r) {
            pthread_cond_wait(&rcond, &rlock);
        }
        round_work += r;
        arrived++;
        pthread_cond_signal(&rdone);
        pthread_mutex_unlock(&rlock);
    }
    return NULL;
}

// A directed signal.
static pthread_mutex_t dlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dcond = PTHREAD_COND_INITIALIZER;
static int waiting, chosen_woke, others_woke, release_all;
static pthread_t chosen;

static void *directed(void *arg) {
    (void)arg;
    pthread_mutex_lock(&dlock);
    waiting++;
    int me_chosen;
    for (;;) {
        pthread_cond_wait(&dcond, &dlock);
        me_chosen = pthread_equal(pthread_self(), chosen);
        if (me_chosen || release_all) {
            break;
        }
    }
    if (me_chosen) {
        chosen_woke++;
    } else {
        others_woke++;
    }
    pthread_mutex_unlock(&dlock);
    return NULL;
}

// Readers and writers.
static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
static long shared_a, shared_b, torn;

static void *rw_reader(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        pthread_rwlock_rdlock(&rw);
        if (shared_a != shared_b) {
            torn++;
        }
        pthread_rwlock_unlock(&rw);
    }
    return NULL;
}

static void *rw_writer(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS / 3; i++) {
        pthread_rwlock_wrlock(&rw);
        shared_a++;
        if (i % 7 == 0) {
            sched_yield();
        }
        shared_b++;
        pthread_rwlock_unlock(&rw);
    }
    return NULL;
}

int main(void) {
    pthread_t t[THREADS];
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_setpolicy_np(&ma, PTHREAD_MUTEX_POLICY_FIRSTFIT_NP);
    pthread_mutex_init(&first_fit, &ma);
    pthread_mutexattr_setpolicy_np(&ma, PTHREAD_MUTEX_POLICY_FAIRSHARE_NP);
    pthread_mutex_init(&fair_share, &ma);
    for (int i = 0; i < THREADS; i++) {
        pthread_create(&t[i], NULL, count, NULL);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
    }
    printf("mutexes: first_fit=%ld fair_share=%ld\n", ff_count, fs_count);

    // Two producers, three consumers.
    pthread_t p[2], c[3];
    pthread_create(&p[0], NULL, producer, (void *)0L);
    pthread_create(&p[1], NULL, producer, (void *)100000L);
    long shares[3] = {1500, 1500, 1000};
    for (int i = 0; i < 3; i++) {
        pthread_create(&c[i], NULL, consumer, (void *)shares[i]);
    }
    for (int i = 0; i < 2; i++) {
        pthread_join(p[i], NULL);
    }
    for (int i = 0; i < 3; i++) {
        pthread_join(c[i], NULL);
    }
    long expect = 0;
    for (int i = 1; i <= ITEMS; i++) {
        expect += i + (100000 + i);
    }
    printf("queue: consumed=%ld sum_ok=%d left=%d\n", consumed_n, consumed_sum == expect, size);

    // Broadcast rounds.
    for (int i = 0; i < THREADS; i++) {
        pthread_create(&t[i], NULL, rounder, NULL);
    }
    for (int r = 1; r <= ROUNDS; r++) {
        pthread_mutex_lock(&rlock);
        arrived = 0;
        round_no = r;
        pthread_cond_broadcast(&rcond);
        while (arrived < THREADS) {
            pthread_cond_wait(&rdone, &rlock);
        }
        pthread_mutex_unlock(&rlock);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
    }
    printf("rounds: work=%ld\n", round_work);

    // Wake one chosen waiter, then the rest.
    pthread_t d[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&d[i], NULL, directed, NULL);
    }
    pthread_mutex_lock(&dlock);
    while (waiting < 4) {
        pthread_mutex_unlock(&dlock);
        usleep(1000);
        pthread_mutex_lock(&dlock);
    }
    chosen = d[2];
    pthread_mutex_unlock(&dlock);
    int r = pthread_cond_signal_thread_np(&dcond, d[2]);
    pthread_join(d[2], NULL);
    pthread_mutex_lock(&dlock);
    printf("directed: r=%d chosen=%d others=%d\n", r, chosen_woke, others_woke);
    release_all = 1;
    pthread_cond_broadcast(&dcond);
    pthread_mutex_unlock(&dlock);
    for (int i = 0; i < 4; i++) {
        if (i != 2) {
            pthread_join(d[i], NULL);
        }
    }
    printf("directed: others after broadcast=%d\n", others_woke);

    // Readers never see a half-done write.
    pthread_t rws[5];
    for (int i = 0; i < 3; i++) {
        pthread_create(&rws[i], NULL, rw_reader, NULL);
    }
    for (int i = 3; i < 5; i++) {
        pthread_create(&rws[i], NULL, rw_writer, NULL);
    }
    for (int i = 0; i < 5; i++) {
        pthread_join(rws[i], NULL);
    }
    printf("rwlock: a=%ld b=%ld torn=%ld\n", shared_a, shared_b, torn);
    printf("destroy: %d %d %d\n", pthread_mutex_destroy(&fair_share),
           pthread_cond_destroy(&not_empty), pthread_rwlock_destroy(&rw));
    return 0;
}
