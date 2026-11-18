// Threads add to shared counters: one under a mutex, one with an atomic
// operation, one through a pointer each thread returns.
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

enum { THREADS = 8, ROUNDS = 5000 };

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static long guarded;
static atomic_long lockless;

struct tally {
  int thread;
  long sum;
};

static void *work(void *argument) {
  int thread = *(int *)argument;
  struct tally *tally = malloc(sizeof *tally);
  tally->thread = thread;
  tally->sum = 0;
  for (int round = 0; round < ROUNDS; ++round) {
    pthread_mutex_lock(&mutex);
    guarded += thread + 1;
    pthread_mutex_unlock(&mutex);
    atomic_fetch_add(&lockless, 1);
    tally->sum += round ^ thread;
  }
  return tally;
}

int main(void) {
  pthread_t threads[THREADS];
  int numbers[THREADS];
  for (int index = 0; index < THREADS; ++index) {
    numbers[index] = index;
    if (pthread_create(&threads[index], NULL, work, &numbers[index]) != 0)
      return 1;
  }
  long sums = 0;
  for (int index = 0; index < THREADS; ++index) {
    void *result;
    if (pthread_join(threads[index], &result) != 0)
      return 2;
    struct tally *tally = result;
    printf("thread %d: %ld\n", tally->thread, tally->sum);
    sums += tally->sum;
    free(tally);
  }
  printf("guarded %ld, lockless %ld, sums %ld\n", guarded, atomic_load(&lockless), sums);
  return guarded == (long)ROUNDS * THREADS * (THREADS + 1) / 2 && lockless == (long)ROUNDS * THREADS ? 0 : 3;
}
