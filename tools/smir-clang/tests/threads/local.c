// What each thread has of its own: thread-local variables, the error
// number, and its values for thread-specific keys with their destructors.
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

enum { THREADS = 5, ROUNDS = 300 };

static _Thread_local long tally = 1000;
static _Thread_local struct {
  char name[8];
  int uses;
} scratch = {"fresh", 0};

static pthread_key_t key;
static atomic_int destroyed, destroyed_sum;

static void destroy(void *value) {
  atomic_fetch_add(&destroyed, 1);
  atomic_fetch_add(&destroyed_sum, *(int *)value);
  free(value);
}

static void *work(void *argument) {
  long number = (long)argument;
  // The variables start from their initializers in every thread.
  int fresh = tally == 1000 && scratch.name[0] == 'f' && scratch.uses == 0 && errno == 0 &&
              pthread_getspecific(key) == NULL;
  int *mine = malloc(sizeof *mine);
  *mine = (int)number + 1;
  pthread_setspecific(key, mine);
  for (int round = 0; round < ROUNDS; ++round) {
    tally += number;
    scratch.uses++;
    errno = (int)number + 1;
  }
  scratch.name[0] = (char)('A' + number);
  int kept = *(int *)pthread_getspecific(key) == number + 1 && errno == number + 1 && scratch.uses == ROUNDS;
  return (void *)(tally * 4 + fresh * 2 + kept);
}

int main(void) {
  pthread_key_create(&key, destroy);
  pthread_setspecific(key, NULL);
  errno = 77;
  tally = 5;
  pthread_t threads[THREADS];
  for (long index = 0; index < THREADS; ++index)
    pthread_create(&threads[index], NULL, work, (void *)index);
  for (long index = 0; index < THREADS; ++index) {
    void *result;
    pthread_join(threads[index], &result);
    long value = (long)result;
    printf("thread %ld: tally %ld, fresh %ld, kept %ld\n", index, value / 4, value / 2 % 2, value % 2);
  }
  // The first thread's own are as it left them.
  printf("main: tally %ld, errno %d, scratch %s %d\n", tally, errno, scratch.name, scratch.uses);
  printf("destructors: %d, sum %d\n", atomic_load(&destroyed), atomic_load(&destroyed_sum));
  // A deleted key is no key; a new one starts with no values.
  pthread_key_delete(key);
  pthread_key_t again;
  pthread_key_create(&again, NULL);
  printf("new key: %s\n", pthread_getspecific(again) == NULL ? "empty" : "not empty");
  return 0;
}
