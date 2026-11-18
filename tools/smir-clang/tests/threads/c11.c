// The threads of ISO C: threads and their results, a mutex and a condition
// variable handing a value over, a recursive mutex, a timed lock that times
// out, once, thread-specific storage, and sleeping.
#include <stdio.h>
#include <threads.h>
#include <time.h>

static mtx_t mutex;
static cnd_t ready;
static int value;
static once_flag once = ONCE_FLAG_INIT;
static int runs;

static void count_run(void) { ++runs; }

static int square(void *argument) {
  call_once(&once, count_run);
  int number = *(int *)argument;
  return number * number;
}

static int supply(void *argument) {
  mtx_lock(&mutex);
  value = *(int *)argument;
  cnd_signal(&ready);
  mtx_unlock(&mutex);
  return 0;
}

static tss_t slot;
static int released;
static thread_local int own = 3;

static void release(void *value) { released += *(int *)value; }

static int leave(void *argument) {
  // The value is the thread's own; its destructor runs as the thread ends.
  own += 4;
  tss_set(slot, &own);
  (void)argument;
  thrd_exit(41);
}

static int try_timed(void *argument) {
  struct timespec deadline;
  timespec_get(&deadline, TIME_UTC);
  deadline.tv_nsec += 10000000;
  if (deadline.tv_nsec >= 1000000000) {
    deadline.tv_nsec -= 1000000000;
    ++deadline.tv_sec;
  }
  return mtx_timedlock(argument, &deadline);
}

int main(void) {
  thrd_t threads[5];
  int numbers[5], total = 0;
  for (int index = 0; index < 5; ++index) {
    numbers[index] = index + 1;
    if (thrd_create(&threads[index], square, &numbers[index]) != thrd_success)
      return 1;
  }
  for (int index = 0; index < 5; ++index) {
    int result;
    thrd_join(threads[index], &result);
    total += result;
  }
  printf("squares %d, once ran %d\n", total, runs);

  mtx_init(&mutex, mtx_plain);
  cnd_init(&ready);
  int sent = 17;
  thrd_t supplier;
  mtx_lock(&mutex);
  thrd_create(&supplier, supply, &sent);
  while (value == 0)
    cnd_wait(&ready, &mutex);
  mtx_unlock(&mutex);
  thrd_join(supplier, NULL);
  printf("handed over %d\n", value);

  mtx_t recursive;
  mtx_init(&recursive, mtx_plain | mtx_recursive);
  int taken = mtx_lock(&recursive) == thrd_success && mtx_lock(&recursive) == thrd_success;
  mtx_unlock(&recursive);
  mtx_unlock(&recursive);
  printf("recursive %d, trylock %d\n", taken, mtx_trylock(&recursive) == thrd_success);
  mtx_unlock(&recursive);

  // The mutex is held here, so the other thread's timed lock runs out.
  mtx_t timed;
  mtx_init(&timed, mtx_timed);
  mtx_lock(&timed);
  thrd_t waiter;
  int outcome;
  thrd_create(&waiter, try_timed, &timed);
  thrd_join(waiter, &outcome);
  mtx_unlock(&timed);
  printf("timed lock %s\n", outcome == thrd_timedout ? "timed out" : "did not time out");

  thrd_t leaver;
  int left;
  tss_create(&slot, release);
  thrd_create(&leaver, leave, NULL);
  thrd_join(leaver, &left);
  printf("exit %d, current equal %d\n", left, thrd_equal(thrd_current(), thrd_current()));
  printf("specific: released %d, here %s, own %d\n", released, tss_get(slot) ? "set" : "unset", own);
  tss_delete(slot);

  struct timespec before, after, pause = {0, 5000000};
  timespec_get(&before, TIME_UTC);
  thrd_sleep(&pause, NULL);
  timespec_get(&after, TIME_UTC);
  long long elapsed = (after.tv_sec - before.tv_sec) * 1000000000LL + (after.tv_nsec - before.tv_nsec);
  printf("slept %s\n", elapsed >= 5000000 ? "long enough" : "too little");
  thrd_yield();
  cnd_destroy(&ready);
  mtx_destroy(&mutex);
  return 0;
}
