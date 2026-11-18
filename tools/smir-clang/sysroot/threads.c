// <pthread.h>, <threads.h> and <sched.h>, over the runtime's thread and wait
// services.
//
// Everything that blocks does so in `smir_sync_wait32`, on a word of the
// object it waits for, after an atomic operation on that word found that it
// must: nothing here spins, and an uncontended operation calls no service.
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <threads.h>

#include "lock.h"

#define ALL UINT32_MAX
// The state of a read-write lock that a writer holds.
#define WRITER UINT32_MAX

static uint32_t load(const uint32_t *word) { return __atomic_load_n(word, __ATOMIC_SEQ_CST); }

static void wake(const uint32_t *word, uint32_t count) {
  uint64_t woken;
  smir_sync_wake32(word, count, &woken);
}

static uint64_t self(void) {
  uint64_t identity;
  smir_thread_id(&identity);
  return identity;
}

// The time left until `deadline`, a time of the realtime clock, in
// nanoseconds: 0 if it has passed or cannot be told.
static uint64_t until(const struct timespec *deadline) {
  uint64_t now;
  if (deadline->tv_sec < 0 || smir_clock_now(SMIR_CLOCK_UTC, &now) != 0)
    return 0;
  uint64_t seconds = (uint64_t)deadline->tv_sec;
  if (seconds > (SMIR_FOREVER - 1) / 1000000000u - 1)
    return SMIR_FOREVER - 1;
  uint64_t then = seconds * 1000000000u + (uint64_t)deadline->tv_nsec;
  return then > now ? then - now : 0;
}

// Threads. A thread's result travels through the runtime as 64 bits.

struct start {
  void *(*routine)(void *);
  void *argument;
};

static uint64_t run(void *raw) {
  struct start start = *(struct start *)raw;
  free(raw);
  return (uint64_t)(uintptr_t)start.routine(start.argument);
}

struct start_c {
  thrd_start_t routine;
  void *argument;
};

static uint64_t run_c(void *raw) {
  struct start_c start = *(struct start_c *)raw;
  free(raw);
  return (uint64_t)(uint32_t)start.routine(start.argument);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*routine)(void *), void *argument) {
  struct start *start = malloc(sizeof *start);
  if (!start)
    return EAGAIN;
  start->routine = routine;
  start->argument = argument;
  uint64_t handle;
  uint32_t status = smir_thread_spawn(run, start, attributes ? attributes->stack_bytes : 0, &handle);
  if (status != 0) {
    free(start);
    return (int)status;
  }
  if (attributes && attributes->detached)
    smir_thread_detach(handle);
  *thread = handle;
  return 0;
}

int pthread_join(pthread_t thread, void **result) {
  uint64_t value;
  uint32_t status = smir_thread_join(thread, &value);
  if (status == 0 && result)
    *result = (void *)(uintptr_t)value;
  return (int)status;
}

int pthread_detach(pthread_t thread) { return (int)smir_thread_detach(thread); }
pthread_t pthread_self(void) { return self(); }
int pthread_equal(pthread_t left, pthread_t right) { return left == right; }
_Noreturn void pthread_exit(void *result) { smir_thread_exit((uint64_t)(uintptr_t)result); }

int pthread_attr_init(pthread_attr_t *attributes) {
  attributes->stack_bytes = 0;
  attributes->detached = PTHREAD_CREATE_JOINABLE;
  return 0;
}

int pthread_attr_destroy(pthread_attr_t *attributes) {
  (void)attributes;
  return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attributes, int state) {
  if (state != PTHREAD_CREATE_JOINABLE && state != PTHREAD_CREATE_DETACHED)
    return EINVAL;
  attributes->detached = state;
  return 0;
}

int pthread_attr_getdetachstate(const pthread_attr_t *attributes, int *state) {
  *state = attributes->detached;
  return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attributes, size_t bytes) {
  attributes->stack_bytes = bytes;
  return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *attributes, size_t *bytes) {
  *bytes = attributes->stack_bytes;
  return 0;
}

int sched_yield(void) {
  smir_thread_yield();
  return 0;
}

// Mutexes. The recursive and the error-checking kind know their owner.

int pthread_mutexattr_init(pthread_mutexattr_t *attributes) {
  attributes->kind = PTHREAD_MUTEX_DEFAULT;
  return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attributes) {
  (void)attributes;
  return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attributes, int kind) {
  if (kind != PTHREAD_MUTEX_NORMAL && kind != PTHREAD_MUTEX_RECURSIVE && kind != PTHREAD_MUTEX_ERRORCHECK)
    return EINVAL;
  attributes->kind = kind;
  return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *attributes, int *kind) {
  *kind = attributes->kind;
  return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attributes) {
  mutex->word = 0;
  mutex->kind = attributes ? attributes->kind : PTHREAD_MUTEX_DEFAULT;
  mutex->owner = 0;
  mutex->depth = 0;
  return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) { return load(&mutex->word) == 0 ? 0 : EBUSY; }

// Take `mutex`: at once if `timeout_ns` is 0, else waiting that long at
// most. Returns 0, EBUSY or ETIMEDOUT, or what the mutex's kind says about a
// thread that holds it already.
static int acquire(pthread_mutex_t *mutex, uint64_t timeout_ns) {
  uint64_t caller = 0;
  if (mutex->kind != PTHREAD_MUTEX_NORMAL) {
    caller = self();
    if (__atomic_load_n(&mutex->owner, __ATOMIC_SEQ_CST) == caller) {
      // An error-checking mutex is not taken twice: waiting for it would
      // never end, and trying says that it is held.
      if (mutex->kind == PTHREAD_MUTEX_ERRORCHECK)
        return timeout_ns == SMIR_FOREVER ? EDEADLK : EBUSY;
      ++mutex->depth;
      return 0;
    }
  }
  if (timeout_ns == 0) {
    if (!smir_try_lock(&mutex->word))
      return EBUSY;
  } else if (!smir_lock_within(&mutex->word, timeout_ns)) {
    return ETIMEDOUT;
  }
  if (mutex->kind != PTHREAD_MUTEX_NORMAL) {
    __atomic_store_n(&mutex->owner, caller, __ATOMIC_SEQ_CST);
    mutex->depth = 1;
  }
  return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) { return acquire(mutex, SMIR_FOREVER); }
int pthread_mutex_trylock(pthread_mutex_t *mutex) { return acquire(mutex, 0); }

int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *deadline) {
  int status = acquire(mutex, 0);
  if (status != EBUSY)
    return status;
  uint64_t left = until(deadline);
  return left == 0 ? ETIMEDOUT : acquire(mutex, left);
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  if (mutex->kind != PTHREAD_MUTEX_NORMAL) {
    if (__atomic_load_n(&mutex->owner, __ATOMIC_SEQ_CST) != self())
      return EPERM;
    if (--mutex->depth != 0)
      return 0;
    __atomic_store_n(&mutex->owner, 0, __ATOMIC_SEQ_CST);
  }
  smir_unlock(&mutex->word);
  return 0;
}

// Condition variables. A waiter remembers the count of signals it saw while
// it held the mutex and waits only while the count is still that: a signal
// between its unlocking and its waiting changes the count, so it is not lost.

int pthread_condattr_init(pthread_condattr_t *attributes) {
  attributes->unused = 0;
  return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attributes) {
  (void)attributes;
  return 0;
}

int pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attributes) {
  (void)attributes;
  condition->sequence = 0;
  return 0;
}

int pthread_cond_destroy(pthread_cond_t *condition) {
  (void)condition;
  return 0;
}

static int await(pthread_cond_t *condition, pthread_mutex_t *mutex, uint64_t timeout_ns) {
  uint32_t seen = load(&condition->sequence);
  int status = pthread_mutex_unlock(mutex);
  if (status != 0)
    return status;
  uint32_t waited = timeout_ns ? smir_sync_wait32(&condition->sequence, seen, timeout_ns) : ETIMEDOUT;
  pthread_mutex_lock(mutex);
  return waited == ETIMEDOUT ? ETIMEDOUT : 0;
}

int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex) {
  return await(condition, mutex, SMIR_FOREVER);
}

int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex, const struct timespec *deadline) {
  return await(condition, mutex, until(deadline));
}

int pthread_cond_signal(pthread_cond_t *condition) {
  __atomic_fetch_add(&condition->sequence, 1, __ATOMIC_SEQ_CST);
  wake(&condition->sequence, 1);
  return 0;
}

int pthread_cond_broadcast(pthread_cond_t *condition) {
  __atomic_fetch_add(&condition->sequence, 1, __ATOMIC_SEQ_CST);
  wake(&condition->sequence, ALL);
  return 0;
}

// Once: the first caller runs the routine; the others wait until it is done.

int pthread_once(pthread_once_t *once, void (*routine)(void)) {
  if (load(&once->state) == 2)
    return 0;
  uint32_t expected = 0;
  if (__atomic_compare_exchange_n(&once->state, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
    routine();
    __atomic_store_n(&once->state, 2, __ATOMIC_SEQ_CST);
    wake(&once->state, ALL);
    return 0;
  }
  while (load(&once->state) != 2)
    smir_sync_wait32(&once->state, 1, SMIR_FOREVER);
  return 0;
}

// Read-write locks. Readers do not hold writers back for one another's
// sake: a writer waits until no reader is left.

int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attributes) {
  (void)attributes;
  lock->state = 0;
  return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *lock) { return load(&lock->state) == 0 ? 0 : EBUSY; }

int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock) {
  uint32_t state = load(&lock->state);
  while (state < WRITER - 1) {
    if (__atomic_compare_exchange_n(&lock->state, &state, state + 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
      return 0;
  }
  return state == WRITER ? EBUSY : EAGAIN;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *lock) {
  for (;;) {
    int status = pthread_rwlock_tryrdlock(lock);
    if (status != EBUSY)
      return status;
    smir_sync_wait32(&lock->state, WRITER, SMIR_FOREVER);
  }
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *lock) {
  uint32_t expected = 0;
  return __atomic_compare_exchange_n(&lock->state, &expected, WRITER, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
             ? 0
             : EBUSY;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *lock) {
  for (;;) {
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&lock->state, &expected, WRITER, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
      return 0;
    smir_sync_wait32(&lock->state, expected, SMIR_FOREVER);
  }
}

int pthread_rwlock_unlock(pthread_rwlock_t *lock) {
  uint32_t state = load(&lock->state);
  if (state == 0)
    return EPERM;
  // A writer leaves the lock free; a reader leaves it to the other readers.
  uint32_t left = 0;
  if (state == WRITER)
    __atomic_store_n(&lock->state, 0, __ATOMIC_SEQ_CST);
  else
    left = __atomic_sub_fetch(&lock->state, 1, __ATOMIC_SEQ_CST);
  if (left == 0)
    wake(&lock->state, ALL);
  return 0;
}

// ISO C threads.

static int outcome(int status) {
  return status == 0 ? thrd_success
       : status == EBUSY ? thrd_busy
       : status == ETIMEDOUT ? thrd_timedout
       : status == EAGAIN ? thrd_nomem
       : thrd_error;
}

int thrd_create(thrd_t *thread, thrd_start_t routine, void *argument) {
  struct start_c *start = malloc(sizeof *start);
  if (!start)
    return thrd_nomem;
  start->routine = routine;
  start->argument = argument;
  uint32_t status = smir_thread_spawn(run_c, start, 0, thread);
  if (status != 0)
    free(start);
  return outcome((int)status);
}

int thrd_join(thrd_t thread, int *result) {
  uint64_t value;
  uint32_t status = smir_thread_join(thread, &value);
  if (status == 0 && result)
    *result = (int)(uint32_t)value;
  return outcome((int)status);
}

int thrd_detach(thrd_t thread) { return outcome((int)smir_thread_detach(thread)); }
thrd_t thrd_current(void) { return self(); }
int thrd_equal(thrd_t left, thrd_t right) { return left == right; }
_Noreturn void thrd_exit(int result) { smir_thread_exit((uint64_t)(uint32_t)result); }
void thrd_yield(void) { smir_thread_yield(); }

int thrd_sleep(const struct timespec *duration, struct timespec *remaining) {
  (void)remaining;
  if (duration->tv_sec < 0 || duration->tv_nsec < 0 || duration->tv_nsec >= 1000000000)
    return -2;
  // A wait on a word nobody else knows, which only its time ends.
  uint32_t word = 0;
  uint64_t seconds = (uint64_t)duration->tv_sec;
  uint64_t whole = seconds > (SMIR_FOREVER - 1) / 1000000000u - 1 ? SMIR_FOREVER - 1
                                                                 : seconds * 1000000000u + (uint64_t)duration->tv_nsec;
  if (whole != 0)
    smir_sync_wait32(&word, 0, whole);
  return 0;
}

int mtx_init(mtx_t *mutex, int kind) {
  pthread_mutexattr_t attributes = {kind & mtx_recursive ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_NORMAL};
  return outcome(pthread_mutex_init(mutex, &attributes));
}

void mtx_destroy(mtx_t *mutex) { (void)mutex; }
int mtx_lock(mtx_t *mutex) { return outcome(pthread_mutex_lock(mutex)); }
int mtx_trylock(mtx_t *mutex) { return outcome(pthread_mutex_trylock(mutex)); }
int mtx_timedlock(mtx_t *__restrict mutex, const struct timespec *__restrict deadline) {
  return outcome(pthread_mutex_timedlock(mutex, deadline));
}
int mtx_unlock(mtx_t *mutex) { return outcome(pthread_mutex_unlock(mutex)); }

int cnd_init(cnd_t *condition) { return outcome(pthread_cond_init(condition, 0)); }
void cnd_destroy(cnd_t *condition) { (void)condition; }
int cnd_wait(cnd_t *condition, mtx_t *mutex) { return outcome(pthread_cond_wait(condition, mutex)); }
int cnd_timedwait(cnd_t *__restrict condition, mtx_t *__restrict mutex,
                  const struct timespec *__restrict deadline) {
  return outcome(pthread_cond_timedwait(condition, mutex, deadline));
}
int cnd_signal(cnd_t *condition) { return outcome(pthread_cond_signal(condition)); }
int cnd_broadcast(cnd_t *condition) { return outcome(pthread_cond_broadcast(condition)); }

void call_once(once_flag *flag, void (*routine)(void)) { pthread_once(flag, routine); }
