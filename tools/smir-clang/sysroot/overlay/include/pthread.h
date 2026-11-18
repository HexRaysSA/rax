// POSIX threads, over the portable runtime's thread and wait services.
//
// What is here: threads (create, join, detach, exit, self), mutexes of the
// three kinds, condition variables, once, read-write locks, and the
// attributes those take. Not here: cancellation, scheduling parameters,
// thread-specific keys, robust and process-shared objects.
//
// A thread that returns from the program's first thread's `main`, or calls
// `exit`, ends the program with all its threads. `pthread_exit` in the first
// thread ends the program too, with status 0, without waiting for the others.
#ifndef SMIR_PTHREAD_H
#define SMIR_PTHREAD_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// A thread's handle. Zero is no thread.
typedef uint64_t pthread_t;

typedef struct {
  uint64_t stack_bytes;
  int detached;
} pthread_attr_t;

typedef struct {
  uint32_t word;  // 0 free, 1 held, 2 held and wanted
  int kind;
  uint64_t owner; // for the kinds that track it
  uint64_t depth;
} pthread_mutex_t;

typedef struct {
  int kind;
} pthread_mutexattr_t;

typedef struct {
  uint32_t sequence; // counts signals and broadcasts
} pthread_cond_t;

typedef struct {
  int unused;
} pthread_condattr_t;

typedef struct {
  uint32_t state; // 0 not run, 1 running, 2 done
} pthread_once_t;

typedef struct {
  uint32_t state; // the number of readers, or all ones for a writer
} pthread_rwlock_t;

typedef struct {
  int unused;
} pthread_rwlockattr_t;

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT PTHREAD_MUTEX_NORMAL

#define PTHREAD_MUTEX_INITIALIZER {0, PTHREAD_MUTEX_NORMAL, 0, 0}
#define PTHREAD_COND_INITIALIZER {0}
#define PTHREAD_ONCE_INIT {0}
#define PTHREAD_RWLOCK_INITIALIZER {0}

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*start)(void *), void *argument);
int pthread_join(pthread_t thread, void **result);
int pthread_detach(pthread_t thread);
pthread_t pthread_self(void);
int pthread_equal(pthread_t left, pthread_t right);
_Noreturn void pthread_exit(void *result);

int pthread_attr_init(pthread_attr_t *attributes);
int pthread_attr_destroy(pthread_attr_t *attributes);
int pthread_attr_setdetachstate(pthread_attr_t *attributes, int state);
int pthread_attr_getdetachstate(const pthread_attr_t *attributes, int *state);
int pthread_attr_setstacksize(pthread_attr_t *attributes, size_t bytes);
int pthread_attr_getstacksize(const pthread_attr_t *attributes, size_t *bytes);

int pthread_mutexattr_init(pthread_mutexattr_t *attributes);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attributes);
int pthread_mutexattr_settype(pthread_mutexattr_t *attributes, int kind);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attributes, int *kind);

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attributes);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
// `deadline` is a time of the realtime clock, as `timespec_get` reads it.
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *deadline);
int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_condattr_init(pthread_condattr_t *attributes);
int pthread_condattr_destroy(pthread_condattr_t *attributes);

int pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attributes);
int pthread_cond_destroy(pthread_cond_t *condition);
// Both may return without a signal; callers test their condition again.
int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex, const struct timespec *deadline);
int pthread_cond_signal(pthread_cond_t *condition);
int pthread_cond_broadcast(pthread_cond_t *condition);

int pthread_once(pthread_once_t *once, void (*routine)(void));

int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attributes);
int pthread_rwlock_destroy(pthread_rwlock_t *lock);
int pthread_rwlock_rdlock(pthread_rwlock_t *lock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock);
int pthread_rwlock_wrlock(pthread_rwlock_t *lock);
int pthread_rwlock_trywrlock(pthread_rwlock_t *lock);
int pthread_rwlock_unlock(pthread_rwlock_t *lock);

#ifdef __cplusplus
}
#endif

#endif
