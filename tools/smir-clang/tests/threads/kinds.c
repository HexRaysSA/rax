// What each kind of mutex says to a thread that holds it already, a timed
// wait that nobody signals, once, a detached thread, a thread that exits
// from inside a call, and a read-write lock.
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *name(int status) {
  switch (status) {
  case 0: return "ok";
  case EBUSY: return "EBUSY";
  case EDEADLK: return "EDEADLK";
  case EPERM: return "EPERM";
  case ETIMEDOUT: return "ETIMEDOUT";
  case EINVAL: return "EINVAL";
  default: return "other";
  }
}

static pthread_once_t once = PTHREAD_ONCE_INIT;
static atomic_int initialized, finished;
static void initialize(void) { atomic_fetch_add(&initialized, 1); }

static void *use_once(void *argument) {
  pthread_once(&once, initialize);
  return argument;
}

static void leave(void *value) { pthread_exit(value); }

static void *exits(void *argument) {
  leave(argument);
  return NULL;
}

static void *detached(void *argument) {
  (void)argument;
  atomic_store(&finished, 1);
  return NULL;
}

static void *foreign_unlock(void *argument) { return (void *)(long)pthread_mutex_unlock(argument); }

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static long pair[2];
static atomic_int torn;

static void *reader(void *argument) {
  (void)argument;
  for (int round = 0; round < 2000; ++round) {
    pthread_rwlock_rdlock(&rwlock);
    if (pair[0] != -pair[1])
      atomic_fetch_add(&torn, 1);
    pthread_rwlock_unlock(&rwlock);
  }
  return NULL;
}

static void *writer(void *argument) {
  (void)argument;
  for (int round = 0; round < 500; ++round) {
    pthread_rwlock_wrlock(&rwlock);
    pair[0] += 3;
    pair[1] -= 3;
    pthread_rwlock_unlock(&rwlock);
  }
  return NULL;
}

int main(void) {
  pthread_mutexattr_t attributes;
  pthread_mutex_t mutex;

  pthread_mutex_init(&mutex, NULL);
  printf("normal: lock %s", name(pthread_mutex_lock(&mutex)));
  printf(", trylock %s", name(pthread_mutex_trylock(&mutex)));
  printf(", unlock %s\n", name(pthread_mutex_unlock(&mutex)));

  pthread_mutexattr_init(&attributes);
  pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&mutex, &attributes);
  printf("recursive: lock %s", name(pthread_mutex_lock(&mutex)));
  printf(", lock %s", name(pthread_mutex_lock(&mutex)));
  printf(", unlock %s", name(pthread_mutex_unlock(&mutex)));
  pthread_t thread;
  void *result;
  pthread_create(&thread, NULL, foreign_unlock, &mutex);
  pthread_join(thread, &result);
  printf(", unlock elsewhere %s", name((int)(long)result));
  printf(", unlock %s", name(pthread_mutex_unlock(&mutex)));
  printf(", unlock %s\n", name(pthread_mutex_unlock(&mutex)));

  pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_ERRORCHECK);
  pthread_mutex_init(&mutex, &attributes);
  printf("errorcheck: lock %s", name(pthread_mutex_lock(&mutex)));
  printf(", lock %s", name(pthread_mutex_lock(&mutex)));
  printf(", unlock %s", name(pthread_mutex_unlock(&mutex)));
  printf(", unlock %s\n", name(pthread_mutex_unlock(&mutex)));
  pthread_mutexattr_destroy(&attributes);

  // Nobody signals: the wait ends when its time has passed.
  pthread_mutex_t plain = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
  struct timespec deadline;
  timespec_get(&deadline, TIME_UTC);
  deadline.tv_nsec += 20000000;
  if (deadline.tv_nsec >= 1000000000) {
    deadline.tv_nsec -= 1000000000;
    ++deadline.tv_sec;
  }
  pthread_mutex_lock(&plain);
  int waited;
  do
    waited = pthread_cond_timedwait(&condition, &plain, &deadline);
  while (waited == 0);
  pthread_mutex_unlock(&plain);
  printf("timed wait: %s\n", name(waited));

  pthread_t threads[6];
  for (long index = 0; index < 6; ++index)
    pthread_create(&threads[index], NULL, use_once, (void *)index);
  long sum = 0;
  for (int index = 0; index < 6; ++index) {
    pthread_join(threads[index], &result);
    sum += (long)result;
  }
  printf("once: ran %d, results %ld\n", atomic_load(&initialized), sum);

  char text[] = "left from inside";
  pthread_create(&thread, NULL, exits, text);
  pthread_join(thread, &result);
  printf("exit: %s, same %d\n", (char *)result, result == (void *)text);

  pthread_attr_t detach;
  pthread_attr_init(&detach);
  pthread_attr_setdetachstate(&detach, PTHREAD_CREATE_DETACHED);
  pthread_create(&thread, &detach, detached, NULL);
  pthread_attr_destroy(&detach);
  while (!atomic_load(&finished))
    ;
  printf("detached: finished\n");
  printf("self: %d %d\n", pthread_equal(pthread_self(), pthread_self()), pthread_equal(pthread_self(), threads[0]));

  pthread_t readers[4], writers[2];
  for (int index = 0; index < 4; ++index)
    pthread_create(&readers[index], NULL, reader, NULL);
  for (int index = 0; index < 2; ++index)
    pthread_create(&writers[index], NULL, writer, NULL);
  for (int index = 0; index < 4; ++index)
    pthread_join(readers[index], NULL);
  for (int index = 0; index < 2; ++index)
    pthread_join(writers[index], NULL);
  printf("rwlock: pair %ld %ld, torn %d\n", pair[0], pair[1], atomic_load(&torn));
  return 0;
}
