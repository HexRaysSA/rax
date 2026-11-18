// The threads of ISO C, over the same objects as <pthread.h>.
// `thread_local` is the language's keyword.
#ifndef SMIR_THREADS_H
#define SMIR_THREADS_H

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__cplusplus) && __STDC_VERSION__ < 202311L && !defined(thread_local)
#define thread_local _Thread_local
#endif

typedef pthread_t thrd_t;
typedef int (*thrd_start_t)(void *);
typedef pthread_mutex_t mtx_t;
typedef pthread_cond_t cnd_t;
typedef pthread_once_t once_flag;
typedef pthread_key_t tss_t;
typedef void (*tss_dtor_t)(void *);

#define TSS_DTOR_ITERATIONS PTHREAD_DESTRUCTOR_ITERATIONS

#define ONCE_FLAG_INIT PTHREAD_ONCE_INIT

enum { thrd_success = 0, thrd_busy = 1, thrd_error = 2, thrd_nomem = 3, thrd_timedout = 4 };
enum { mtx_plain = 0, mtx_recursive = 1, mtx_timed = 2 };

int thrd_create(thrd_t *thread, thrd_start_t start, void *argument);
int thrd_join(thrd_t thread, int *result);
int thrd_detach(thrd_t thread);
thrd_t thrd_current(void);
int thrd_equal(thrd_t left, thrd_t right);
_Noreturn void thrd_exit(int result);
// Sleeps for `duration`; nothing interrupts it, so `remaining` is not used.
int thrd_sleep(const struct timespec *duration, struct timespec *remaining);
void thrd_yield(void);

int mtx_init(mtx_t *mutex, int kind);
void mtx_destroy(mtx_t *mutex);
int mtx_lock(mtx_t *mutex);
int mtx_trylock(mtx_t *mutex);
// `deadline` is a time of the `TIME_UTC` base of `timespec_get`.
int mtx_timedlock(mtx_t *__restrict mutex, const struct timespec *__restrict deadline);
int mtx_unlock(mtx_t *mutex);

int cnd_init(cnd_t *condition);
void cnd_destroy(cnd_t *condition);
int cnd_wait(cnd_t *condition, mtx_t *mutex);
int cnd_timedwait(cnd_t *__restrict condition, mtx_t *__restrict mutex, const struct timespec *__restrict deadline);
int cnd_signal(cnd_t *condition);
int cnd_broadcast(cnd_t *condition);

void call_once(once_flag *flag, void (*routine)(void));

int tss_create(tss_t *key, tss_dtor_t destructor);
void tss_delete(tss_t key);
void *tss_get(tss_t key);
int tss_set(tss_t key, void *value);

#ifdef __cplusplus
}
#endif

#endif
