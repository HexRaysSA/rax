// A lock for the C library's own use, over the runtime's wait and wake.
//
// The word is 0 when the lock is free, 1 when it is held, and 2 when it is
// held and a thread may be waiting for it. Taking and releasing a lock
// nobody else wants is one atomic operation each and calls no service.
#ifndef SMIR_SYSROOT_LOCK_H
#define SMIR_SYSROOT_LOCK_H

#include <smir/services.h>

static inline int smir_try_lock(uint32_t *word) {
  uint32_t expected = 0;
  return __atomic_compare_exchange_n(word, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

// Take the lock, waiting at most `timeout_ns` at a time for it. Returns
// whether the lock was taken (1 or 0); with SMIR_FOREVER it always is.
static inline int smir_lock_within(uint32_t *word, uint64_t timeout_ns) {
  if (smir_try_lock(word))
    return 1;
  // From here on the word says that someone waits, so that whoever releases
  // the lock wakes a waiter.
  while (__atomic_exchange_n(word, 2, __ATOMIC_ACQUIRE) != 0) {
    if (smir_sync_wait32(word, 2, timeout_ns) == 110 /* ETIMEDOUT */)
      return 0;
  }
  return 1;
}

static inline void smir_lock(uint32_t *word) { smir_lock_within(word, SMIR_FOREVER); }

static inline void smir_unlock(uint32_t *word) {
  if (__atomic_exchange_n(word, 0, __ATOMIC_RELEASE) == 2) {
    uint64_t woken;
    smir_sync_wake32(word, 1, &woken);
  }
}

#endif
