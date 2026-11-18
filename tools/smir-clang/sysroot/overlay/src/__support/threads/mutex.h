// The mutex of LLVM libc, for this target: a lock over the runtime's wait
// and wake. LLVM libc has one for Linux and for macOS and, for a program of
// one thread, one that does nothing; the library here is used by threads.
#ifndef LLVM_LIBC_SRC___SUPPORT_THREADS_MUTEX_H
#define LLVM_LIBC_SRC___SUPPORT_THREADS_MUTEX_H

#include "src/__support/macros/attributes.h"
#include "src/__support/macros/config.h"
#include "src/__support/threads/mutex_common.h"

#include "../../../../lock.h"

namespace LIBC_NAMESPACE_DECL {

// Not recursive, whatever is asked for: nothing in the library asks.
struct Mutex {
  uint32_t word = 0;

  LIBC_INLINE constexpr Mutex(bool, bool, bool, bool, bool = false) {}

  LIBC_INLINE MutexError lock() {
    smir_lock(&word);
    return MutexError::NONE;
  }
  LIBC_INLINE MutexError unlock() {
    smir_unlock(&word);
    return MutexError::NONE;
  }
  LIBC_INLINE MutexError reset() {
    word = 0;
    return MutexError::NONE;
  }
  LIBC_INLINE MutexError try_lock() { return smir_try_lock(&word) ? MutexError::NONE : MutexError::BUSY; }
  LIBC_INLINE bool is_robust() const { return false; }
};

} // namespace LIBC_NAMESPACE_DECL

#endif // LLVM_LIBC_SRC___SUPPORT_THREADS_MUTEX_H
