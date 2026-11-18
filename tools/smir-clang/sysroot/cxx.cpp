// What C++ programs need from a runtime besides the C library, where they
// are compiled without exceptions and run-time type information: storage
// for `new`, the guard of a function's static variable, the function a call
// of a pure virtual function reaches, and the name by which a static
// object's destructor is registered.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "lock.h"

namespace std {
enum class align_val_t : size_t {};
struct nothrow_t {
  explicit nothrow_t() = default;
};
extern const nothrow_t nothrow;
const nothrow_t nothrow{};
} // namespace std

// Storage. Without exceptions there is no way to report that there is none
// left, so the program ends. A program linked with the C++ library gets
// that library's functions instead, which throw `bad_alloc`.

static void *allocate(size_t size, size_t alignment) {
  if (size == 0)
    size = 1;
  // `aligned_alloc` wants a size that is a multiple of the alignment.
  void *storage = alignment <= alignof(max_align_t)
                      ? malloc(size)
                      : aligned_alloc(alignment, (size + alignment - 1) / alignment * alignment);
  return storage;
}

static void *allocate_or_end(size_t size, size_t alignment) {
  void *storage = allocate(size, alignment);
  if (!storage)
    abort();
  return storage;
}

void *operator new(size_t size) { return allocate_or_end(size, 1); }
void *operator new[](size_t size) { return allocate_or_end(size, 1); }
void *operator new(size_t size, std::align_val_t alignment) { return allocate_or_end(size, (size_t)alignment); }
void *operator new[](size_t size, std::align_val_t alignment) { return allocate_or_end(size, (size_t)alignment); }
void *operator new(size_t size, const std::nothrow_t &) noexcept { return allocate(size, 1); }
void *operator new[](size_t size, const std::nothrow_t &) noexcept { return allocate(size, 1); }
void *operator new(size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept {
  return allocate(size, (size_t)alignment);
}
void *operator new[](size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept {
  return allocate(size, (size_t)alignment);
}

void operator delete(void *storage) noexcept { free(storage); }
void operator delete[](void *storage) noexcept { free(storage); }
void operator delete(void *storage, size_t) noexcept { free(storage); }
void operator delete[](void *storage, size_t) noexcept { free(storage); }
void operator delete(void *storage, std::align_val_t) noexcept { free(storage); }
void operator delete[](void *storage, std::align_val_t) noexcept { free(storage); }
void operator delete(void *storage, size_t, std::align_val_t) noexcept { free(storage); }
void operator delete[](void *storage, size_t, std::align_val_t) noexcept { free(storage); }
void operator delete(void *storage, const std::nothrow_t &) noexcept { free(storage); }
void operator delete[](void *storage, const std::nothrow_t &) noexcept { free(storage); }
void operator delete(void *storage, std::align_val_t, const std::nothrow_t &) noexcept { free(storage); }
void operator delete[](void *storage, std::align_val_t, const std::nothrow_t &) noexcept { free(storage); }

extern "C" {

// The guard of a function's static variable: 64 bits, of which the compiler
// reads the first byte, nonzero once the variable is initialized, before it
// calls anything. The upper half is the state of the initialization: 0 when
// nobody is at it, 1 while a thread is, 2 while a thread is and others wait.
// A thread that initializes the variable it is initializing waits for
// itself.

int __cxa_guard_acquire(uint64_t *guard) {
  uint8_t *done = (uint8_t *)guard;
  uint32_t *state = (uint32_t *)guard + 1;
  for (;;) {
    if (__atomic_load_n(done, __ATOMIC_ACQUIRE))
      return 0;
    uint32_t seen = 0;
    if (__atomic_compare_exchange_n(state, &seen, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
      // Another thread may have finished between the two looks.
      if (!__atomic_load_n(done, __ATOMIC_ACQUIRE))
        return 1;
      if (__atomic_exchange_n(state, 0, __ATOMIC_RELEASE) == 2) {
        uint64_t woken;
        smir_sync_wake32(state, UINT32_MAX, &woken);
      }
      return 0;
    }
    if (seen == 1 && !__atomic_compare_exchange_n(state, &seen, 2, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
      continue;
    smir_sync_wait32(state, 2, SMIR_FOREVER);
  }
}

static void guard_leave(uint64_t *guard, uint8_t initialized) {
  if (initialized)
    __atomic_store_n((uint8_t *)guard, 1, __ATOMIC_RELEASE);
  uint32_t *state = (uint32_t *)guard + 1;
  if (__atomic_exchange_n(state, 0, __ATOMIC_RELEASE) == 2) {
    uint64_t woken;
    smir_sync_wake32(state, UINT32_MAX, &woken);
  }
}

void __cxa_guard_release(uint64_t *guard) { guard_leave(guard, 1); }

// The initializer threw: the next thread to come tries again.
void __cxa_guard_abort(uint64_t *guard) { guard_leave(guard, 0); }

// A pure virtual function was called: the object was not yet, or no longer,
// of a class that defines it.
[[noreturn]] void __cxa_pure_virtual() { abort(); }
[[noreturn]] void __cxa_deleted_virtual() { abort(); }

// What a static object names when it registers its destructor with
// `__cxa_atexit`, which the C library has: the program it belongs to. There
// is one program.
void *__dso_handle = &__dso_handle;

} // extern "C"
