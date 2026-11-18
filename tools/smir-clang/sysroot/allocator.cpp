// The allocation functions, one caller at a time.
//
// LLVM libc's freestanding heap is for one thread. Its entry points are
// built under their internal names only, and the public names are defined
// here: each takes the heap's lock and calls the entry point of that name.
#include "src/__support/macros/config.h"
#include "src/stdlib/aligned_alloc.h"
#include "src/stdlib/calloc.h"
#include "src/stdlib/free.h"
#include "src/stdlib/malloc.h"
#include "src/stdlib/malloc_usable_size.h"
#include "src/stdlib/realloc.h"

extern "C" {
#include "lock.h"
}

namespace {

uint32_t heap_lock;

struct Held {
  Held() { smir_lock(&heap_lock); }
  ~Held() { smir_unlock(&heap_lock); }
};

} // namespace

extern "C" {

void *malloc(size_t size) {
  Held held;
  return LIBC_NAMESPACE::malloc(size);
}

void free(void *pointer) {
  Held held;
  LIBC_NAMESPACE::free(pointer);
}

void *calloc(size_t count, size_t size) {
  Held held;
  return LIBC_NAMESPACE::calloc(count, size);
}

void *realloc(void *pointer, size_t size) {
  Held held;
  return LIBC_NAMESPACE::realloc(pointer, size);
}

void *aligned_alloc(size_t alignment, size_t size) {
  Held held;
  return LIBC_NAMESPACE::aligned_alloc(alignment, size);
}

size_t malloc_usable_size(void *pointer) {
  Held held;
  return LIBC_NAMESPACE::malloc_usable_size(pointer);
}

} // extern "C"
