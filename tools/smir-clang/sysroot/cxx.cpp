// What C++ programs need from a runtime besides the C library, where they
// are compiled without exceptions and run-time type information: storage
// for `new`, the function a call of a pure virtual function reaches, and
// the name by which a static object's destructor is registered.
#include <stddef.h>
#include <stdlib.h>

namespace std {
enum class align_val_t : size_t {};
struct nothrow_t {
  explicit nothrow_t() = default;
};
extern const nothrow_t nothrow;
const nothrow_t nothrow{};
} // namespace std

// Storage. Without exceptions there is no way to report that there is none
// left, so the program ends.

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

// A pure virtual function was called: the object was not yet, or no longer,
// of a class that defines it.
[[noreturn]] void __cxa_pure_virtual() { abort(); }
[[noreturn]] void __cxa_deleted_virtual() { abort(); }

// What a static object names when it registers its destructor with
// `__cxa_atexit`, which the C library has: the program it belongs to. There
// is one program.
void *__dso_handle = &__dso_handle;

} // extern "C"
