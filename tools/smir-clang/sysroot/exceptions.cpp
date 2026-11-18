// The runtime under C++ exceptions.
//
// The compiler makes a throw an ordinary return with a flag set, and tests
// the flag after every call that may throw (see ../exceptions.cpp). This is
// the other half: the exception objects, the flag, the choice of a handler,
// and the bookkeeping of handlers that the C++ ABI describes, with the names
// that ABI gives its entry points. Which type a handler catches is decided
// by libc++abi's own type descriptions, compiled beside this file.
//
// Nothing here throws: every function is `noexcept`, so the compiler tests
// no flag inside the runtime itself.
#include <exception>
#include <new>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <typeinfo>

#include "private_typeinfo.h"

extern "C" {
// Set while an exception propagates in this thread.
__thread int __smir_unwinding;
}

namespace {

// What precedes a thrown object in the storage `__cxa_allocate_exception`
// returns. Its size is a multiple of the strictest alignment, so that the
// object after it is aligned for any type.
struct alignas(16) Header {
  const std::type_info *type;
  void (*destructor)(void *);
  // The exception caught before this one, while both are being handled.
  Header *next;
  // The address a handler receives: the object, or its base of the type
  // the handler names.
  void *adjusted;
  // Handlers that hold it; negated while it is thrown again from one.
  int handlers;
  // Owners besides the handlers: `exception_ptr`s.
  int references;
};

__thread Header *propagating;
__thread Header *caught;
__thread unsigned uncaught;

Header *header_of(void *object) { return static_cast<Header *>(object) - 1; }
void *object_of(Header *header) { return header + 1; }

void destroy(Header *header) noexcept {
  if (header->destructor)
    header->destructor(object_of(header));
  free(header);
}

void report_and_abort() {
  fputs("terminate called\n", stderr);
  abort();
}

std::terminate_handler terminate_handler = report_and_abort;

// What `operator new` asks for more storage before it gives up.
std::new_handler new_handler;

} // namespace

namespace std {

terminate_handler set_terminate(terminate_handler handler) noexcept {
  return __atomic_exchange_n(&::terminate_handler, handler ? handler : report_and_abort, __ATOMIC_SEQ_CST);
}

terminate_handler get_terminate() noexcept { return __atomic_load_n(&::terminate_handler, __ATOMIC_SEQ_CST); }

[[noreturn]] void terminate() noexcept {
  get_terminate()();
  // A handler that returns has not done what it is for.
  abort();
}

new_handler set_new_handler(new_handler handler) noexcept {
  return __atomic_exchange_n(&::new_handler, handler, __ATOMIC_SEQ_CST);
}

new_handler get_new_handler() noexcept { return __atomic_load_n(&::new_handler, __ATOMIC_SEQ_CST); }

} // namespace std

extern "C" {

void *__cxa_allocate_exception(size_t size) noexcept {
  void *storage = calloc(1, sizeof(Header) + size);
  if (!storage)
    abort();
  return object_of(static_cast<Header *>(storage));
}

void __cxa_free_exception(void *object) noexcept { free(header_of(object)); }

// The compiler follows a call of this with a return to the caller: here it
// only records what is thrown and sets the flag.
void __cxa_throw(void *object, std::type_info *type, void (*destructor)(void *)) noexcept {
  Header *header = header_of(object);
  header->type = type;
  header->destructor = destructor;
  propagating = header;
  ++uncaught;
  __smir_unwinding = 1;
}

// At a landing pad: which of its clauses catches the exception in flight.
// `types` are the types the clauses name, null for a clause that catches
// everything, and `ids` the number that stands for each; the result is the
// number of the first clause that catches, or zero.
int __smir_select(const std::type_info *const *types, const int *ids, int count) noexcept {
  Header *header = propagating;
  auto *thrown = static_cast<const __cxxabiv1::__shim_type_info *>(header->type);
  // The comparison of types is compiled code like any other, whose calls
  // are followed by tests of the flag: for its duration nothing propagates.
  __smir_unwinding = 0;
  int chosen = 0;
  for (int index = 0; index < count && chosen == 0; ++index) {
    void *adjusted = object_of(header);
    if (types[index] == nullptr ||
        static_cast<const __cxxabiv1::__shim_type_info *>(types[index])->can_catch(thrown, adjusted)) {
      header->adjusted = adjusted;
      chosen = ids[index];
    }
  }
  __smir_unwinding = 1;
  return chosen;
}

// The exception has reached a landing pad that takes it: it propagates no
// more, until the pad resumes it.
void *__smir_landed() noexcept {
  __smir_unwinding = 0;
  return object_of(propagating);
}

void __smir_resume(void *object) noexcept {
  propagating = header_of(object);
  __smir_unwinding = 1;
}

// An exception left the program's entry.
[[noreturn]] void __smir_unhandled() noexcept {
  fputs("terminating due to an uncaught exception\n", stderr);
  abort();
}

// A thread's function has returned to the C library, which calls this if
// the program has it. An exception that left the function was caught by
// nothing.
void __smir_thread_returned() noexcept {
  if (__smir_unwinding)
    __smir_unhandled();
}

void *__cxa_begin_catch(void *object) noexcept {
  Header *header = header_of(object);
  header->handlers = header->handlers < 0 ? -header->handlers + 1 : header->handlers + 1;
  if (header != caught) {
    header->next = caught;
    caught = header;
  }
  --uncaught;
  return header->adjusted;
}

void __cxa_end_catch() noexcept {
  Header *header = caught;
  if (!header)
    return;
  if (header->handlers < 0) {
    // Thrown again from its handler: it lives on, in flight.
    if (++header->handlers == 0)
      caught = header->next;
  } else if (--header->handlers == 0) {
    caught = header->next;
    if (header->references == 0)
      destroy(header);
  }
}

// `throw;`: the exception being handled propagates again.
void __cxa_rethrow() noexcept {
  Header *header = caught;
  if (!header) {
    fputs("terminating: nothing to throw again\n", stderr);
    abort();
  }
  header->handlers = -header->handlers;
  ++uncaught;
  propagating = header;
  __smir_unwinding = 1;
}

void *__cxa_get_exception_ptr(void *object) noexcept { return header_of(object)->adjusted; }

std::type_info *__cxa_current_exception_type() noexcept {
  return caught ? const_cast<std::type_info *>(caught->type) : nullptr;
}

unsigned __cxa_uncaught_exceptions() noexcept { return uncaught; }
bool __cxa_uncaught_exception() noexcept { return uncaught != 0; }

// What `exception_ptr` is made of: a reference to the exception being
// handled, which keeps it alive after its handlers are done, and a way to
// throw it again, from any thread.
void *__cxa_current_primary_exception() noexcept {
  if (!caught)
    return nullptr;
  __atomic_add_fetch(&caught->references, 1, __ATOMIC_SEQ_CST);
  return object_of(caught);
}

void __cxa_increment_exception_refcount(void *object) noexcept {
  if (object)
    __atomic_add_fetch(&header_of(object)->references, 1, __ATOMIC_SEQ_CST);
}

void __cxa_decrement_exception_refcount(void *object) noexcept {
  if (!object)
    return;
  Header *header = header_of(object);
  if (__atomic_sub_fetch(&header->references, 1, __ATOMIC_SEQ_CST) == 0 && header->handlers == 0 &&
      header != propagating)
    destroy(header);
}

// Makes storage from `__cxa_allocate_exception` an exception that was
// never thrown, for `make_exception_ptr`.
__cxxabiv1::__cxa_exception *__cxa_init_primary_exception(void *object, std::type_info *type,
                                                          void (*destructor)(void *)) noexcept {
  Header *header = header_of(object);
  header->type = type;
  header->destructor = destructor;
  header->adjusted = object;
  // The library does nothing with what this returns but keep it.
  return reinterpret_cast<__cxxabiv1::__cxa_exception *>(header);
}

void __cxa_rethrow_primary_exception(void *object) noexcept {
  if (!object)
    return;
  propagating = header_of(object);
  ++uncaught;
  __smir_unwinding = 1;
}

} // extern "C"
