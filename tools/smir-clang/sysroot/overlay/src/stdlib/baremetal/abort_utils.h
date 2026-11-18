// How the C library ends the program abnormally: LLVM libc's freestanding
// configuration executes a trap instruction; here the runtime is told, so
// that whoever runs the program sees an abort and not a fault.
#ifndef LLVM_LIBC_SRC_STDLIB_BAREMETAL_ABORT_UTILS_H
#define LLVM_LIBC_SRC_STDLIB_BAREMETAL_ABORT_UTILS_H

#include "src/__support/common.h"
#include "src/__support/macros/config.h"

extern "C" [[noreturn]] void __smir_abort() __asm__("smir.portable.v1:process.abort");

namespace LIBC_NAMESPACE_DECL {

namespace abort_utils {
[[noreturn]] LIBC_INLINE void abort() { __smir_abort(); }
} // namespace abort_utils

} // namespace LIBC_NAMESPACE_DECL

#endif // LLVM_LIBC_SRC_STDLIB_BAREMETAL_ABORT_UTILS_H
