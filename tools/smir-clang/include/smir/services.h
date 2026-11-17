// The portable runtime services a C program can call directly.
//
// Each function is bound by its link name to one entry of the service
// catalog (docs/specifications/smir/portable/schema/runtime/services-v1.json)
// and compiles to a call of that service: no function of this name exists in
// the program. A service that returns a status and a value returns the status
// here and stores the value through the last parameter.
//
// The status is 0 for success and otherwise a portable error number, whose
// values are those of Linux. The value is 0 when the call fails.
//
// Compiled natively, the same declarations are ordinary functions that a
// host library must define; the compiler's tests use that to compare a
// program with its native build.
#ifndef SMIR_SERVICES_H
#define SMIR_SERVICES_H

#include <stdint.h>

#ifdef __SMIR__
#define SMIR_SERVICE(name) __asm__("smir.portable.v1:" name)
#else
#define SMIR_SERVICE(name)
#endif

// The streams every program starts with.
#define SMIR_STANDARD_INPUT 0
#define SMIR_STANDARD_OUTPUT 1
#define SMIR_STANDARD_ERROR 2

// Read up to `length` bytes into `buffer`. `*count` is how many were read;
// zero is the end of the input. One call transfers at most 65536 bytes.
uint32_t smir_file_read(uint64_t handle, void *buffer, uint64_t length, uint64_t *count) SMIR_SERVICE("file.read");

// Write up to `length` bytes of `buffer`. `*count` is how many were written,
// which may be fewer than asked. One call transfers at most 65536 bytes.
uint32_t smir_file_write(uint64_t handle, const void *buffer, uint64_t length, uint64_t *count)
    SMIR_SERVICE("file.write");

// How a program ends itself: after its cleanup, after its quick-exit
// handlers only, or at once.
#define SMIR_EXIT_CLEAN 0
#define SMIR_EXIT_QUICK 1
#define SMIR_EXIT_IMMEDIATE 2

// End the program with `status`.
_Noreturn void smir_process_exit(int32_t status, uint32_t mode) SMIR_SERVICE("process.exit");

// End the program abnormally.
_Noreturn void smir_process_abort(void) SMIR_SERVICE("process.abort");

#endif
