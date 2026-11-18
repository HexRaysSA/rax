// The portable runtime services a C program can call directly.
//
// Each function is bound by its link name to one entry of the service
// catalog (docs/specifications/smir/portable/schema/runtime/services-v1.json)
// and compiles to a call of that service: no function of this name exists in
// the program. A service that returns a status and a value returns the status
// here and stores the value through the last parameter.
//
// The status is 0 for success and otherwise a portable error number, whose
// values are those of Linux. The value is 0 when the call fails. Where the
// value says nothing, as after a wait, the declaration leaves its parameter
// out.
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

// How a file is opened: for reading, for writing or for both, and whether
// it is made if there is none, emptied if there is one, and whether every
// write goes to its end. Emptying and appending need writing.
#define SMIR_OPEN_READ 1
#define SMIR_OPEN_WRITE 2
#define SMIR_OPEN_CREATE 4
#define SMIR_OPEN_TRUNCATE 8
#define SMIR_OPEN_APPEND 16

// Open the file that the `length` bytes at `path` name: UTF-8, names
// separated by `/`, in the namespace the runtime gives the program. `mode`
// is the permission bits of a file this makes. `*handle` is a number no
// other open file has or had, for `smir_file_read`, `smir_file_write` and
// the functions below.
uint32_t smir_file_open(const char *path, uint64_t length, uint32_t flags, uint32_t mode, uint64_t *handle)
    SMIR_SERVICE("file.open");

// Close a file. Its handle is then no handle.
uint32_t smir_file_close(uint64_t handle) SMIR_SERVICE("file.close");

// What an offset counts from: the start of the file, its position, its end.
#define SMIR_SEEK_START 0
#define SMIR_SEEK_CURRENT 1
#define SMIR_SEEK_END 2

// Move the position of a file; `*position` is where it then is, from the
// start. EINVAL for a position before the start, ESPIPE for a stream.
uint32_t smir_file_seek(uint64_t handle, int64_t offset, uint32_t whence, uint64_t *position)
    SMIR_SERVICE("file.seek");

// Remove a file's name.
uint32_t smir_file_unlink(const char *path, uint64_t length) SMIR_SERVICE("file.unlink");

// Give a file another name, in place of any file that has it.
uint32_t smir_file_rename(const char *source, uint64_t source_length, const char *destination,
                          uint64_t destination_length) SMIR_SERVICE("file.rename");

// The clocks: time since an arbitrary start, time since the Unix epoch, and
// the processor time of the program and of the calling thread.
#define SMIR_CLOCK_MONOTONIC 0
#define SMIR_CLOCK_UTC 1
#define SMIR_CLOCK_PROCESS_CPU 2
#define SMIR_CLOCK_THREAD_CPU 3

// Read a clock, in nanoseconds.
uint32_t smir_clock_now(uint32_t clock, uint64_t *nanoseconds) SMIR_SERVICE("clock.now");

// How a program ends itself: after its cleanup, after its quick-exit
// handlers only, or at once.
#define SMIR_EXIT_CLEAN 0
#define SMIR_EXIT_QUICK 1
#define SMIR_EXIT_IMMEDIATE 2

// End the program with `status`.
_Noreturn void smir_process_exit(int32_t status, uint32_t mode) SMIR_SERVICE("process.exit");

// End the program abnormally.
_Noreturn void smir_process_abort(void) SMIR_SERVICE("process.abort");

// What mapped memory permits.
#define SMIR_MAP_READ 1
#define SMIR_MAP_WRITE 2

// Map `bytes` bytes of zeros at an address that is a multiple of
// `alignment`, a power of two; `*base` is where. The bytes count against the
// memory the program may hold. EINVAL for a request that makes no sense,
// ENOMEM when there is no room; `*base` is then null.
uint32_t smir_memory_map(uint64_t bytes, uint64_t alignment, uint32_t permissions, void **base)
    SMIR_SERVICE("memory.map");

// Unmap what one `smir_memory_map` mapped: its base and its size. Any
// pointer into it is then invalid.
uint32_t smir_memory_unmap(void *address, uint64_t bytes) SMIR_SERVICE("memory.unmap");

// Change what a whole mapping permits.
uint32_t smir_memory_protect(void *address, uint64_t bytes, uint32_t permissions) SMIR_SERVICE("memory.protect");

// Start a thread that calls `entry(argument)`; what that returns is the
// thread's result. `*thread` is its handle, for one join or one detach.
// `stack_bytes` is a wish the runtime may ignore; 0 leaves it the choice.
uint32_t smir_thread_spawn(uint64_t (*entry)(void *), void *argument, uint64_t stack_bytes, uint64_t *thread)
    SMIR_SERVICE("thread.spawn");

// Wait for a thread to end; `*result` is its result. The handle is then no
// longer valid.
uint32_t smir_thread_join(uint64_t thread, uint64_t *result) SMIR_SERVICE("thread.join");

// Give up the right to join a thread, which goes on running.
uint32_t smir_thread_detach(uint64_t thread) SMIR_SERVICE("thread.detach");

// Let other threads run.
uint32_t smir_thread_yield(void) SMIR_SERVICE("thread.yield");

// The calling thread's identity: 1 for the program's first thread, otherwise
// the handle `smir_thread_spawn` stored for it.
uint32_t smir_thread_id(uint64_t *identity) SMIR_SERVICE("thread.id");

// How many of the program's threads can run at one time: one at least.
uint32_t smir_thread_concurrency(uint64_t *count) SMIR_SERVICE("thread.concurrency");

// End the calling thread with `result`.
_Noreturn void smir_thread_exit(uint64_t result) SMIR_SERVICE("thread.exit");

// A timeout that never passes.
#define SMIR_FOREVER UINT64_MAX

// If the 32-bit word at `address` holds `expected`, wait until a wake on
// that address or until `timeout_ns` nanoseconds have passed. Comparing and
// starting to wait are one action with respect to a wake. Returns 0 when
// woken, which may be for no reason, EAGAIN if the word held something else,
// and ETIMEDOUT. `address` is a multiple of four.
uint32_t smir_sync_wait32(const void *address, uint32_t expected, uint64_t timeout_ns) SMIR_SERVICE("sync.wait32");

// Wake up to `count` of the threads waiting on `address`, the longest
// waiting first. `*woken` is how many.
uint32_t smir_sync_wake32(const void *address, uint32_t count, uint64_t *woken) SMIR_SERVICE("sync.wake32");

#endif
