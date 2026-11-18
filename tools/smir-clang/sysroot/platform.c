// What LLVM libc's freestanding configuration asks its embedder for, over
// the portable runtime services: the three standard streams, the end of the
// program, and the error number; and the time functions it leaves to an
// operating system.
#include <errno.h>
#include <smir/services.h>
#include <stddef.h>
#include <time.h>

// A stream is the handle of one of the runtime's standard streams. The C
// library keeps no state of its own for it and does not buffer.
struct __llvm_libc_stdio_cookie {
  uint64_t handle;
};

struct __llvm_libc_stdio_cookie __llvm_libc_stdin_cookie = {SMIR_STANDARD_INPUT};
struct __llvm_libc_stdio_cookie __llvm_libc_stdout_cookie = {SMIR_STANDARD_OUTPUT};
struct __llvm_libc_stdio_cookie __llvm_libc_stderr_cookie = {SMIR_STANDARD_ERROR};

// Both return the number of bytes transferred, or a negated error number.
long __llvm_libc_stdio_read(void *cookie, char *buffer, size_t size) {
  uint64_t count;
  uint32_t status = smir_file_read(((struct __llvm_libc_stdio_cookie *)cookie)->handle, buffer, size, &count);
  return status ? -(long)status : (long)count;
}

long __llvm_libc_stdio_write(void *cookie, const char *buffer, size_t size) {
  // One service call may take only part of the bytes; the library expects
  // all of them to be written.
  size_t done = 0;
  while (done < size) {
    uint64_t count;
    uint32_t status = smir_file_write(((struct __llvm_libc_stdio_cookie *)cookie)->handle, buffer + done, size - done, &count);
    if (status)
      return -(long)status;
    if (count == 0)
      break;
    done += count;
  }
  return (long)done;
}

// Called by `exit` after the functions registered with `atexit` have run.
// The runtime then runs the program's finalizers.
_Noreturn void __llvm_libc_exit(int status) { smir_process_exit(status, SMIR_EXIT_CLEAN); }

// `_Exit` ends the program at once: no registered function and no finalizer
// runs. The library's own `_Exit` would go through the hook above, so this
// one takes its place.
_Noreturn void _Exit(int status) { smir_process_exit(status, SMIR_EXIT_IMMEDIATE); }

// The clocks behind `timespec_get` and `clock`: the time since the epoch and
// the processor time the program has used. Each returns whether it could
// read its clock.
static _Bool read_clock(uint32_t clock, struct timespec *time) {
  uint64_t nanoseconds;
  if (smir_clock_now(clock, &nanoseconds) != 0)
    return 0;
  time->tv_sec = (time_t)(nanoseconds / 1000000000u);
  time->tv_nsec = (long)(nanoseconds % 1000000000u);
  return 1;
}

_Bool __llvm_libc_timespec_get_utc(struct timespec *time) { return read_clock(SMIR_CLOCK_UTC, time); }
_Bool __llvm_libc_timespec_get_active(struct timespec *time) { return read_clock(SMIR_CLOCK_PROCESS_CPU, time); }

// Each thread has its own error number.
static _Thread_local int error_number;
int *__llvm_libc_errno(void) { return &error_number; }

// The time functions LLVM libc leaves to an operating system.

time_t time(time_t *out) {
  struct timespec now;
  if (!read_clock(SMIR_CLOCK_UTC, &now))
    return (time_t)-1;
  if (out)
    *out = now.tv_sec;
  return now.tv_sec;
}

int clock_gettime(clockid_t clock, struct timespec *time) {
  static const uint32_t clocks[] = {[CLOCK_REALTIME] = SMIR_CLOCK_UTC,
                                    [CLOCK_MONOTONIC] = SMIR_CLOCK_MONOTONIC,
                                    [CLOCK_PROCESS_CPUTIME_ID] = SMIR_CLOCK_PROCESS_CPU,
                                    [CLOCK_THREAD_CPUTIME_ID] = SMIR_CLOCK_THREAD_CPU};
  if ((unsigned)clock >= sizeof clocks / sizeof clocks[0] || !read_clock(clocks[clock], time)) {
    error_number = EINVAL;
    return -1;
  }
  return 0;
}

// The runtime tells no time zone, so local time is UTC.
struct tm *localtime_r(const time_t *time, struct tm *result) { return gmtime_r(time, result); }

struct tm *localtime(const time_t *time) {
  static struct tm result;
  return localtime_r(time, &result);
}
