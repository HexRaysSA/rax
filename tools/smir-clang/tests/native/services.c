// The services of <smir/services.h> for a native build, over POSIX. Used only
// to produce the reference behaviour that compiled programs are compared
// with; the error numbers are the host's, which the tests do not rely on.
#include <smir/services.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

enum { STREAM_LIMIT = 65536 };

uint32_t smir_file_read(uint64_t handle, void *buffer, uint64_t length, uint64_t *count) {
  *count = 0;
  if (handle != SMIR_STANDARD_INPUT)
    return EBADF;
  ssize_t moved = read(0, buffer, length < STREAM_LIMIT ? length : STREAM_LIMIT);
  if (moved < 0)
    return (uint32_t)errno;
  *count = (uint64_t)moved;
  return 0;
}

uint32_t smir_file_write(uint64_t handle, const void *buffer, uint64_t length, uint64_t *count) {
  *count = 0;
  if (handle != SMIR_STANDARD_OUTPUT && handle != SMIR_STANDARD_ERROR)
    return EBADF;
  ssize_t moved = write((int)handle, buffer, length < STREAM_LIMIT ? length : STREAM_LIMIT);
  if (moved < 0)
    return (uint32_t)errno;
  *count = (uint64_t)moved;
  return 0;
}

_Noreturn void smir_process_exit(int32_t status, uint32_t mode) {
  (void)mode;
  _exit(status);
}

_Noreturn void smir_process_abort(void) { abort(); }
