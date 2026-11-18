// The services of <smir/services.h> for a native build, over POSIX. Used only
// to produce the reference behaviour that compiled programs are compared
// with; the error numbers are the host's, which the tests do not rely on.
#include <smir/services.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
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

uint32_t smir_clock_now(uint32_t clock, uint64_t *nanoseconds) {
  static const clockid_t clocks[4] = {CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_PROCESS_CPUTIME_ID,
                                      CLOCK_THREAD_CPUTIME_ID};
  struct timespec now;
  *nanoseconds = 0;
  if (clock > 3)
    return EINVAL;
  if (clock_gettime(clocks[clock], &now) != 0)
    return (uint32_t)errno;
  *nanoseconds = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
  return 0;
}

// Mappings, so that only a whole one is unmapped or protected.
enum { MAPPINGS = 64 };
static struct {
  void *base;
  uint64_t bytes;
} mappings[MAPPINGS];

static int protection(uint32_t permissions) {
  return (permissions & SMIR_MAP_READ ? PROT_READ : 0) | (permissions & SMIR_MAP_WRITE ? PROT_WRITE : 0);
}

static int find_mapping(void *address, uint64_t bytes) {
  for (int index = 0; index < MAPPINGS; index++)
    if (mappings[index].base == address && mappings[index].bytes == bytes && bytes != 0)
      return index;
  return -1;
}

uint32_t smir_memory_map(uint64_t bytes, uint64_t alignment, uint32_t permissions, void **base) {
  *base = 0;
  // A page is aligned enough for what the tests ask.
  if (bytes == 0 || alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > 4096 || permissions > 3)
    return EINVAL;
  int slot = find_mapping(0, 0);
  for (int index = 0; index < MAPPINGS && slot < 0; index++)
    if (mappings[index].bytes == 0)
      slot = index;
  void *mapped = slot < 0 ? MAP_FAILED : mmap(0, bytes, protection(permissions), MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mapped == MAP_FAILED)
    return ENOMEM;
  mappings[slot].base = *base = mapped;
  mappings[slot].bytes = bytes;
  return 0;
}

uint32_t smir_memory_unmap(void *address, uint64_t bytes) {
  int slot = find_mapping(address, bytes);
  if (slot < 0)
    return EINVAL;
  munmap(address, bytes);
  mappings[slot].base = 0;
  mappings[slot].bytes = 0;
  return 0;
}

uint32_t smir_memory_protect(void *address, uint64_t bytes, uint32_t permissions) {
  if (permissions > 3 || find_mapping(address, bytes) < 0)
    return EINVAL;
  return mprotect(address, bytes, protection(permissions)) == 0 ? 0 : (uint32_t)errno;
}

_Noreturn void smir_process_exit(int32_t status, uint32_t mode) {
  (void)mode;
  _exit(status);
}

_Noreturn void smir_process_abort(void) { abort(); }
