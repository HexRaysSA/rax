// The services of <smir/services.h> for a native build, over POSIX. Used only
// to produce the reference behaviour that compiled programs are compared
// with; the error numbers are the host's, which the tests do not rely on.
#include <smir/services.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

enum { STREAM_LIMIT = 65536, PATH_LIMIT = 4096, FILES = 64 };

// Open files: a handle is a number that is never given out twice, which a
// descriptor of the host is not.
static struct {
  uint64_t handle;
  int descriptor;
} files[FILES];
static uint64_t next_handle = 3;

// The descriptor behind a handle: the standard streams, or an open file.
static int descriptor_of(uint64_t handle) {
  if (handle <= SMIR_STANDARD_ERROR)
    return (int)handle;
  for (int index = 0; index < FILES; index++)
    if (files[index].handle == handle)
      return files[index].descriptor;
  return -1;
}

// A counted path as the string the host wants; null if it is not one.
static const char *path_of(const char *path, uint64_t length, char *terminated) {
  if (length == 0 || length > PATH_LIMIT || memchr(path, 0, length))
    return 0;
  memcpy(terminated, path, length);
  terminated[length] = 0;
  return terminated;
}

uint32_t smir_file_read(uint64_t handle, void *buffer, uint64_t length, uint64_t *count) {
  *count = 0;
  int descriptor = descriptor_of(handle);
  if (descriptor < 0 || handle == SMIR_STANDARD_OUTPUT || handle == SMIR_STANDARD_ERROR)
    return EBADF;
  ssize_t moved = read(descriptor, buffer, length < STREAM_LIMIT ? length : STREAM_LIMIT);
  if (moved < 0)
    return (uint32_t)errno;
  *count = (uint64_t)moved;
  return 0;
}

uint32_t smir_file_write(uint64_t handle, const void *buffer, uint64_t length, uint64_t *count) {
  *count = 0;
  int descriptor = descriptor_of(handle);
  if (descriptor < 0 || handle == SMIR_STANDARD_INPUT)
    return EBADF;
  ssize_t moved = write(descriptor, buffer, length < STREAM_LIMIT ? length : STREAM_LIMIT);
  if (moved < 0)
    return (uint32_t)errno;
  *count = (uint64_t)moved;
  return 0;
}

uint32_t smir_file_open(const char *path, uint64_t length, uint32_t flags, uint32_t mode, uint64_t *handle) {
  char terminated[PATH_LIMIT + 1];
  *handle = 0;
  const char *name = path_of(path, length, terminated);
  int reads = flags & SMIR_OPEN_READ, writes = flags & SMIR_OPEN_WRITE;
  if (!name || flags > 31 || (!reads && !writes) ||
      ((flags & (SMIR_OPEN_TRUNCATE | SMIR_OPEN_APPEND)) && !writes) || mode > 07777)
    return EINVAL;
  int slot = -1;
  for (int index = 0; index < FILES && slot < 0; index++)
    if (files[index].handle == 0)
      slot = index;
  if (slot < 0)
    return EMFILE;
  int how = (reads && writes ? O_RDWR : writes ? O_WRONLY : O_RDONLY) | (flags & SMIR_OPEN_CREATE ? O_CREAT : 0) |
            (flags & SMIR_OPEN_TRUNCATE ? O_TRUNC : 0) | (flags & SMIR_OPEN_APPEND ? O_APPEND : 0);
  int descriptor = open(name, how, (mode_t)mode);
  if (descriptor < 0)
    return (uint32_t)errno;
  files[slot].handle = *handle = next_handle++;
  files[slot].descriptor = descriptor;
  return 0;
}

uint32_t smir_file_close(uint64_t handle) {
  for (int index = 0; index < FILES; index++)
    if (handle > SMIR_STANDARD_ERROR && files[index].handle == handle) {
      close(files[index].descriptor);
      files[index].handle = 0;
      return 0;
    }
  return EBADF;
}

uint32_t smir_file_seek(uint64_t handle, int64_t offset, uint32_t whence, uint64_t *position) {
  static const int origins[3] = {SEEK_SET, SEEK_CUR, SEEK_END};
  *position = 0;
  int descriptor = descriptor_of(handle);
  if (descriptor < 0)
    return EBADF;
  if (handle <= SMIR_STANDARD_ERROR)
    return ESPIPE;
  if (whence > 2)
    return EINVAL;
  off_t moved = lseek(descriptor, (off_t)offset, origins[whence]);
  if (moved < 0)
    return (uint32_t)errno;
  *position = (uint64_t)moved;
  return 0;
}

uint32_t smir_file_unlink(const char *path, uint64_t length) {
  char terminated[PATH_LIMIT + 1];
  const char *name = path_of(path, length, terminated);
  if (!name)
    return EINVAL;
  return unlink(name) == 0 ? 0 : (uint32_t)errno;
}

uint32_t smir_file_rename(const char *source, uint64_t source_length, const char *destination,
                          uint64_t destination_length) {
  char from[PATH_LIMIT + 1], to[PATH_LIMIT + 1];
  if (!path_of(source, source_length, from) || !path_of(destination, destination_length, to))
    return EINVAL;
  return rename(from, to) == 0 ? 0 : (uint32_t)errno;
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
