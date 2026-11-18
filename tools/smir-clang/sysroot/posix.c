// The functions of <unistd.h> (see overlay/include/unistd.h), over the
// runtime services. A file descriptor is a handle of the runtime.
#include <errno.h>
#include <smir/services.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// The result of a call that failed with `status`.
static long failed(uint32_t status) {
  errno = (int)status;
  return -1;
}

long sysconf(int name) {
  switch (name) {
  case _SC_NPROCESSORS_CONF:
  case _SC_NPROCESSORS_ONLN: {
    uint64_t count;
    return smir_thread_concurrency(&count) == 0 ? (long)count : 1;
  }
  case _SC_PAGESIZE:
    // What `smir_memory_map` aligns to when asked for no more.
    return 4096;
  default:
    return failed(EINVAL);
  }
}

ssize_t read(int descriptor, void *buffer, size_t count) {
  uint64_t moved;
  uint32_t status = descriptor < 0 ? EBADF : smir_file_read((uint64_t)descriptor, buffer, count, &moved);
  return status ? failed(status) : (ssize_t)moved;
}

ssize_t write(int descriptor, const void *buffer, size_t count) {
  uint64_t moved;
  uint32_t status = descriptor < 0 ? EBADF : smir_file_write((uint64_t)descriptor, buffer, count, &moved);
  return status ? failed(status) : (ssize_t)moved;
}

off_t lseek(int descriptor, off_t offset, int whence) {
  uint64_t position;
  // SEEK_SET, SEEK_CUR and SEEK_END are the runtime's 0, 1 and 2.
  uint32_t status = descriptor < 0 ? EBADF : smir_file_seek((uint64_t)descriptor, offset, (uint32_t)whence, &position);
  return status ? failed(status) : (off_t)position;
}

int close(int descriptor) {
  uint32_t status = descriptor < 0 ? EBADF : smir_file_close((uint64_t)descriptor);
  return status ? (int)failed(status) : 0;
}

int unlink(const char *path) {
  uint32_t status = smir_file_unlink(path, strlen(path));
  return status ? (int)failed(status) : 0;
}

int isatty(int descriptor) {
  (void)descriptor;
  errno = ENOTTY;
  return 0;
}

unsigned sleep(unsigned seconds) {
  struct timespec duration = {(time_t)seconds, 0};
  nanosleep(&duration, 0);
  return 0;
}

int usleep(useconds_t microseconds) {
  struct timespec duration = {(time_t)(microseconds / 1000000u), (long)(microseconds % 1000000u) * 1000};
  return nanosleep(&duration, 0);
}
