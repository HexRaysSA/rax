#define PRIVATE 1
#include "references/guarded.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int (*open_guarded_fn)(const char *, const uint64_t *, unsigned, int,
                               ...);
typedef int (*close_guarded_fn)(int, const uint64_t *);
typedef ssize_t (*write_guarded_fn)(int, const uint64_t *, const void *,
                                    size_t);
typedef ssize_t (*pwrite_guarded_fn)(int, const uint64_t *, const void *,
                                     size_t, off_t);
typedef ssize_t (*writev_guarded_fn)(int, const uint64_t *,
                                     const struct iovec *, int);

static void result(const char *name, long value, int error) {
  printf("{\"kind\":\"%s\",\"result\":%ld,\"errno\":%d}\n", name, value, error);
}

int main(int argc, char **argv) {
  if (argc != 5) {
    return 2;
  }
  open_guarded_fn open_guarded =
      (open_guarded_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_guarded_fn close_guarded =
      (close_guarded_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  write_guarded_fn write_guarded =
      (write_guarded_fn)dlsym(RTLD_DEFAULT, "guarded_write_np");
  pwrite_guarded_fn pwrite_guarded =
      (pwrite_guarded_fn)dlsym(RTLD_DEFAULT, "guarded_pwrite_np");
  writev_guarded_fn writev_guarded =
      (writev_guarded_fn)dlsym(RTLD_DEFAULT, "guarded_writev_np");
  if (!open_guarded || !close_guarded || !write_guarded || !pwrite_guarded ||
      !writev_guarded) {
    puts("{\"missing_native_symbol\":true}");
    return 3;
  }
  uint64_t guard = UINT64_C(0x1122334455667788);
  unsigned attributes = (unsigned)strtoul(argv[3], NULL, 0);
  int flags = (int)strtoul(argv[4], NULL, 0);
  const uint64_t *guard_pointer = &guard;
  if (strcmp(argv[1], "zero-guard") == 0) {
    guard = 0;
  } else if (strcmp(argv[1], "null-guard") == 0) {
    guard_pointer = NULL;
  } else if (strcmp(argv[1], "bad-guard") == 0) {
    guard_pointer = (const uint64_t *)(uintptr_t)1;
  }
  if (strcmp(argv[1], "bad-fd") == 0) {
    errno = 0;
    int value = close_guarded(-1, guard_pointer);
    result("close-bad-fd", value, errno);
    errno = 0;
    ssize_t written = write_guarded(-1, guard_pointer, "x", 1);
    result("write-bad-fd", written, errno);
    return 0;
  }
  errno = 0;
  int fd = open_guarded(argv[2], guard_pointer, attributes, flags, 0600);
  result("open", fd, errno);
  if (fd < 0) {
    return 0;
  }
  errno = 0;
  int descriptor_flags = fcntl(fd, F_GETFD);
  result("descriptor-flags", descriptor_flags, errno);
  if (strcmp(argv[1], "positive") == 0) {
    errno = 0;
    ssize_t written = write_guarded(fd, &guard, "abc", 3);
    result("write", written, errno);
    errno = 0;
    written = pwrite_guarded(fd, &guard, "Z", 1, 1);
    result("pwrite", written, errno);
    struct iovec vectors[2] = {{.iov_base = "!", .iov_len = 1},
                               {.iov_base = "?", .iov_len = 1}};
    errno = 0;
    written = writev_guarded(fd, &guard, vectors, 2);
    result("writev", written, errno);
    char data[16] = {0};
    errno = 0;
    ssize_t count = pread(fd, data, sizeof(data), 0);
    result("pread", count, errno);
    printf("{\"kind\":\"content\",\"hex\":\"");
    for (ssize_t index = 0; index < count; ++index) {
      printf("%02x", (unsigned char)data[index]);
    }
    puts("\"}");
  }
  errno = 0;
  int closed = close_guarded(fd, &guard);
  result("close", closed, errno);
  errno = 0;
  descriptor_flags = fcntl(fd, F_GETFD);
  result("after-close", descriptor_flags, errno);
  return 0;
}
