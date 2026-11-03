#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <sys/stat.h>

typedef int (*dp_open_fn)(const char *, const uint64_t *, unsigned, int,
                          int, int, ...);

int main(int argc, char **argv) {
  if (argc != 9)
    return 2;
  umask(0022);
  int cookie_mode = atoi(argv[2]);
  unsigned attributes = (unsigned)strtoul(argv[3], NULL, 0);
  int flags = (int)strtoul(argv[4], NULL, 0);
  int dpclass = (int)strtol(argv[5], NULL, 0);
  int dpflags = (int)strtol(argv[6], NULL, 0);
  unsigned mode = (unsigned)strtoul(argv[7], NULL, 0);
  int path_mode = atoi(argv[8]);
  if (path_mode != 2) {
    int initial = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0600);
    if (initial < 0 || close(initial))
      return 3;
  }
  dp_open_fn guarded_dp =
      (dp_open_fn)dlsym(RTLD_DEFAULT, "guarded_open_dprotected_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  if (!guarded_dp || !guarded_close)
    return 4;
  uint64_t cookie = cookie_mode == 1 ? 0 : UINT64_C(0x1122334455667788);
  const uint64_t *pointer = cookie_mode == 2 ? NULL
                            : cookie_mode == 3 ? (void *)(uintptr_t)1
                                               : &cookie;
  const char *path = path_mode == 1 ? (void *)(uintptr_t)1 : argv[1];
  errno = 0;
  int fd = guarded_dp(path, pointer, attributes, flags, dpclass, dpflags, mode);
  result("guarded-dp-open", fd, errno);
  if (fd >= 0) {
    errno = 0;
    int value = fcntl(fd, F_GETFD);
    result("fd-flags", value, errno);
    struct stat info;
    if (fstat(fd, &info))
      return 5;
    result("file-mode", info.st_mode & 07777, 0);
    errno = 0;
    value = guarded_close(fd, &cookie);
    result("guarded-dp-close", value, errno);
    if (value)
      return 6;
  }
  return 0;
}
