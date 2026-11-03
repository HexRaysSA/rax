#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <sys/stat.h>

int main(int argc, char **argv) {
  if (argc != 6)
    return 2;
  unsigned guarded = (unsigned)atoi(argv[2]);
  int mode = atoi(argv[3]);
  int descriptor_flags = atoi(argv[4]);
  int flags = (int)strtoul(argv[5], NULL, 0);
  int initial = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (initial < 0 || write(initial, "abcde", 5) != 5 || close(initial))
    return 3;
  uint64_t guard = UINT64_C(0x1122334455667788);
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  if (!guarded_open || !guarded_close)
    return 4;
  int original = guarded ? guarded_open(argv[1], &guard, 2, mode | O_CLOEXEC)
                         : open(argv[1], mode | O_CLOEXEC);
  if (original < 0 || fcntl(original, F_SETFD, descriptor_flags))
    return 5;
  char name[64];
  snprintf(name, sizeof(name), "/dev/fd/%d", original);
  errno = 0;
  int duplicate = open(name, flags, 0600);
  result("open-devfd", duplicate, errno);
  if (duplicate >= 0) {
    errno = 0;
    int value = fcntl(duplicate, F_GETFD);
    result("cloned-fd-flags", value, errno);
    errno = 0;
    value = fcntl(duplicate, F_GETFL);
    result("cloned-file-flags", value, errno);
    errno = 0;
    off_t offset = lseek(duplicate, 2, SEEK_SET);
    result("cloned-seek", offset, errno);
    errno = 0;
    offset = lseek(original, 0, SEEK_CUR);
    result("original-offset", offset, errno);
    close(duplicate);
  }
  struct stat status;
  if (fstat(original, &status))
    return 6;
  result("file-size", status.st_size, 0);
  int closed = guarded ? guarded_close(original, &guard) : close(original);
  return closed == 0 ? 0 : 7;
}
