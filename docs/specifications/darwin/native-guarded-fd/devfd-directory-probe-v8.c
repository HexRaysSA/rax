#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <sys/stat.h>

int main(int argc, char **argv) {
  if (argc != 4 || mkdir(argv[1], 0700))
    return 2;
  uint64_t guard = UINT64_C(0x1122334455667788);
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  if (!guarded_open || !guarded_close)
    return 3;
  int guarded = atoi(argv[2]);
  int fd = guarded ? guarded_open(argv[1], &guard, 2, O_RDONLY | O_CLOEXEC)
                   : open(argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 4;
  char name[64];
  snprintf(name, sizeof(name), "/dev/fd/%d", fd);
  errno = 0;
  int copy = open(name, (int)strtoul(argv[3], NULL, 0));
  result("open-directory-devfd", copy, errno);
  if (copy >= 0)
    close(copy);
  return (guarded ? guarded_close(fd, &guard) : close(fd)) == 0 ? 0 : 5;
}
