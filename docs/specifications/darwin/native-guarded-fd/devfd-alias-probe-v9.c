#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main

int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  uint64_t guard = UINT64_C(0x1122334455667788);
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  if (!guarded_open || !guarded_close)
    return 3;
  int guarded = atoi(argv[2]);
  int fd = guarded ? guarded_open(argv[1], &guard, 2,
                                 O_RDWR | O_CREAT | O_CLOEXEC, 0600)
                   : open(argv[1], O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0)
    return 4;
  char direct[64], path[4096], link[4096];
  snprintf(direct, sizeof(direct), "/dev/fd/%d", fd);
  snprintf(link, sizeof(link), "%s.link", argv[1]);
  if (strcmp(argv[3], "directory-alias") == 0) {
    if (symlink("/dev/fd", link))
      return 5;
    snprintf(path, sizeof(path), "%s/%d", link, fd);
  } else if (strcmp(argv[3], "file-alias") == 0) {
    if (symlink(direct, link))
      return 6;
    snprintf(path, sizeof(path), "%s", link);
  } else if (strcmp(argv[3], "relative") == 0) {
    if (chdir("/dev/fd"))
      return 7;
    snprintf(path, sizeof(path), "%d", fd);
  } else {
    snprintf(path, sizeof(path), "%s", direct);
  }
  errno = 0;
  int duplicate = open(path, (int)strtoul(argv[4], NULL, 0), 0600);
  result("open-alias", duplicate, errno);
  if (duplicate >= 0)
    close(duplicate);
  if (strcmp(argv[3], "directory-alias") == 0 ||
      strcmp(argv[3], "file-alias") == 0)
    if (unlink(link))
      return 8;
  return (guarded ? guarded_close(fd, &guard) : close(fd)) == 0 ? 0 : 9;
}
