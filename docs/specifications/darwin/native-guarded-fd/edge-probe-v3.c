#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main

typedef ssize_t (*writev_fn)(int, const uint64_t *, const struct iovec *, int);

int main(int argc, char **argv) {
  if (argc != 8)
    return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || !install_guard_receiver())
    return 3;
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  write_fn guarded_write = (write_fn)dlsym(RTLD_DEFAULT, "guarded_write_np");
  writev_fn guarded_writev =
      (writev_fn)dlsym(RTLD_DEFAULT, "guarded_writev_np");
  if (!guarded_open || !guarded_close || !guarded_write || !guarded_writev)
    return 4;
  uint64_t guard = UINT64_C(0x1122334455667788);
  uint64_t wrong = UINT64_C(0x8877665544332211);
  unsigned attributes = (unsigned)strtoul(argv[3], NULL, 0);
  int fd = guarded_open(
      argv[2], &guard, attributes,
      O_CREAT | O_CLOEXEC | (atoi(argv[4]) ? O_RDONLY : O_RDWR), 0600);
  result("open", fd, errno);
  if (fd < 0)
    return 5;
  int target = atoi(argv[5]) ? -1 : fd;
  int cookie_mode = atoi(argv[6]);
  const uint64_t *cookie = cookie_mode == 0   ? &guard
                           : cookie_mode == 1 ? &wrong
                           : cookie_mode == 2 ? NULL
                                              : (void *)(uintptr_t)1;
  int argument = atoi(argv[7]);
  const char *operation = argv[1];
  errno = 0;
  ssize_t value;
  if (strcmp(operation, "scalar") == 0) {
    size_t count = argument ? (size_t)INT32_MAX + 1 : 1;
    value = guarded_write(target, cookie, "x", count);
  } else {
    struct iovec vectors[2] = {{.iov_base = "x", .iov_len = 1},
                               {.iov_base = "y", .iov_len = 1}};
    const struct iovec *pointer = vectors;
    int count = argument;
    if (strcmp(operation, "bad-vector") == 0)
      pointer = (void *)(uintptr_t)1;
    if (strcmp(operation, "large-vector") == 0) {
      vectors[0].iov_len = (size_t)INT32_MAX;
      vectors[1].iov_len = 1;
      count = 2;
    }
    value = strcmp(operation, "ordinary-vector") == 0 ||
                    strcmp(operation, "bad-ordinary-vector") == 0
                ? writev(target,
                         strcmp(operation, "bad-ordinary-vector") == 0
                             ? (void *)(uintptr_t)1
                             : pointer,
                         count)
                : guarded_writev(target, cookie, pointer, count);
  }
  result(operation, value, errno);
  errno = 0;
  value = guarded_close(fd, &guard);
  result("cleanup", value, errno);
  return 0;
}
