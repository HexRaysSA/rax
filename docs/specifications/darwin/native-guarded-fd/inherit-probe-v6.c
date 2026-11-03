#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <libproc.h>
#include <sys/proc_info.h>

int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core))
    return 3;
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  if (!guarded_open || !guarded_close)
    return 4;
  uint64_t guard = UINT64_C(0x1122334455667788);
  unsigned attributes = (unsigned)strtoul(argv[2], NULL, 0);
  int fd = guarded_open(argv[1], &guard, attributes,
                        O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0)
    return 5;
  if (atoi(argv[3]) && fcntl(fd, F_SETFD, FD_CLOEXEC))
    return 6;
  pid_t child = fork();
  if (child < 0)
    return 7;
  if (child == 0) {
    errno = 0;
    int flags = fcntl(fd, F_GETFD);
    result("child-flags", flags, errno);
    if (flags >= 0) {
      uint64_t storage[256] = {0};
      int count = proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEINFO, storage,
                                 sizeof(storage));
      if (count < (int)sizeof(struct proc_fileinfo))
        _exit(8);
      const struct proc_fileinfo *info = (const void *)storage;
      printf("{\"kind\":\"child-fileinfo\",\"status\":%u,\"guard_flags\":%u}\n",
             info->fi_status, info->fi_guardflags);
      errno = 0;
      int duplicate = dup(fd);
      result("child-dup", duplicate, errno);
      if (duplicate >= 0)
        close(duplicate);
    }
    _exit(0);
  }
  int status;
  if (waitpid(child, &status, 0) != child)
    return 9;
  result("child-wait-status", status, 0);
  return guarded_close(fd, &guard) == 0 ? 0 : 10;
}
