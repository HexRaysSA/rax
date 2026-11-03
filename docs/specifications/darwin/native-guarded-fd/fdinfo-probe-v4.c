#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <libproc.h>
#include <sys/proc_info.h>

int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  kqueue_fn guarded_kqueue =
      (kqueue_fn)dlsym(RTLD_DEFAULT, "guarded_kqueue_np");
  if (!guarded_open || !guarded_close || !guarded_kqueue)
    return 3;
  uint64_t guard = UINT64_C(0x1122334455667788);
  unsigned attributes = (unsigned)strtoul(argv[3], NULL, 0);
  int queue = strcmp(argv[1], "kqueue") == 0;
  errno = 0;
  int fd = queue ? guarded_kqueue(&guard, attributes)
                 : guarded_open(argv[2], &guard, attributes,
                                O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0)
    return 4;
  uint64_t storage[256] = {0};
  errno = 0;
  int count = proc_pidfdinfo(getpid(), fd,
                             queue ? PROC_PIDFDKQUEUEINFO : PROC_PIDFDVNODEINFO,
                             storage, sizeof(storage));
  if (count < (int)sizeof(struct proc_fileinfo))
    return 5;
  const struct proc_fileinfo *info = (const void *)storage;
  printf("{\"kind\":\"fileinfo\",\"bytes\":%d,\"status\":%u,"
         "\"guard_flags\":%u,\"type\":%d,\"open_flags\":%u}\n",
         count, info->fi_status, info->fi_guardflags, info->fi_type,
         info->fi_openflags);
  return guarded_close(fd, &guard) == 0 ? 0 : 6;
}
