#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <spawn.h>

extern char **environ;

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc == 3 && strcmp(argv[1], "inspect") == 0) {
    errno = 0;
    int value = fcntl(atoi(argv[2]), F_GETFD);
    result("child-descriptor", value, errno);
    return 0;
  }
  if (argc != 6)
    return 2;
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || !install_guard_receiver())
    return 3;
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  if (!guarded_open || !guarded_close)
    return 4;
  uint64_t guard = UINT64_C(0x1122334455667788);
  unsigned attributes = (unsigned)strtoul(argv[3], NULL, 0);
  errno = 0;
  int fd = guarded_open(argv[2], &guard, attributes,
                        O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  result("open", fd, errno);
  if (fd < 0)
    return 5;
  if (atoi(argv[4])) {
    errno = 0;
    int value = fcntl(fd, F_SETFD, FD_CLOEXEC);
    result("clear-clofork", value, errno);
  }
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attr;
  if (posix_spawn_file_actions_init(&actions) || posix_spawnattr_init(&attr))
    return 6;
  int observed = fd;
  int error;
  if (strcmp(argv[1], "dup") == 0) {
    observed = 100;
    error = posix_spawn_file_actions_adddup2(&actions, fd, observed);
  } else if (strcmp(argv[1], "dup-self") == 0) {
    error = posix_spawn_file_actions_adddup2(&actions, fd, fd);
  } else if (strcmp(argv[1], "inherit") == 0) {
    error = posix_spawn_file_actions_addinherit_np(&actions, fd);
  } else if (strcmp(argv[1], "close") == 0) {
    error = posix_spawn_file_actions_addclose(&actions, fd);
  } else {
    return 7;
  }
  if (error)
    return 8;
  int setexec = atoi(argv[5]);
  if (posix_spawnattr_setflags(&attr, setexec ? POSIX_SPAWN_SETEXEC : 0))
    return 9;
  char number[32];
  snprintf(number, sizeof(number), "%d", observed);
  char *child_argv[] = {argv[0], "inspect", number, NULL};
  pid_t child = 0;
  puts("{\"kind\":\"before-spawn\"}");
  error = posix_spawn(&child, argv[0], &actions, &attr, child_argv, environ);
  result("spawn-error", error, 0);
  if (!error) {
    int status;
    if (waitpid(child, &status, 0) != child)
      return 10;
    result("child-wait-status", status, 0);
  }
  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attr);
  errno = 0;
  int value = guarded_close(fd, &guard);
  result("cleanup", value, errno);
  return 0;
}
