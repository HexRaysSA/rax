#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t clock_ns(void) {
  struct timespec time;
  if (clock_gettime(CLOCK_MONOTONIC, &time))
    _exit(20);
  return (uint64_t)time.tv_sec * UINT64_C(1000000000) + time.tv_nsec;
}

int main(int argc, char **argv) {
  if (argc != 10)
    return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  umask(0022);
  int command = atoi(argv[2]);
  int conflict = atoi(argv[5]);
  int confined = atoi(argv[8]);
  int fd = open(argv[1], O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0)
    return 3;
  if (confined) {
    if (fcntl(fd, F_SETFD, 3))
      return 4;
    errno = 0;
    int result = fcntl(fd, 95, 1);
    printf("{\"kind\":\"confine\",\"result\":%d,\"errno\":%d}\n", result, errno);
  }
  pid_t child = -1;
  if (conflict) {
    int ready[2];
    if (pipe(ready))
      return 5;
    child = fork();
    if (child < 0)
      return 6;
    if (child == 0) {
      close(ready[0]);
      int own = open(argv[1], O_RDWR | O_CLOEXEC);
      struct flock lock = {.l_start = 0, .l_len = 1, .l_type = F_WRLCK, .l_whence = SEEK_SET};
      if (own < 0 || fcntl(own, command == 93 ? 90 : F_SETLK, &lock) ||
          write(ready[1], "L", 1) != 1)
        _exit(10);
      usleep(50000);
      close(own);
      _exit(0);
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1 || byte != 'L' || close(ready[0]))
      return 7;
  }
  struct flocktimeout request;
  memset(&request, 0, sizeof(request));
  request.fl.l_start = 0;
  request.fl.l_len = 1;
  request.fl.l_type = (short)atoi(argv[6]);
  request.fl.l_whence = SEEK_SET;
  request.timeout.tv_sec = strtoll(argv[3], NULL, 0);
  request.timeout.tv_nsec = strtoll(argv[4], NULL, 0);
  unsigned char before[sizeof(request)];
  memcpy(before, &request, sizeof(request));
  void *argument = atoi(argv[7]) ? (void *)(uintptr_t)1 : &request;
  int target = atoi(argv[9]) ? -1 : fd;
  errno = 0;
  uint64_t start = clock_ns();
  int value = fcntl(target, command, argument);
  int error = errno;
  uint64_t elapsed = clock_ns() - start;
  printf("{\"kind\":\"timed-lock\",\"result\":%d,\"errno\":%d,\"elapsed_ns\":%" PRIu64
         ",\"flock_bytes\":%zu,\"request_bytes\":%zu,\"request_unchanged\":%s}\n",
         value, error, elapsed, sizeof(struct flock), sizeof(request),
         memcmp(before, &request, sizeof(request)) ? "false" : "true");
  if (child > 0) {
    int status;
    if (waitpid(child, &status, 0) != child || status != 0)
      return 8;
  }
  return close(fd) ? 9 : 0;
}
