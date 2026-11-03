#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 7) return 2;
  int fd = open(argv[1], O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fd < 0 || ftruncate(fd, 64) || lseek(fd, 16, SEEK_SET) != 16) return 3;
  struct flocktimeout request = {
    .fl = {.l_start = strtoll(argv[6], NULL, 10), .l_len = 1,
      .l_pid = atoi(argv[3]), .l_type = (short)atoi(argv[4]),
      .l_whence = (short)atoi(argv[5])}, .timeout = {0, 0}};
  struct flocktimeout original = request;
  errno = 0;
  int result = fcntl(fd, atoi(argv[2]), &request), error = errno;
  printf("{\"command\":%d,\"pid\":%d,\"type\":%d,\"whence\":%d,\"start\":%lld,"
      "\"result\":%d,\"errno\":%d,\"unchanged\":%s}\n",
      atoi(argv[2]), original.fl.l_pid, original.fl.l_type, original.fl.l_whence,
      (long long)original.fl.l_start, result, error,
      memcmp(&request, &original, sizeof(request)) == 0 ? "true" : "false");
  return close(fd) != 0;
}
