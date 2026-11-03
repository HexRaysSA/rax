#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct operation { int fd; atomic_int started, done; ssize_t result; int error; };
static void *reader(void *raw) {
  struct operation *op = raw;
  char byte;
  atomic_store(&op->started, 1);
  errno = 0;
  op->result = read(op->fd, &byte, 1);
  op->error = errno;
  atomic_store(&op->done, 1);
  return NULL;
}
int main(int argc, char **argv) {
  if (argc != 3 || mkfifo(argv[1], 0600)) return 2;
  int readfd = open(argv[1], O_RDONLY | O_NONBLOCK);
  int writefd = open(argv[1], O_WRONLY | O_NONBLOCK);
  if (readfd < 0 || writefd < 0 || unlink(argv[1]) || fcntl(readfd, F_SETFL, 0)) return 3;
  int before = fcntl(readfd, F_GETFL);
  struct operation op = {.fd = readfd};
  pthread_t thread;
  if (pthread_create(&thread, NULL, reader, &op)) return 4;
  mach_port_t port = pthread_mach_thread_np(thread);
  int waited = 0;
  for (int attempt = 0; attempt < 2000; ++attempt) {
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (atomic_load(&op.started) &&
        thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&info, &count) == KERN_SUCCESS &&
        info.run_state == TH_STATE_WAITING) { waited = 1; break; }
    if (atomic_load(&op.done)) break;
    usleep(1000);
  }
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int safely = atoi(argv[2]);
  kern_return_t aborted = safely ? thread_abort_safely(port) : thread_abort(port);
  for (int attempt = 0; attempt < 200; ++attempt) {
    if (atomic_load(&op.done)) break;
    usleep(1000);
  }
  int completed_by_abort = atomic_load(&op.done);
  clock_gettime(CLOCK_MONOTONIC, &end);
  close(writefd);
  if (pthread_join(thread, NULL)) return 5;
  printf("{\"waiting_before\":%d,\"safe_abort\":%d,\"abort_return\":%d,"
         "\"completed_by_abort\":%d,\"read_result\":%zd,\"read_errno\":%d,"
         "\"flags_before\":%d,\"flags_after\":%d,\"seconds\":%.9f}\n",
         waited, safely, aborted, completed_by_abort, op.result, op.error,
         before, fcntl(readfd, F_GETFL),
         (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9);
  close(readfd);
  return 0;
}
