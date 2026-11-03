#define main timed_lock_matrix_main
#include "timed-lock-probe-v13.c"
#undef main
#include <mach/mach.h>
#include <mach/thread_info.h>
#include <pthread.h>
#include <stdatomic.h>

struct operation {
  int fd, command, result, error;
  struct flocktimeout request;
  atomic_int done;
};

static void *locking(void *raw) {
  struct operation *op = raw;
  errno = 0;
  op->result = fcntl(op->fd, op->command, &op->request);
  op->error = errno;
  atomic_store(&op->done, 1);
  return NULL;
}

static void *closing(void *raw) {
  struct operation *op = raw;
  errno = 0;
  op->result = close(op->fd);
  op->error = errno;
  atomic_store(&op->done, 1);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  int command = atoi(argv[2]), close_it = atoi(argv[3]), mutate = atoi(argv[4]);
  int holder = open(argv[1], O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  int fd = open(argv[1], O_RDWR | O_CLOEXEC);
  struct flock lock = {.l_start = 0, .l_len = 1, .l_type = F_WRLCK, .l_whence = SEEK_SET};
  if (holder < 0 || fd < 0 || fcntl(holder, 90, &lock))
    return 3;
  struct operation op = {.fd = fd, .command = command,
      .request = {.fl = lock, .timeout = {.tv_sec = 0, .tv_nsec = 200000000}}};
  pthread_t thread;
  if (pthread_create(&thread, NULL, locking, &op))
    return 4;
  int state = 0;
  for (int attempt = 0; attempt < 1000; ++attempt) {
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (thread_info(pthread_mach_thread_np(thread), THREAD_BASIC_INFO,
          (thread_info_t)&info, &count) == KERN_SUCCESS &&
        (info.run_state == TH_STATE_WAITING || info.run_state == TH_STATE_UNINTERRUPTIBLE)) {
      state = info.run_state;
      break;
    }
    if (atomic_load(&op.done))
      return 5;
    usleep(1000);
  }
  if (!state)
    return 6;
  if (mutate) {
    op.request.fl.l_type = 0;
    op.request.timeout.tv_nsec = 1;
  }
  struct operation closer = {.fd = fd};
  pthread_t close_thread;
  if (close_it && pthread_create(&close_thread, NULL, closing, &closer))
    return 7;
  usleep(10000);
  errno = 0;
  int flags = fcntl(fd, F_GETFD), flags_error = errno;
  int duplicate = dup(holder);
  int lock_done = atomic_load(&op.done), close_done = atomic_load(&closer.done);
  if (duplicate < 0 || close(duplicate))
    return 8;
  lock.l_type = F_UNLCK;
  if (fcntl(holder, 90, &lock) || pthread_join(thread, NULL))
    return 9;
  if (close_it && pthread_join(close_thread, NULL))
    return 10;
  printf("{\"kind\":\"timed-lock-lifetime\",\"state\":%d,\"lock_done_before_unlock\":%d,"
      "\"close_done_before_unlock\":%d,\"flags\":%d,\"flags_errno\":%d,"
      "\"original_fd\":%d,\"duplicate_fd\":%d,\"lock_result\":%d,\"lock_errno\":%d,"
      "\"close_result\":%d,\"close_errno\":%d}\n", state, lock_done, close_done,
      flags, flags_error, fd, duplicate, op.result, op.error, closer.result, closer.error);
  if ((!close_it && close(fd)) || close(holder))
    return 11;
  return 0;
}
