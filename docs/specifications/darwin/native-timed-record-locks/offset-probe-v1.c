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

static int query(int fd, off_t start) {
  struct flock lock = {.l_start = start, .l_len = 1,
      .l_type = F_WRLCK, .l_whence = SEEK_SET};
  if (fcntl(fd, 92, &lock))
    return -1;
  return lock.l_type;
}

int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  int command = atoi(argv[2]), whence = atoi(argv[3]);
  off_t original = whence == SEEK_CUR ? 16 : 64;
  off_t changed = whence == SEEK_CUR ? 32 : 96;
  int holder = open(argv[1], O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  int target = open(argv[1], O_RDWR | O_CLOEXEC);
  int inspector = open(argv[1], O_RDWR | O_CLOEXEC);
  struct flock held = {.l_start = original, .l_len = 1,
      .l_type = F_WRLCK, .l_whence = SEEK_SET};
  if (holder < 0 || target < 0 || inspector < 0 || ftruncate(holder, 64) ||
      lseek(target, 16, SEEK_SET) != 16 || fcntl(holder, 90, &held))
    return 3;
  struct operation op = {.fd = target, .command = command,
      .request = {.fl = {.l_start = 0, .l_len = 1, .l_type = F_WRLCK,
          .l_whence = (short)whence}, .timeout = {.tv_sec = 2, .tv_nsec = 0}}};
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
  if (whence == SEEK_CUR) {
    if (lseek(target, changed, SEEK_SET) != changed)
      return 7;
  } else if (ftruncate(holder, changed)) {
    return 8;
  }
  held.l_type = F_UNLCK;
  if (fcntl(holder, 90, &held) || pthread_join(thread, NULL))
    return 9;
  int old_type = query(inspector, original), new_type = query(inspector, changed);
  printf("{\"command\":%d,\"whence\":%d,\"original_offset\":%lld,\"changed_offset\":%lld,"
      "\"result\":%d,\"errno\":%d,\"original_lock_type\":%d,\"changed_lock_type\":%d,"
      "\"entry_state\":%d,\"request_start\":%lld,\"request_whence\":%d}\n",
      command, whence, (long long)original, (long long)changed, op.result, op.error,
      old_type, new_type, state, (long long)op.request.fl.l_start, op.request.fl.l_whence);
  if (close(inspector) || close(target) || close(holder))
    return 10;
  return 0;
}
