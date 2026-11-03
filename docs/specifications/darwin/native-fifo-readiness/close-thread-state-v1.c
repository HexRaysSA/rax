#define main policy_probe_main_v2
#include "policy-probe-v2.c"
#undef main
#include <mach/thread_info.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <sys/stat.h>

typedef ssize_t (*vector_fn)(int, const uint64_t *, const struct iovec *, int);
typedef int (*change_fn)(int, const uint64_t *, unsigned,
                         const uint64_t *, unsigned, int *);

struct operation {
  int fd, vector;
  uint64_t cookie;
  char first, alternate;
  struct iovec iovec;
  write_fn scalar_write;
  vector_fn vector_write;
  close_fn guarded_close;
  atomic_int started, done;
  ssize_t value;
  int error;
};

static void *write_thread(void *raw) {
  struct operation *op = raw;
  atomic_store(&op->started, 1);
  errno = 0;
  op->value = op->vector
      ? op->vector_write(op->fd, &op->cookie, &op->iovec, 1)
      : op->scalar_write(op->fd, &op->cookie, &op->first, 1);
  op->error = errno;
  atomic_store(&op->done, 1);
  return NULL;
}

static void *close_thread(void *raw) {
  struct operation *op = raw;
  atomic_store(&op->started, 1);
  errno = 0;
  op->value = op->guarded_close(op->fd, &op->cookie);
  op->error = errno;
  atomic_store(&op->done, 1);
  return NULL;
}

/* The worker has no other blocking operation after publishing started. */
static int waiting(pthread_t thread, struct operation *op) {
  for (int attempt = 0; attempt < 5000; ++attempt) {
    if (atomic_load(&op->done))
      return 0;
    if (atomic_load(&op->started)) {
      thread_basic_info_data_t info;
      mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
      kern_return_t error = thread_info(pthread_mach_thread_np(thread),
          THREAD_BASIC_INFO, (thread_info_t)&info, &count);
      static int last_close_state = -1;
      if (error == KERN_SUCCESS && !op->scalar_write && info.run_state != last_close_state) {
        result("close-thread-run-state", info.run_state, info.flags);
        last_close_state = info.run_state;
      }
      if (error == KERN_SUCCESS && info.run_state == TH_STATE_WAITING)
        return 1;
    }
    usleep(1000);
  }
  return -1;
}

int main(int argc, char **argv) {
  if (argc != 6)
    return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    return 2;
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core))
    return 3;
  int pipefd[2];
  if (strcmp(argv[4], "pipe") == 0) {
    if (pipe(pipefd))
      return 4;
  } else {
    if (mkfifo(argv[5], 0600))
      return 4;
    pipefd[0] = open(argv[5], O_RDONLY | O_NONBLOCK);
    pipefd[1] = open(argv[5], O_WRONLY | O_NONBLOCK);
    if (pipefd[0] < 0 || pipefd[1] < 0 || unlink(argv[5]))
      return 4;
  }
  if (fcntl(pipefd[0], F_SETFL, 0) || fcntl(pipefd[1], F_SETFL, O_NONBLOCK))
    return 4;
  char bytes[4096];
  memset(bytes, '.', sizeof(bytes));
  ssize_t total = 0, count;
  while ((count = write(pipefd[1], bytes, sizeof(bytes))) > 0) {
    total += count;
    if (total > 1024 * 1024)
      return 5;
  }
  if (count != -1 || errno != EAGAIN || fcntl(pipefd[1], F_SETFL, 0))
    return 6;
  struct operation writer = {.fd = pipefd[1], .vector = atoi(argv[1]),
      .cookie = UINT64_C(0x1122334455667788), .first = 'A', .alternate = 'B'};
  writer.iovec = (struct iovec){.iov_base = &writer.first, .iov_len = 1};
  writer.scalar_write = (write_fn)dlsym(RTLD_DEFAULT, "guarded_write_np");
  writer.vector_write = (vector_fn)dlsym(RTLD_DEFAULT, "guarded_writev_np");
  writer.guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  change_fn change = (change_fn)dlsym(RTLD_DEFAULT, "change_fdguard_np");
  if (!writer.scalar_write || !writer.vector_write || !writer.guarded_close || !change)
    return 7;
  if (change(writer.fd, NULL, 0, &writer.cookie, 19, NULL))
    return 8;
  result("initial-fd-flags", fcntl(writer.fd, F_GETFD), 0);
  pthread_t writing;
  if (pthread_create(&writing, NULL, write_thread, &writer))
    return 9;
  int blocked = waiting(writing, &writer);
  result("writer-was-blocked", blocked, 0);
  if (blocked != 1)
    return 10;
  int mutation = atoi(argv[3]);
  if (mutation & 1)
    writer.cookie = UINT64_C(0x8877665544332211);
  if (mutation & 2)
    writer.iovec.iov_base = &writer.alternate;
  int concurrent_close = atoi(argv[2]);
  struct operation closer = {.fd = writer.fd,
      .cookie = UINT64_C(0x1122334455667788), .guarded_close = writer.guarded_close};
  pthread_t closing;
  if (concurrent_close) {
    if (pthread_create(&closing, NULL, close_thread, &closer))
      return 11;
    result("closer-was-blocked", waiting(closing, &closer), 0);
    errno = 0;
    int flags = fcntl(writer.fd, F_GETFD);
    result("during-close-fd-flags", flags, errno);
    int duplicate = dup(pipefd[0]);
    result("during-close-duplicate", duplicate, 0);
    if (duplicate < 0 || close(duplicate))
      return 12;
  }
  ssize_t first = read(pipefd[0], bytes, sizeof(bytes));
  if (first <= 0 || pthread_join(writing, NULL))
    return 13;
  result("write-result", writer.value, writer.error);
  if (concurrent_close) {
    if (pthread_join(closing, NULL))
      return 14;
    result("close-result", closer.value, closer.error);
  } else if (writer.guarded_close(writer.fd, &closer.cookie)) {
    return 15;
  }
  ssize_t received = first;
  int last = bytes[first - 1];
  while ((count = read(pipefd[0], bytes, sizeof(bytes))) > 0) {
    received += count;
    last = bytes[count - 1];
  }
  result("received-bytes", received, 0);
  result("filled-bytes", total, 0);
  result("last-byte", last, 0);
  if (count || close(pipefd[0]))
    return 16;
  return 0;
}
