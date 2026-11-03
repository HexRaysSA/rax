#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

struct operation { int fd; atomic_int entered, done; int result, error; };
static atomic_int handled;
static void handler(int signal) { (void)signal; atomic_store(&handled, 1); }
static void *read_entry(void *raw) {
  struct operation *op = raw; char byte;
  atomic_store(&op->entered, 1); errno = 0;
  op->result = (int)read(op->fd, &byte, 1); op->error = errno;
  atomic_store(&op->done, 1); return NULL;
}
static void *close_entry(void *raw) {
  struct operation *op = raw;
  atomic_store(&op->entered, 1); errno = 0;
  op->result = close(op->fd); op->error = errno;
  atomic_store(&op->done, 1); return NULL;
}
static int await_state(pthread_t thread, struct operation *op, int state) {
  for (int attempt = 0; attempt < 2000; ++attempt) {
    thread_basic_info_data_t info; mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (atomic_load(&op->entered) && thread_info(pthread_mach_thread_np(thread),
        THREAD_BASIC_INFO, (thread_info_t)&info, &count) == KERN_SUCCESS && info.run_state == state)
      return 1;
    if (atomic_load(&op->done)) return 0;
    usleep(1000);
  }
  return -1;
}
int main(int argc, char **argv) {
  if (argc != 2 || mkfifo(argv[1], 0600)) return 2;
  struct sigaction action = {.sa_handler = handler}; sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL)) return 3;
  int rd = open(argv[1], O_RDONLY | O_NONBLOCK), wr = open(argv[1], O_WRONLY | O_NONBLOCK);
  if (rd < 0 || wr < 0 || unlink(argv[1]) || fcntl(rd, F_SETFL, 0)) return 4;
  struct operation reading = {.fd = rd}, closing = {.fd = rd}; pthread_t reader, closer;
  if (pthread_create(&reader, NULL, read_entry, &reading)) return 5;
  int read_wait = await_state(reader, &reading, TH_STATE_WAITING);
  if (thread_suspend(pthread_mach_thread_np(reader))) return 6;
  if (pthread_create(&closer, NULL, close_entry, &closing)) return 7;
  int close_wait = await_state(closer, &closing, TH_STATE_UNINTERRUPTIBLE);
  int sent = pthread_kill(reader, SIGUSR1);
  for (int attempt = 0; attempt < 1000 && !atomic_load(&closing.done); ++attempt) usleep(1000);
  int close_completed_held = atomic_load(&closing.done);
  int read_completed_held = atomic_load(&reading.done), handler_held = atomic_load(&handled);
  close(wr);
  if (thread_resume(pthread_mach_thread_np(reader))) return 8;
  pthread_join(reader, NULL); pthread_join(closer, NULL);
  printf("{\"read_wait\":%d,\"close_wait\":%d,\"signal_sent\":%d,"
         "\"close_completed_while_reader_held\":%d,\"read_user_done_while_held\":%d,"
         "\"handler_while_held\":%d,\"read_result\":%d,\"read_errno\":%d,"
         "\"close_result\":%d,\"close_errno\":%d,\"handler_after_resume\":%d}\n",
         read_wait, close_wait, sent, close_completed_held, read_completed_held, handler_held,
         reading.result, reading.error, closing.result, closing.error, atomic_load(&handled));
  return 0;
}
