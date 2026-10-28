/* Observe task_resume while one traced thread remains in BSD sigwait.
 * Build: clang -arch arm64 -O1 -Wall -Wno-deprecated-declarations
 * tools/darwin/ptrace_oob_resume_probe.c -o /tmp/ptrace-oob-resume
 * Sign with tests/fixtures/user/darwin/src/ptrace_get_task_allow.plist.
 * A shared counter proves interprocess visibility before the trace stop.
 * Pass "signal" to make the worker raise SIGUSR1 while the first stop waits,
 * or "sigexc" to enable PT_SIGEXC without replacing the original hard wait.
 * Diagnostic output, rather than exit status alone, is the observation.
 */
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t owned_child;
static int worker_action;
struct shared {
  _Atomic uint64_t ticks;
  _Atomic uint64_t main_id;
  _Atomic unsigned after_stop;
  _Atomic unsigned run;
};
static void timed_out(int sig) {
  (void)sig;
  if (owned_child > 0)
    kill(owned_child, SIGKILL);
  _exit(124);
}
static void *worker(void *arg) {
  struct shared *s = arg;
  atomic_store_explicit(&s->ticks, 1, memory_order_release);
  while (!atomic_load_explicit(&s->run, memory_order_acquire)) {
  }
  if (worker_action == 1)
    raise(SIGUSR1);
  if (worker_action == 2 && ptrace(PT_SIGEXC, 0, NULL, 0))
    _exit(85);
  for (;;)
    atomic_fetch_add_explicit(&s->ticks, 1, memory_order_relaxed);
  return NULL;
}
static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int hold_count(task_t task) {
  task_basic_info_data_t info;
  mach_msg_type_number_t n = TASK_BASIC_INFO_COUNT;
  return task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &n) ? -1
                                                                  : info.suspend_count;
}
static int main_state(task_t task, uint64_t main_id) {
  thread_act_array_t threads = NULL;
  mach_msg_type_number_t count = 0;
  if (task_threads(task, &threads, &count))
    return -1;
  int state = -1;
  for (unsigned i = 0; i < count; ++i) {
    thread_identifier_info_data_t id;
    mach_msg_type_number_t n = THREAD_IDENTIFIER_INFO_COUNT;
    if (!thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&id, &n) &&
        id.thread_id == main_id) {
      thread_basic_info_data_t basic;
      n = THREAD_BASIC_INFO_COUNT;
      if (!thread_info(threads[i], THREAD_BASIC_INFO, (thread_info_t)&basic, &n))
        state = basic.run_state;
    }
    mach_port_deallocate(mach_task_self(), threads[i]);
  }
  vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof *threads);
  return state;
}

#ifndef OOB_RESUME_MAIN
#define OOB_RESUME_MAIN main
#endif

int OOB_RESUME_MAIN(int argc, char **argv) {
  worker_action = argc > 1 && strcmp(argv[1], "signal") == 0   ? 1
                  : argc > 1 && strcmp(argv[1], "sigexc") == 0 ? 2
                                                               : 0;
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  struct shared *s =
      mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (s == MAP_FAILED)
    return 1;
  atomic_init(&s->ticks, 0);
  atomic_init(&s->main_id, 0);
  atomic_init(&s->after_stop, 0);
  atomic_init(&s->run, 0);
  int ready[2], gate[2], status;
  if (pipe(ready) || pipe(gate))
    return 1;
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (!child) {
    close(ready[0]);
    close(gate[1]);
    uint64_t main_id = 0;
    if (pthread_threadid_np(NULL, &main_id))
      _exit(84);
    atomic_store_explicit(&s->main_id, main_id, memory_order_release);
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, s))
      _exit(80);
    while (!atomic_load_explicit(&s->ticks, memory_order_relaxed)) {
    }
    if (ptrace(PT_TRACE_ME, 0, NULL, 0))
      _exit(81);
    if (write(ready[1], "r", 1) != 1)
      _exit(82);
    char byte;
    if (read(gate[0], &byte, 1) != 1)
      _exit(83);
    raise(SIGSTOP);
    atomic_store_explicit(&s->after_stop, 1, memory_order_relaxed);
    while (atomic_load_explicit(&s->ticks, memory_order_relaxed) == 1) {
    }
    _exit(42);
  }
  owned_child = child;
  close(ready[1]);
  close(gate[0]);
  char byte;
  if (read(ready[0], &byte, 1) != 1)
    goto fail;
  printf("shared-visible=%d\n",
         atomic_load_explicit(&s->ticks, memory_order_relaxed) != 0);
  if (!atomic_load_explicit(&s->ticks, memory_order_relaxed))
    goto fail;
  if (write(gate[1], "g", 1) != 1)
    goto fail;
  pid_t got;
  do {
    got = waitpid(child, &status, 0);
  } while (got < 0 && errno == EINTR);
  if (got != child || !WIFSTOPPED(status))
    goto fail;
  task_t task = MACH_PORT_NULL;
  kern_return_t grant = task_for_pid(mach_task_self(), child, &task);
  printf("stop=%d task=%d count=%d\n", WSTOPSIG(status), grant,
         grant ? -1 : hold_count(task));
  if (grant)
    goto fail;
  uint64_t main_id = atomic_load_explicit(&s->main_id, memory_order_acquire);
  printf("main-before-resume=%d\n", main_state(task, main_id));
  uint64_t before = atomic_load_explicit(&s->ticks, memory_order_relaxed);
  kern_return_t resume = task_resume(task);
  atomic_store_explicit(&s->run, 1, memory_order_release);
  uint64_t end = now_ns() + 2000000000ULL;
  while (atomic_load_explicit(&s->ticks, memory_order_relaxed) == before &&
         now_ns() < end)
    usleep(1000);
  printf("resume=%d count=%d worker-progress=%d main-after-stop=%u\n", resume,
         hold_count(task),
         atomic_load_explicit(&s->ticks, memory_order_relaxed) != before,
         atomic_load_explicit(&s->after_stop, memory_order_relaxed));
  printf("main-after-resume=%d\n", main_state(task, main_id));
  int continued = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
  printf("continue=%d\n", continued);
  if (continued)
    goto fail;
  do {
    got = waitpid(child, &status, 0);
  } while (got < 0 && errno == EINTR);
  if (got == child && WIFSTOPPED(status)) {
    printf("next-stop=%d\n", WSTOPSIG(status));
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
      goto fail;
    do {
      got = waitpid(child, &status, 0);
    } while (got < 0 && errno == EINTR);
  }
  owned_child = 0;
  printf("child-exit=%d\n",
         got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return !(got == child && WIFEXITED(status) && WEXITSTATUS(status) == 42);
fail:
  kill(child, SIGKILL);
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
  }
  owned_child = 0;
  return 1;
}
