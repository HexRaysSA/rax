/* Observe out-of-band task_resume of an untraced job-control stop.
 * Build: clang -arch arm64 -O1 -Wall tools/darwin/ptrace_oob_job_probe.c -o
 * /tmp/ptrace-oob-job Sign with
 * tests/fixtures/user/darwin/src/ptrace_get_task_allow.plist. Both threads can execute
 * after the task hold drains; the main thread stays alive behind a second gate while
 * its THREAD_BASIC_INFO is queried. A stalled task is killed and reaped through its
 * untraced host signal path.
 */
#include <errno.h>
#ifdef JOB_CHECK_STATUS
#include <libproc.h>
#include <sys/proc_info.h>
#endif
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
struct shared {
  _Atomic uint64_t ticks;
  _Atomic uint64_t main_id;
  _Atomic unsigned after_stop;
  _Atomic unsigned run;
  _Atomic unsigned finish;
#ifdef JOB_CHECK_STATUS
  _Atomic unsigned caught;
  _Atomic unsigned self_status;
  _Atomic unsigned continued;
  _Atomic unsigned continued_status;
#endif
};
#ifdef JOB_CHECK_STATUS
static struct shared *observed;
static unsigned bsd_status(pid_t pid) {
  struct proc_bsdinfo info = {0};
  return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof info) == sizeof info
             ? info.pbi_status
             : 0;
}
static void caught_usr1(int sig) {
  (void)sig;
  atomic_store_explicit(&observed->caught, 1, memory_order_relaxed);
}
static void caught_cont(int sig) {
  (void)sig;
  atomic_store_explicit(&observed->continued, 1, memory_order_relaxed);
}
#endif
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
  for (;;)
    atomic_fetch_add_explicit(&s->ticks, 1, memory_order_relaxed);
  return NULL;
}
static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
/* Progress is a semantic observation, not a real-time guarantee. A debug
 * interpreter's default 2^20-instruction slice can exceed 2 s before another
 * guest thread or a pending signal gets a turn. Bound the observation at 60 s;
 * the independent 180 s alarm bounds the whole probe and its cleanup.
 */
#define PROGRESS_NS 60000000000ULL
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

int main(void) {
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
  atomic_init(&s->finish, 0);
#ifdef JOB_CHECK_STATUS
  atomic_init(&s->caught, 0);
  atomic_init(&s->self_status, 0);
  atomic_init(&s->continued, 0);
  atomic_init(&s->continued_status, 0);
  observed = s;
#endif
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
#ifdef JOB_CHECK_STATUS
    if (signal(SIGUSR1, caught_usr1) == SIG_ERR ||
        signal(SIGCONT, caught_cont) == SIG_ERR)
      _exit(87);
#endif
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, s))
      _exit(80);
    while (!atomic_load_explicit(&s->ticks, memory_order_relaxed)) {
    }

    if (write(ready[1], "r", 1) != 1)
      _exit(82);
    char byte;
    if (read(gate[0], &byte, 1) != 1)
      _exit(83);
    raise(SIGSTOP);
#ifdef JOB_CHECK_STATUS
    atomic_store_explicit(&s->self_status, bsd_status(getpid()), memory_order_relaxed);
#endif
    atomic_store_explicit(&s->after_stop, 1, memory_order_release);
    while (atomic_load_explicit(&s->ticks, memory_order_relaxed) == 1) {
    }
#ifdef JOB_CHECK_STATUS
    int reported_continue = 0;
#endif
    while (!atomic_load_explicit(&s->finish, memory_order_acquire)) {
#ifdef JOB_CHECK_STATUS
      if (!reported_continue &&
          atomic_load_explicit(&s->continued, memory_order_relaxed)) {
        atomic_store_explicit(&s->continued_status, bsd_status(getpid()),
                              memory_order_release);
        if (write(ready[1], "c", 1) != 1)
          _exit(88);
        reported_continue = 1;
      }
#endif
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
    got = waitpid(child, &status, WUNTRACED);
  } while (got < 0 && errno == EINTR);
  if (got != child || !WIFSTOPPED(status))
    goto fail;
  task_t task = MACH_PORT_NULL;
  kern_return_t grant = task_for_pid(mach_task_self(), child, &task);
  printf("stop=%d task=%d count=%d\n", WSTOPSIG(status), grant,
         grant ? -1 : hold_count(task));
  if (grant)
    goto fail;
#ifdef JOB_EXTRA_HOLD
  kern_return_t extra = task_suspend(task);
  printf("extra-hold=%d count=%d\n", extra, hold_count(task));
  if (extra)
    goto fail;
#endif
  uint64_t main_id = atomic_load_explicit(&s->main_id, memory_order_acquire);
  printf("main-before-resume=%d\n", main_state(task, main_id));
  uint64_t before = atomic_load_explicit(&s->ticks, memory_order_relaxed);
  kern_return_t resume = task_resume(task);
#ifdef JOB_EXTRA_HOLD
  printf("first-resume=%d count=%d main-state=%d\n", resume, hold_count(task),
         main_state(task, main_id));
  if (resume || hold_count(task) != 1)
    goto fail;
  resume = task_resume(task);
#endif
  atomic_store_explicit(&s->run, 1, memory_order_release);
  uint64_t end = now_ns() + PROGRESS_NS;
  while ((atomic_load_explicit(&s->ticks, memory_order_relaxed) == before ||
          !atomic_load_explicit(&s->after_stop, memory_order_acquire)) &&
         now_ns() < end)
    usleep(1000);
  printf("resume=%d count=%d worker-progress=%d main-after-stop=%u\n", resume,
         hold_count(task),
         atomic_load_explicit(&s->ticks, memory_order_relaxed) != before,
         atomic_load_explicit(&s->after_stop, memory_order_acquire));
  printf("main-after-resume=%d\n", main_state(task, main_id));
#ifdef JOB_CHECK_STATUS
  printf("bsd-status=%u,%u\n",
         atomic_load_explicit(&s->self_status, memory_order_relaxed),
         bsd_status(child));
  if (kill(child, SIGUSR1))
    goto fail;
  uint64_t signal_deadline = now_ns() + PROGRESS_NS;
  while (!atomic_load_explicit(&s->caught, memory_order_relaxed) &&
         now_ns() < signal_deadline)
    usleep(1000);
  printf("caught-after-job-resume=%u\n",
         atomic_load_explicit(&s->caught, memory_order_relaxed));
  if (kill(child, SIGCONT) || read(ready[0], &byte, 1) != 1 || byte != 'c')
    goto fail;
  printf("continued-status=%u,%u\n",
         atomic_load_explicit(&s->continued_status, memory_order_acquire),
         bsd_status(child));
#endif
#ifdef JOB_REPEAT_STOP
  if (kill(child, SIGSTOP))
    goto fail;
  usleep(50000);
  int repeated_count = hold_count(task);
  printf("repeat-stop-count=%d main-state=%d\n", repeated_count,
         main_state(task, main_id));
  if (repeated_count > 0 && task_resume(task))
    goto fail;
#endif
  int progressed = atomic_load_explicit(&s->after_stop, memory_order_acquire) != 0 &&
                   atomic_load_explicit(&s->ticks, memory_order_relaxed) != before;
  if (progressed)
    atomic_store_explicit(&s->finish, 1, memory_order_release);
  else
    kill(child, SIGKILL);
  printf("cleanup-progressed=%d\n", progressed);
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
