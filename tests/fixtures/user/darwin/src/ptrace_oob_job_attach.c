/* Attach after task_resume released a job stop and the child returned to user
 * instructions. Build with xcrun clang -arch arm64 -O1 -Wall, then sign with
 * tests/fixtures/user/darwin/src/ptrace_get_task_allow.plist.
 */
#include <errno.h>
#ifdef JOB_ATTACH_HELD
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
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
struct shared {
  _Atomic uint64_t main_id;
  _Atomic unsigned resumed;
  _Atomic unsigned finish;
};
static void timed_out(int signal) {
  (void)signal;
  if (tracee > 0)
    kill(tracee, SIGKILL);
  _exit(124);
}
static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int holds(task_t task) {
  task_basic_info_data_t info;
  mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
  return task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &count)
             ? -1
             : info.suspend_count;
}
static pid_t waited(pid_t pid, int *status, int options) {
  pid_t result;
  do {
    result = waitpid(pid, status, options);
  } while (result < 0 && errno == EINTR);
  return result;
}
static int parked(task_t task, uint64_t main_id) {
  thread_act_array_t threads = NULL;
  mach_msg_type_number_t count = 0;
  if (task_threads(task, &threads, &count))
    return 0;
  thread_t main = MACH_PORT_NULL;
  for (unsigned i = 0; i < count; ++i) {
    thread_identifier_info_data_t id;
    mach_msg_type_number_t n = THREAD_IDENTIFIER_INFO_COUNT;
    if (!thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&id, &n) &&
        id.thread_id == main_id)
      main = threads[i];
    else
      mach_port_deallocate(mach_task_self(), threads[i]);
  }
  vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof *threads);
  if (main == MACH_PORT_NULL)
    return 0;
  uint64_t deadline = now_ns() + 60000000000ULL;
  int settled = 0;
  do {
    int count = holds(task);
    thread_basic_info_data_t info;
    mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
    if (thread_info(main, THREAD_BASIC_INFO, (thread_info_t)&info, &n))
      break;
    /* kern_sig.c notifies the parent before assert_wait(p->sigwait).
     * Wait for the new hard-stop hold and its selected thread's wait before
     * continuing, so the oracle does not depend on that wakeup race.
     */
    settled = count == 1 && info.run_state == TH_STATE_WAITING;
    if (!settled)
      usleep(1000);
  } while (!settled && now_ns() < deadline);
  mach_port_deallocate(mach_task_self(), main);
  return settled;
}
int main(void) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  struct shared *s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANON, -1, 0);
  if (s == MAP_FAILED)
    return 1;
  atomic_init(&s->resumed, 0);
  atomic_init(&s->finish, 0);
  atomic_init(&s->main_id, 0);
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (!child) {
    uint64_t main_id;
    if (pthread_threadid_np(NULL, &main_id))
      _exit(81);
    atomic_store_explicit(&s->main_id, main_id, memory_order_release);
    raise(SIGSTOP);
    atomic_store_explicit(&s->resumed, 1, memory_order_release);
    while (!atomic_load_explicit(&s->finish, memory_order_acquire)) {
    }
    _exit(42);
  }
  tracee = child;
  int status;
  if (waited(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
    goto fail;
  task_t task = MACH_PORT_NULL;
  if (task_for_pid(mach_task_self(), child, &task))
    goto fail;
  if (!parked(task, atomic_load_explicit(&s->main_id, memory_order_acquire)))
    goto fail;
  printf("job-stop=%d holds=%d\n", WSTOPSIG(status), holds(task));
#ifdef JOB_ATTACH_HELD
  if (task_suspend(task))
    goto fail;
  printf("extra-hold=%d\n", holds(task));
#else
  if (task_resume(task))
    goto fail;
  uint64_t deadline = now_ns() + 60000000000ULL;
  while (!atomic_load_explicit(&s->resumed, memory_order_acquire) &&
         now_ns() < deadline)
    usleep(1000);
  printf("resumed=%u holds=%d\n",
         atomic_load_explicit(&s->resumed, memory_order_acquire), holds(task));
  if (!atomic_load_explicit(&s->resumed, memory_order_acquire))
    goto fail;
#endif
  errno = 0;
  int attached = ptrace(PT_ATTACH, child, 0, 0);
  printf("attach=%d errno=%d\n", attached, errno);
  if (attached)
    goto fail;
#ifdef JOB_ATTACH_HELD
  struct proc_bsdinfo info;
  if (proc_pidinfo(child, PROC_PIDTBSDINFO, 0, &info, sizeof info) != sizeof info)
    goto fail;
  printf("attached holds=%d state=%u xstatus=%u\n", holds(task), info.pbi_status,
         info.pbi_xstatus);
  if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
    goto fail;
  if (proc_pidinfo(child, PROC_PIDTBSDINFO, 0, &info, sizeof info) != sizeof info)
    goto fail;
  printf("continued holds=%d state=%u xstatus=%u\n", holds(task), info.pbi_status,
         info.pbi_xstatus);
  if (task_resume(task))
    goto fail;
#endif
  if (waited(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
    goto fail;
  printf("attach-stop=%d holds=%d\n", WSTOPSIG(status), holds(task));
  if (!parked(task, atomic_load_explicit(&s->main_id, memory_order_acquire)))
    goto fail;
  if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
    goto fail;
  atomic_store_explicit(&s->finish, 1, memory_order_release);
  pid_t got = waited(child, &status, 0);
  for (unsigned extra = 0; got == child && WIFSTOPPED(status) && extra < 4;
       ++extra) {
    if ((WSTOPSIG(status) != 0 && WSTOPSIG(status) != SIGSTOP) ||
        ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
      goto fail;
    got = waited(child, &status, 0);
  }
  if (got != child || !WIFEXITED(status))
    goto fail;
  tracee = 0;
  printf("child-exit=%d\n", WEXITSTATUS(status));
  return WEXITSTATUS(status) != 42;
fail:
  kill(child, SIGKILL);
  ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
  waited(child, &status, 0);
  tracee = 0;
  return 1;
}
