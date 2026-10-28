/* Attach to a child whose earlier job stop has already been waited. */
#include <errno.h>
#include <signal.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;

static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
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

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int self_stop = argc > 1 && strcmp(argv[1], "self") == 0;
    int sigexc = argc > 1 && strcmp(argv[1], "sigexc") == 0;
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        char byte;
        uint64_t main_id;
        if (pthread_threadid_np(NULL, &main_id) ||
            write(ready[1], &main_id, sizeof main_id) != sizeof main_id) _exit(90);
        if (self_stop) raise(SIGSTOP);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        _exit(n == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(180);
    close(ready[1]); close(gate[0]);
    uint64_t main_id;
    int status;
    if (read(ready[0], &main_id, sizeof main_id) != sizeof main_id || (!self_stop && kill(child, SIGSTOP)) ||
        waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status)) goto fail;
    printf("job-stop=%d\n", WSTOPSIG(status));
    task_t task = MACH_PORT_NULL;
    if (self_stop &&
        (task_for_pid(mach_task_self(), child, &task) || !parked(task, main_id)))
        goto fail;
    errno = 0;
    int attached = ptrace(sigexc ? PT_ATTACHEXC : PT_ATTACH, child, 0, 0);
    int attach_error = errno;
    printf("attach=%d errno=%d\n", attached, attach_error);
    if (attached) goto fail;
    if (self_stop) {
        int settled = parked(task, main_id);
        mach_port_deallocate(mach_task_self(), task);
        if (!settled) goto fail;
    }
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) || write(gate[1], "x", 1) != 1 ||
        waitpid(child, &status, 0) != child) goto fail;
    if (WIFSTOPPED(status)) {
        int signal = WSTOPSIG(status);
        if ((signal != 0 && signal != SIGSTOP) || ptrace(PT_CONTINUE, child, (caddr_t)1, 0) ||
            waitpid(child, &status, 0) != child) goto fail;
    }
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    tracee = 0;
    alarm(0);
    puts("failed");
    return 1;
}
