/* Legacy task holds, hidden resume sends, and caller-exec cleanup.
 * Sign with tests/fixtures/user/darwin/src/ptrace_get_task_allow.plist. */
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_port.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t owned_child;
static void timed_out(int signal) {
  (void)signal;
  if (owned_child > 0)
    kill((pid_t)owned_child, SIGKILL);
  _exit(124);
}

static pid_t wait_one(pid_t pid, int *status) {
  pid_t got;
  do { got = waitpid(pid, status, 0); } while (got < 0 && errno == EINTR);
  return got;
}


static int holds(task_t task) {
  mach_task_basic_info_data_t info = {0};
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  kern_return_t kr = task_info(task, MACH_TASK_BASIC_INFO,
                               (task_info_t)&info, &count);
  return kr ? -1 : info.suspend_count;
}

static mach_port_t resume_port(void) {
  mach_port_name_array_t names;
  mach_port_type_array_t types;
  mach_msg_type_number_t names_count, types_count;
  if (mach_port_names(mach_task_self(), &names, &names_count,
                       &types, &types_count))
    return MACH_PORT_NULL;
  mach_port_t result = MACH_PORT_NULL;
  for (mach_msg_type_number_t i = 0; i < names_count; i++) {
    natural_t kind = 0;
    mach_vm_address_t object = 0;
    if ((types[i] & MACH_PORT_TYPE_SEND) &&
        !mach_port_kobject(mach_task_self(), names[i], &kind, &object) &&
        kind == 36) { /* IPC_OTYPE_TASK_RESUME in mach_debug/ipc_info.h. */
      result = names[i];
      break;
    }
  }
  vm_deallocate(mach_task_self(), (vm_address_t)names,
                 names_count * sizeof *names);
  vm_deallocate(mach_task_self(), (vm_address_t)types,
                 types_count * sizeof *types);
  return result;
}

static unsigned refs(mach_port_t port) {
  if (!MACH_PORT_VALID(port))
    return 0;
  mach_port_urefs_t count = 0;
  return mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND,
                             &count) ? 0 : count;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  signal(SIGUSR1, SIG_IGN);
  if (argc == 3 && !strcmp(argv[1], "wait")) {
    pid_t child = (pid_t)strtol(argv[2], NULL, 10);
    owned_child = child;
    mach_port_t token = resume_port();
    printf("exec-hidden=%d refs=%u\n", MACH_PORT_VALID(token), refs(token));
    while (MACH_PORT_VALID(token) && refs(token))
      mach_port_deallocate(mach_task_self(), token);
    /* The exec assertion is namespace retirement. Native ptrace-prepared
     * children can remain parked in read with zero user holds; ordinary
     * instruction progress is characterized by the separate tool probe. */
    int status;
    if (kill(child, SIGKILL) || wait_one(child, &status) != child)
      return 80;
    owned_child = 0;
    printf("cleanup-signal=%d\n", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return !(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  }
  int gate[2], ready[2], status = 0, outstanding = 0, result = 1;
  task_t task = MACH_PORT_NULL;
  if (pipe(gate) || pipe(ready))
    return 1;
  pid_t child = fork();
  if (child < 0)
    return 2;
  if (!child) {
    close(gate[1]);
    close(ready[0]);
    if (write(ready[1], "r", 1) != 1)
      _exit(83);
    close(ready[1]);
    char byte;
    ssize_t got;
    do { got = read(gate[0], &byte, 1); } while (got < 0 && errno == EINTR);
    _exit(got == 1 ? 42 : 81);
  }
  owned_child = child;
  close(gate[0]);
  close(ready[1]);
  char notification;
  ssize_t received;
  do { received = read(ready[0], &notification, 1); } while (received < 0 && errno == EINTR);
  close(ready[0]);
  if (received != 1)
    goto done;
  if (ptrace(PT_ATTACH, child, 0, 0) ||
      wait_one(child, &status) != child || !WIFSTOPPED(status) ||
      task_for_pid(mach_task_self(), child, &task) ||
      ptrace(PT_CONTINUE, child, (caddr_t)1, 0) ||
      kill(child, SIGUSR1) ||
      wait_one(child, &status) != child || !WIFSTOPPED(status) ||
      WSTOPSIG(status) != SIGUSR1 ||
      ptrace(PT_DETACH, child, (caddr_t)1, 0))
    goto done;
  /* Detach re-delivers SIGUSR1, which is ignored. Detaching from SIGSTOP
   * would race a new job-control hold against the legacy hold assertions. */
  printf("initial holds=%d\n", holds(task));
  for (int i = 1; i <= 2; i++) {
    kern_return_t kr = task_suspend(task);
    if (!kr)
      outstanding++;
    int observed = holds(task);
    printf("suspend%d=%d holds=%d\n", i, kr, observed);
    if (kr || observed != i)
      goto done;
  }
  mach_port_t token = resume_port();
  printf("hidden=%d refs=%u\n", MACH_PORT_VALID(token), refs(token));
  if (!MACH_PORT_VALID(token) || refs(token) != 2)
    goto done;
  if (argc > 1 && !strcmp(argv[1], "exec")) {
    char pid[32];
    snprintf(pid, sizeof pid, "%d", child);
    char *args[] = {argv[0], "wait", pid, NULL};
    execv(argv[0], args);
    goto done;
  }
  if (mach_port_deallocate(mach_task_self(), token))
    goto done;
  printf("one-left=%u holds=%d\n", refs(token), holds(task));
  if (refs(token) != 1 || holds(task) != 2 ||
      mach_port_deallocate(mach_task_self(), token))
    goto done;
  int count = -1;
  for (int i = 0; i < 10000; i++) {
    count = holds(task);
    if (!count)
      break;
    usleep(1000);
  }
  printf("last-send holds=%d resume-empty=%d\n", count, task_resume(task));
  if (count || kill(child, SIGKILL) || wait_one(child, &status) != child)
    goto done;
  outstanding = 0;
  owned_child = 0;
  printf("cleanup-signal=%d\n", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
  result = !(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
done:
  if (result) {
    while (outstanding-- > 0)
      task_resume(task);
    kill(child, SIGKILL);
    ptrace(PT_KILL, child, (caddr_t)1, 0);
    wait_one(child, NULL);
  }
  return result;
}
