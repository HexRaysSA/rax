/* Interaction of ptrace's normal hold and legacy task suspension. */
#define main legacy_probe_main
#include "ptrace_task_suspend.c"
#undef main

int main(void) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(20);
  int gate[2], ready[2], status = 0, result = 1;
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
  close(gate[0]);
  owned_child = child;
  close(ready[1]);
  char notification;
  ssize_t received;
  do { received = read(ready[0], &notification, 1); } while (received < 0 && errno == EINTR);
  close(ready[0]);
  if (received != 1)
    goto done;
  if (ptrace(PT_ATTACH, child, 0, 0) ||
      wait_one(child, &status) != child || !WIFSTOPPED(status) ||
      task_for_pid(mach_task_self(), child, &task))
    goto done;
  printf("traced holds=%d\n", holds(task));
  kern_return_t suspended = task_suspend(task);
  mach_port_t token = resume_port();
  printf("suspend=%d holds=%d refs=%u\n", suspended, holds(task), refs(token));
  if (suspended)
    goto done;
  if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
    goto done;
  printf("continued holds=%d refs=%u\n", holds(task), refs(token));
  kern_return_t resumed = task_resume(task);
  printf("resume=%d holds=%d refs=%u\n", resumed, holds(task), refs(token));
  if (resumed || write(gate[1], "x", 1) != 1 || wait_one(child, &status) != child)
    goto done;
  printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  result = !(WIFEXITED(status) && WEXITSTATUS(status) == 42);
  owned_child = 0;
done:
  if (result) {
    kill(child, SIGKILL);
    ptrace(PT_KILL, child, (caddr_t)1, 0);
    wait_one(child, NULL);
  }
  return result;
}
