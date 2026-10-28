/* Resume sends retained in registered ports across caller exec. This probe
 * obtains a task port directly, independently of ptrace signal stops. */
#define main legacy_probe_main
#include "ptrace_task_suspend_probe.c"
#undef main

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(120);
  if (argc == 4 && !strcmp(argv[1], "wait")) {
    pid_t child = (pid_t)strtol(argv[2], NULL, 10);
    owned_child = child;
    int gate = (int)strtol(argv[3], NULL, 10);
    mach_port_array_t ports = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t lookup = mach_ports_lookup(mach_task_self(), &ports, &count);
    printf("lookup=%d count=%u first-live=%d\n", lookup, count,
           !lookup && count && MACH_PORT_VALID(ports[0]));
    task_t target = MACH_PORT_NULL;
    kern_return_t acquired = task_for_pid(mach_task_self(), child, &target);
    printf("exec-task=%d holds=%d\n", acquired, acquired ? -1 : holds(target));
    if (lookup || !count || !MACH_PORT_VALID(ports[0]) || acquired || holds(target) != 2)
      goto fail_exec;
    for (mach_msg_type_number_t i = 0; i < count; i++)
      if (MACH_PORT_VALID(ports[i]))
        mach_port_deallocate(mach_task_self(), ports[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)ports, count * sizeof *ports);
    kern_return_t clear = mach_ports_register(mach_task_self(), NULL, 0);
    int remaining = -1;
    for (int i = 0; i < 1000; i++) {
      remaining = holds(target);
      if (!remaining)
        break;
      usleep(1000);
    }
    printf("clear=%d holds=%d\n", clear, remaining);
    if (clear || remaining || write(gate, "x", 1) != 1)
      goto fail_exec;
    int status;
    if (wait_one(child, &status) != child)
      goto fail_exec;
    owned_child = 0;
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 42);
fail_exec:
    kill(child, SIGKILL);
    wait_one(child, NULL);
    return 1;
  }
  int gate[2], ready[2];
  if (pipe(gate) || pipe(ready))
    return 2;
  pid_t child = fork();
  if (child < 0)
    return 3;
  if (!child) {
    close(gate[1]);
    close(ready[0]);
    if (write(ready[1], "r", 1) != 1)
      _exit(80);
    close(ready[1]);
    char byte;
    ssize_t got;
    do { got = read(gate[0], &byte, 1); } while (got < 0 && errno == EINTR);
    _exit(got == 1 ? 42 : 81);
  }
  owned_child = child;
  close(gate[0]);
  close(ready[1]);
  char byte;
  ssize_t got;
  do { got = read(ready[0], &byte, 1); } while (got < 0 && errno == EINTR);
  close(ready[0]);
  task_t target = MACH_PORT_NULL;
  if (got != 1 || task_for_pid(mach_task_self(), child, &target))
    goto fail;
  for (int i = 0; i < 2; i++)
    if (task_suspend(target))
      goto fail;
  mach_port_t token = resume_port();
  kern_return_t registered = mach_ports_register(mach_task_self(), &token, 1);
  printf("register=%d holds=%d refs=%u\n", registered, holds(target), refs(token));
  if (registered || holds(target) != 2 || refs(token) != 2)
    goto fail;
  char pid[32], descriptor[32];
  snprintf(pid, sizeof pid, "%d", child);
  snprintf(descriptor, sizeof descriptor, "%d", gate[1]);
  char *args[] = {argv[0], "wait", pid, descriptor, NULL};
  execv(argv[0], args);
fail:
  kill(child, SIGKILL);
  wait_one(child, NULL);
  return 1;
}
