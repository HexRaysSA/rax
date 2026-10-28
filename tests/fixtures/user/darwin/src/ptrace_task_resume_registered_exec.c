/* Retain a foreign resume send across the tracer's exec. */
#define main primitive_main
#include "ptrace_task_suspend.c"
#undef main

static int finish_child(pid_t child) {
  if (kill(child, SIGKILL))
    return 1;
  int status;
  for (;;) {
    pid_t got;
    do { got = waitpid(child, &status, WUNTRACED); } while (got < 0 && errno == EINTR);
    if (got != child)
      return 2;
    if (!WIFSTOPPED(status))
      break;
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
      return 3;
  }
  owned_child = 0;
  printf("cleanup-signal=%d\n", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
  return !(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  if (argc == 3 && !strcmp(argv[1], "wait")) {
    pid_t child = (pid_t)strtol(argv[2], NULL, 10);
    owned_child = child;
    mach_port_array_t ports = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t lookup = mach_ports_lookup(mach_task_self(), &ports, &count);
    natural_t kind = 0;
    mach_vm_address_t object = 0;
    if (!lookup && count && MACH_PORT_VALID(ports[0]))
      mach_port_kobject(mach_task_self(), ports[0], &kind, &object);
    printf("lookup=%d count=%u kind=%u refs=%u\n", lookup, count, kind,
           !lookup && count ? refs(ports[0]) : 0);
    if (lookup || count != 3 || kind != 36 || refs(ports[0]) != 1)
      return 4;
    kern_return_t clear = mach_ports_register(mach_task_self(), NULL, 0);
    printf("clear=%d\n", clear);
    if (clear)
      return 5;
    for (mach_msg_type_number_t i = 0; i < count; i++)
      if (MACH_PORT_VALID(ports[i]))
        mach_port_deallocate(mach_task_self(), ports[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)ports, count * sizeof *ports);
    return finish_child(child);
  }
  int gate[2], ready[2], status;
  if (pipe(gate) || pipe(ready))
    return 6;
  pid_t child = fork();
  if (child < 0)
    return 7;
  if (!child) {
    close(gate[1]);
    close(ready[0]);
    if (write(ready[1], "r", 1) != 1)
      _exit(80);
    close(ready[1]);
    char byte;
    for (;;) {
      ssize_t got = read(gate[0], &byte, 1);
      if (got >= 0)
        _exit(81);
      if (errno != EINTR)
        _exit(82);
    }
  }
  owned_child = child;
  close(gate[0]);
  close(ready[1]);
  char byte;
  ssize_t got;
  do { got = read(ready[0], &byte, 1); } while (got < 0 && errno == EINTR);
  close(ready[0]);
  task_t target = MACH_PORT_NULL;
  if (got != 1 || ptrace(PT_ATTACH, child, 0, 0) ||
      wait_one(child, &status) != child || !WIFSTOPPED(status) ||
      task_for_pid(mach_task_self(), child, &target) ||
      ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
    goto fail;
  for (int i = 0; i < 2; i++)
    if (task_suspend(target))
      goto fail;
  mach_port_t token = resume_port();
  kern_return_t registered = mach_ports_register(mach_task_self(), &token, 1);
  printf("register=%d holds=%d refs=%u\n", registered, holds(target), refs(token));
  if (registered || holds(target) != 2 || refs(token) != 2)
    goto fail;
  char pid[32];
  snprintf(pid, sizeof pid, "%d", child);
  char *args[] = {argv[0], "wait", pid, NULL};
  execv(argv[0], args);
fail:
  finish_child(child);
  return 8;
}
