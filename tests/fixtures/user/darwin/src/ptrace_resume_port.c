/* The native resume port accepts task_resume2 through a legacy send right
 * when a raw kobject call uses COPY_SEND or MOVE_SEND. The typed task_resume2 client uses
 * MOVE_SEND_ONCE. This isolates the shared port's dispatch semantics. */
#define main token_probe_main
#include "ptrace_task_suspend2.c"
#undef main

#ifndef RESUME_PORT_MAIN
#define RESUME_PORT_MAIN main
#endif

static mach_port_t resume_send(void) {
  mach_port_name_array_t names = NULL;
  mach_port_type_array_t types = NULL;
  mach_msg_type_number_t nc = 0, tc = 0;
  if (mach_port_names(mach_task_self(), &names, &nc, &types, &tc))
    return MACH_PORT_NULL;
  mach_port_t result = MACH_PORT_NULL;
  for (unsigned i = 0; i < nc; ++i) {
    natural_t kind = 0;
    mach_vm_address_t object = 0;
    if ((types[i] & MACH_PORT_TYPE_SEND) &&
        !mach_port_kobject(mach_task_self(), names[i], &kind, &object) && kind == 36) {
      result = names[i];
      break;
    }
  }
  vm_deallocate(mach_task_self(), (vm_address_t)names, nc * sizeof *names);
  vm_deallocate(mach_task_self(), (vm_address_t)types, tc * sizeof *types);
  return result;
}

int RESUME_PORT_MAIN(int argc, char **argv) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  int ready[2], gate[2], status;
  if (pipe(ready) || pipe(gate)) return 1;
  pid_t child = fork();
  if (child < 0) return 1;
  if (!child) {
    close(ready[0]);
    close(gate[1]);
    if (write(ready[1], "r", 1) != 1) _exit(80);
    close(ready[1]);
    char byte;
    ssize_t n;
    do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
    _exit(n == 1 ? 42 : 81);
  }
  owned_child = child;
  close(ready[1]);
  close(gate[0]);
  char byte;
  if (read(ready[0], &byte, 1) != 1) goto fail;
  close(ready[0]);
  task_t task = MACH_PORT_NULL;
  kern_return_t grant = task_for_pid(mach_task_self(), child, &task);
  printf("task=%d\n", grant);
  if (grant || task_suspend(task)) goto fail;
  mach_port_t resume = resume_send(), reply = MACH_PORT_NULL;
  if (!resume || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply)) goto fail;
  struct {
    mach_msg_header_t header;
    NDR_record_t ndr;
    kern_return_t result;
    char spare[32];
  } message = {0};
  unsigned disposition = argc > 1 && strcmp(argv[1], "move") == 0
      ? MACH_MSG_TYPE_MOVE_SEND : MACH_MSG_TYPE_COPY_SEND;
  message.header.msgh_bits = MACH_MSGH_BITS(disposition, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  message.header.msgh_size = 24;
  message.header.msgh_remote_port = resume;
  message.header.msgh_local_port = reply;
  message.header.msgh_id = 3437;
  kern_return_t result = mach_msg2_internal(&message,
      0x0000000200000000ULL | MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT,
      (uint64_t)24 << 32 | message.header.msgh_bits,
      (uint64_t)reply << 32 | resume, (uint64_t)3437 << 32,
      (uint64_t)reply << 32, sizeof message, 2000);
  printf("legacy-send-call: receive=%#x result=%d count=%d\n",
         result, result ? 0 : message.result, holds(task));
  mach_port_deallocate(mach_task_self(), resume);
  mach_port_destroy(mach_task_self(), reply);
  if (write(gate[1], "g", 1) != 1) goto fail;
  pid_t got;
  do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
  owned_child = 0;
  printf("child-exit=%d\n", got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return !(got == child && WIFEXITED(status) && WEXITSTATUS(status) == 42);
fail:
  kill(child, SIGKILL);
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
  owned_child = 0;
  return 1;
}
