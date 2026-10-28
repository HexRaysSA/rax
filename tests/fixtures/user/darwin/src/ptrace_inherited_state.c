/* A debugger-owned task exception handler inherited by a forked grandchild.
 * Ad-hoc sign with ptrace_get_task_allow.plist before running. */
#include <mach/exc.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static uint32_t word(const unsigned char *p) {
  uint32_t value;
  memcpy(&value, p, sizeof value);
  return value;
}

static pid_t wait_one(pid_t pid, int *status, int flags) {
  pid_t got;
  do { got = waitpid(pid, status, flags); } while (got < 0 && errno == EINTR);
  return got;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  if (argc == 3 && !strcmp(argv[1], "relay")) {
    int status;
    pid_t child = (pid_t)strtol(argv[2], NULL, 10);
    if (wait_one(child, &status, 0) != child || !WIFEXITED(status))
      return 94;
    return WEXITSTATUS(status);
  }
  int exec_parent = argc > 1 && !strcmp(argv[1], "exec");
  int direct = argc > 1 && !strcmp(argv[1], "direct");
  int ready[2], gate[2], control[2];
  if (pipe(ready) || pipe(gate) || pipe(control))
    return 1;
  pid_t target = fork();
  if (target < 0)
    return 2;
  if (!target) {
    close(ready[0]);
    close(gate[1]);
    close(control[1]);
    if (setpgid(0, 0) || write(ready[1], "r", 1) != 1)
      _exit(90);
    char byte;
    ssize_t n;
    do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
    if (n != 1)
      _exit(91);
    printf("released\n");
    pid_t grandchild = direct ? 0 : fork();
    if (grandchild < 0)
      _exit(92);
    if (!grandchild) {
      exception_mask_t masks[EXC_TYPES_COUNT];
      mach_port_t ports[EXC_TYPES_COUNT];
      exception_behavior_t behaviors[EXC_TYPES_COUNT];
      thread_state_flavor_t flavors[EXC_TYPES_COUNT];
      mach_msg_type_number_t count = EXC_TYPES_COUNT;
      kern_return_t checked = task_get_exception_ports(mach_task_self(),
          EXC_MASK_BREAKPOINT, masks, &count, ports, behaviors, flavors);
      printf("inherited=%d present=%d behavior=%d\n", checked,
             !checked && count == 1 && MACH_PORT_VALID(ports[0]),
             !checked && count == 1 ? behaviors[0] : -1);
#if defined(__arm64__)
      __asm__ volatile("brk #0x123");
#else
      __asm__ volatile("int3");
#endif
      _exit(42);
    }
    if (exec_parent) {
      do { n = read(control[0], &byte, 1); } while (n < 0 && errno == EINTR);
      if (n != 1)
        _exit(95);
      char pid[32];
      snprintf(pid, sizeof pid, "%d", grandchild);
      char *args[] = {argv[0], "relay", pid, NULL};
      execv(argv[0], args);
      _exit(96);
    }
    int status;
    if (wait_one(grandchild, &status, 0) != grandchild || !WIFEXITED(status))
      _exit(93);
    _exit(WEXITSTATUS(status));
  }
  close(ready[1]);
  close(gate[0]);
  close(control[0]);
  char byte;
  int status = 0, result = 1;
  if (read(ready[0], &byte, 1) != 1 || ptrace(PT_ATTACH, target, 0, 0) ||
      wait_one(target, &status, 0) != target || !WIFSTOPPED(status))
    goto done;
  mach_port_t task = MACH_PORT_NULL, handler = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), target, &task);
  if (kr || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                               &handler) ||
      mach_port_insert_right(mach_task_self(), handler, handler,
                              MACH_MSG_TYPE_MAKE_SEND))
    goto done;
#if defined(__arm64__)
  const int flavor = ARM_THREAD_STATE64;
#else
  const int flavor = x86_THREAD_STATE64;
#endif
  kr = task_set_exception_ports(task, EXC_MASK_BREAKPOINT, handler,
                                EXCEPTION_STATE, flavor);
  printf("set=%d\n", kr);
  if (kr || ptrace(PT_CONTINUE, target, (caddr_t)1, 0) ||
      write(gate[1], "x", 1) != 1)
    goto done;
  struct {
    mach_msg_header_t header;
    unsigned char body[4096];
  } request = {0}, reply = {0};
  kr = mach_msg(&request.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                sizeof request, handler, 10000, MACH_PORT_NULL);
  printf("receive=%d\n", kr);
  if (kr) {
    pid_t observed = wait_one(target, &status, WNOHANG);
    printf("target-event=%d stop=%d exit=%d\n", observed == target,
           observed == target && WIFSTOPPED(status) ? WSTOPSIG(status) : -1,
           observed == target && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  }
  if (kr || request.header.msgh_bits & MACH_MSGH_BITS_COMPLEX ||
      request.header.msgh_size < sizeof(mach_msg_header_t) + 24)
    goto done;
  uint32_t count = word(request.body + 12);
  size_t width = request.header.msgh_id == 2406 ? 8 : 4;
  size_t state_offset = 16 + count * width;
  if (count > 2 || state_offset + 8 >
      request.header.msgh_size - sizeof(mach_msg_header_t))
    goto done;
  uint32_t returned_flavor = word(request.body + state_offset);
  uint32_t words = word(request.body + state_offset + 4);
  if (returned_flavor != (uint32_t)flavor || words > 614 ||
      state_offset + 8 + words * 4 !=
          request.header.msgh_size - sizeof(mach_msg_header_t))
    goto done;
  memcpy(reply.body, &NDR_record, 8);
  memcpy(reply.body + 12, request.body + state_offset, 8 + words * 4);
#if defined(__arm64__)
  if (words != ARM_THREAD_STATE64_COUNT)
    goto done;
  arm_thread_state64_t state;
  memcpy(&state, reply.body + 20, sizeof state);
  __darwin_arm_thread_state64_set_pc_fptr(
      state, (void *)(__darwin_arm_thread_state64_get_pc(state) + 4));
  memcpy(reply.body + 20, &state, sizeof state);
#endif
  reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  reply.header.msgh_size = sizeof(mach_msg_header_t) + 20 + words * 4;
  reply.header.msgh_remote_port = request.header.msgh_remote_port;
  reply.header.msgh_id = request.header.msgh_id + 100;
  if (exec_parent) {
    if (write(control[1], "x", 1) != 1 ||
        wait_one(target, &status, 0) != target || !WIFSTOPPED(status))
      goto done;
    printf("exec-stop=%d\n", WSTOPSIG(status));
    if (WSTOPSIG(status) != SIGTRAP ||
        ptrace(PT_CONTINUE, target, (caddr_t)1, 0))
      goto done;
  }
  kr = mach_msg(&reply.header, MACH_SEND_MSG, reply.header.msgh_size, 0,
                MACH_PORT_NULL, 0, MACH_PORT_NULL);
  if (kr)
    goto done;
  for (;;) {
    if (wait_one(target, &status, 0) != target)
      goto done;
    if (!WIFSTOPPED(status))
      break;
    if (ptrace(PT_CONTINUE, target, (caddr_t)1, 0))
      goto done;
  }
  printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  result = !(WIFEXITED(status) && WEXITSTATUS(status) == 42);
done:
  if (result) {
    /* Only the probe's child and grandchild belong to this new group. */
    kill(-target, SIGKILL);
    kill(target, SIGKILL);
    ptrace(PT_KILL, target, (caddr_t)1, 0);
    wait_one(target, NULL, 0);
  }
  return result;
}
