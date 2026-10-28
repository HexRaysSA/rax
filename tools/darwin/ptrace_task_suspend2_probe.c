/* Characterize suspension tokens independently of BSD tracing. Sign the
 * parent/child image with ptrace_get_task_allow.plist. XNU task.defs uses
 * MOVE_SEND_ONCE for task_suspension_token_t; ipc_tt.c and task.c release
 * one normal hold when such a right is abandoned. */
#include <errno.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Private tooling entrypoint, with the ABI in pinned osfmk/mach/message.h.
 * mach_msg() marks messages as queue calls, so a kobject probe must set the
 * explicit kobject-call classification through mach_msg2_internal(). */
extern mach_msg_return_t mach_msg2_internal(void *, uint64_t, uint64_t, uint64_t,
                                          uint64_t, uint64_t, uint64_t, uint64_t);

static volatile sig_atomic_t owned_child;

static void timed_out(int signal) {
  (void)signal;
  if (owned_child > 0)
    kill((pid_t)owned_child, SIGKILL);
  _exit(124);
}

static int holds(task_t task) {
  mach_task_basic_info_data_t info = {0};
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  kern_return_t result = task_info(task, MACH_TASK_BASIC_INFO,
                                  (task_info_t)&info, &count);
  return result ? -1 : info.suspend_count;
}

static int send_once(mach_port_t name) {
  mach_port_type_t type = 0;
  return mach_port_type(mach_task_self(), name, &type) == KERN_SUCCESS &&
         (type & MACH_PORT_TYPE_SEND_ONCE) != 0;
}

static int invalid_request(task_t task, const char *label, int id, unsigned size) {
  task_suspension_token_t token = MACH_PORT_NULL;
  mach_port_t reply = MACH_PORT_NULL;
  if (task_suspend2(task, &token) ||
      mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply))
    return -1;
  struct {
    mach_msg_header_t header;
    NDR_record_t ndr;
    kern_return_t result;
    char spare[64];
  } *message = calloc(1, size > sizeof *message ? size : sizeof *message);
  if (!message) return -1;
  message->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE,
                                           MACH_MSG_TYPE_MAKE_SEND_ONCE);
  message->header.msgh_size = size;
  message->header.msgh_remote_port = token;
  message->header.msgh_local_port = reply;
  message->header.msgh_id = id;
  kern_return_t result = mach_msg2_internal(message,
      0x0000000200000000ULL | MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT,
      (uint64_t)size << 32 | message->header.msgh_bits,
      (uint64_t)reply << 32 | token, (uint64_t)(uint32_t)id << 32,
      (uint64_t)reply << 32, sizeof *message, 2000);
  int count = holds(task);
  printf("%s: receive=%#x result=%d count=%d\n", label, result,
         result ? 0 : message->result, count);
  mach_port_deallocate(mach_task_self(), token);
  mach_port_destroy(mach_task_self(), reply);
  if (count > 0)
    task_resume(task);
  free(message);
  return count < 0 ? -1 : 0;
}

static int after_exec(pid_t child, int gate) {
  owned_child = child;
  task_t task = MACH_PORT_NULL;
  kern_return_t result = task_for_pid(mach_task_self(), child, &task);
  int count = result ? -1 : holds(task);
  printf("after-exec: task=%d count=%d\n", result, count);
  if (result || count != 0 || write(gate, "g", 1) != 1)
    return 1;
  int status;
  pid_t got;
  do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
  owned_child = 0;
  printf("child-exit=%d\n", got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return !(got == child && WIFEXITED(status) && WEXITSTATUS(status) == 42);
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  if (argc == 4 && strcmp(argv[1], "after-exec") == 0)
    return after_exec((pid_t)atoi(argv[2]), atoi(argv[3]));
  int ready[2], gate[2], status;
  if (pipe(ready) || pipe(gate))
    return 1;
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (!child) {
    close(ready[0]);
    close(gate[1]);
    if (write(ready[1], "r", 1) != 1)
      _exit(80);
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
  if (read(ready[0], &byte, 1) != 1)
    goto fail;
  close(ready[0]);
  task_t task = MACH_PORT_NULL;
  kern_return_t result = task_for_pid(mach_task_self(), child, &task);
  printf("task=%d\n", result);
  if (result)
    goto fail;
  task_suspension_token_t first = MACH_PORT_NULL, second = MACH_PORT_NULL;
  result = task_suspend2(task, &first);
  printf("suspend2-first=%d\n", result);
  if (result)
    goto fail;
  result = task_suspend2(task, &second);
  printf("suspend2-second=%d count=%d separate=%d send-once=%d,%d\n",
         result, holds(task), first != second, send_once(first), send_once(second));
  if (result)
    goto fail;
  if (argc == 2 && strcmp(argv[1], "exec") == 0) {
    char self[4096], pid_arg[32], gate_arg[32];
    uint32_t length = sizeof self;
    if (_NSGetExecutablePath(self, &length))
      goto fail;
    snprintf(pid_arg, sizeof pid_arg, "%d", child);
    snprintf(gate_arg, sizeof gate_arg, "%d", gate[1]);
    execl(self, self, "after-exec", pid_arg, gate_arg, (char *)NULL);
    goto fail;
  }
  result = mach_port_deallocate(mach_task_self(), first);
  printf("abandon-first=%d count=%d\n", result, holds(task));
  result = task_resume2(second);
  printf("resume2-second=%d count=%d\n", result, holds(task));
  task_suspension_token_t third = MACH_PORT_NULL;
  result = task_suspend2(task, &third);
  printf("suspend2-third=%d count=%d\n", result, holds(task));
  if (result)
    goto fail;
  result = task_resume(task);
  printf("legacy-resume=%d count=%d\n", result, holds(task));
  result = task_resume2(third);
  printf("resume2-drained=%d count=%d\n", result, holds(task));
  if (invalid_request(task, "unknown-id", 0x7ffffffe, 24) ||
      invalid_request(task, "bad-size", 3437, 28) ||
      invalid_request(task, "large-size", 3437, 2 * 1024 * 1024))
    goto fail;
  if (write(gate[1], "g", 1) != 1)
    goto fail;
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
