/* Obtain the task and install the debugger's exception handler before
 * PT_ATTACHEXC, as debugserver's AttachForDebug does. Sign with the fixture
 * ptrace_get_task_allow.plist. The fixture exercises the same pre-attach ordering. */
#include <errno.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
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

static pid_t wait_one(pid_t child, int *status, int flags) {
  pid_t got;
  do { got = waitpid(child, status, flags); } while (got < 0 && errno == EINTR);
  return got;
}

int main(void) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  int ready[2], gate[2], status;
  if (pipe(ready) || pipe(gate))
    return 1;
  pid_t child = fork();
  if (child < 0)
    return 2;
  if (!child) {
    close(ready[0]);
    close(gate[1]);
    if (write(ready[1], "r", 1) != 1)
      _exit(80);
    close(ready[1]);
    char byte;
    ssize_t got;
    do { got = read(gate[0], &byte, 1); } while (got < 0 && errno == EINTR);
    _exit(81);
  }
  owned_child = child;
  close(ready[1]);
  close(gate[0]);
  char byte;
  ssize_t got;
  do { got = read(ready[0], &byte, 1); } while (got < 0 && errno == EINTR);
  close(ready[0]);
  task_t task = MACH_PORT_NULL;
  mach_port_t handler = MACH_PORT_NULL;
  int received = 0;
  struct { __Request__exception_raise_t request; mach_msg_trailer_t trailer; } message = {0};
  if (got != 1)
    goto fail;
  kern_return_t grant = task_for_pid(mach_task_self(), child, &task);
  printf("pre-attach-task=%d\n", grant);
  if (grant)
    goto fail;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &handler) ||
      mach_port_insert_right(mach_task_self(), handler, handler, MACH_MSG_TYPE_MAKE_SEND))
    goto fail;
  kern_return_t installed = task_set_exception_ports(task, EXC_MASK_SOFTWARE,
      handler, EXCEPTION_DEFAULT, THREAD_STATE_NONE);
  printf("pre-attach-set=%d\n", installed);
  if (installed)
    goto fail;
  int attached = ptrace(PT_ATTACHEXC, child, 0, 0);
  printf("attach=%d\n", attached);
  if (attached)
    goto fail;
  kern_return_t incoming = mach_msg(&message.request.Head,
      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof message, handler, 30000, MACH_PORT_NULL);
  printf("receive=%d exception=%d count=%u signal=%d\n", incoming,
      message.request.exception, message.request.codeCnt, message.request.code[1]);
  if (incoming)
    goto fail;
  received = 1;
  if (message.request.exception != EXC_SOFTWARE || message.request.codeCnt != 2 ||
      message.request.code[0] != 0x10003 || message.request.code[1] != SIGSTOP)
    goto fail;
  pid_t stopped;
  do {
    stopped = wait_one(child, &status, WNOHANG);
    if (!stopped)
      usleep(1000);
  } while (!stopped);
  if (stopped != child || !WIFSTOPPED(status) || ptrace(PT_KILL, child, (caddr_t)1, 0))
    goto fail;
  __Reply__exception_raise_t reply = {0};
  reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  reply.Head.msgh_size = sizeof reply;
  reply.Head.msgh_remote_port = message.request.Head.msgh_remote_port;
  reply.Head.msgh_id = message.request.Head.msgh_id + 100;
  reply.NDR = NDR_record;
  reply.RetCode = KERN_SUCCESS;
  kern_return_t answered = mach_msg(&reply.Head, MACH_SEND_MSG, sizeof reply, 0,
      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  message.request.Head.msgh_remote_port = MACH_PORT_NULL;
  mach_msg_destroy(&message.request.Head);
  received = 0;
  printf("reply=%d\n", answered);
  if (answered || wait_one(child, &status, 0) != child)
    goto fail;
  owned_child = 0;
  printf("exit-signal=%d\n", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
  return !(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
fail:
  kill(child, SIGKILL);
  ptrace(PT_KILL, child, (caddr_t)1, 0);
  if (received)
    mach_msg_destroy(&message.request.Head);
  if (MACH_PORT_VALID(handler))
    mach_port_destroy(mach_task_self(), handler);
  wait_one(child, NULL, 0);
  owned_child = 0;
  return 1;
}
