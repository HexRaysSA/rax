/* The tracer installs its own receive port in the attached target, then
 * continues the signal stop and replies to the forwarded exception. */
#include <errno.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid;
static void timeout(int signal) {
  (void)signal;
  if (child_pid > 0)
    kill(child_pid, SIGKILL);
  _exit(124);
}
static pid_t wait_stop(pid_t pid, int *status) {
  pid_t got;
  do {
    do { got = waitpid(pid, status, WNOHANG); } while (got < 0 && errno == EINTR);
    if (!got)
      usleep(1000);
  } while (!got);
  return got;
}
int main(void) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timeout);
  alarm(25);
  int gate[2];
  if (pipe(gate))
    return 1;
  pid_t child = fork();
  if (child < 0)
    return 2;
  if (!child) {
    close(gate[1]);
    char c;
    ssize_t got;
    do { got = read(gate[0], &c, 1); } while (got < 0 && errno == EINTR);
    if (got != 1)
      _exit(91);
    raise(SIGUSR1);
    _exit(42);
  }
  child_pid = child;
  close(gate[0]);
  int status = 0;
  if (ptrace(PT_ATTACHEXC, child, 0, 0)) {
    printf("attach-error=%d\n", errno);
    goto fail;
  }
  pid_t stopped = wait_stop(child, &status);
  if (stopped != child || !WIFSTOPPED(status)) {
    printf("initial-stop=%d status=%d errno=%d\n", stopped == child, status, errno);
    goto fail;
  }
  mach_port_t task = MACH_PORT_NULL, port = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), child, &task);
  if (kr) {
    printf("task=%d\n", kr);
    goto fail;
  }
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) ||
      mach_port_insert_right(mach_task_self(), port, port,
                             MACH_MSG_TYPE_MAKE_SEND))
    goto fail;
  kr = task_set_exception_ports(task, EXC_MASK_SOFTWARE, port,
                                EXCEPTION_DEFAULT, THREAD_STATE_NONE);
  printf("set=%d\n", kr);
  if (kr)
    goto fail;
  if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) || write(gate[1], "x", 1) != 1)
    goto fail;
  struct {
    __Request__exception_raise_t req;
    mach_msg_trailer_t trailer;
  } message = {0};
  kr = mach_msg(&message.req.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                sizeof message, port, 10000, MACH_PORT_NULL);
  printf("receive=%d exception=%d count=%d code=%d signal=%d\n", kr,
         message.req.exception, (int)message.req.codeCnt, message.req.code[0],
         message.req.code[1]);
  if (kr)
    goto fail;
  if (waitpid(child, &status, WNOHANG) != child || !WIFSTOPPED(status))
    goto fail;
  if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0))
    goto fail;
  __Reply__exception_raise_t reply = {0};
  reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  reply.Head.msgh_size = sizeof reply;
  reply.Head.msgh_remote_port = message.req.Head.msgh_remote_port;
  reply.Head.msgh_id = message.req.Head.msgh_id + 100;
  reply.NDR = NDR_record;
  reply.RetCode = KERN_SUCCESS;
  kr = mach_msg(&reply.Head, MACH_SEND_MSG, sizeof reply, 0, MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  printf("reply=%d\n", kr);
  if (kr || waitpid(child, &status, 0) != child)
    goto fail;
  child_pid = 0;
  alarm(0);
  printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return !(WIFEXITED(status) && WEXITSTATUS(status) == 42);
fail:
  kill(child, SIGKILL);
  ptrace(PT_KILL, child, (caddr_t)1, 0);
  waitpid(child, NULL, 0);
  child_pid = 0;
  return 1;
}
