/* Arm one AArch64 user instruction through ARM_DEBUG_STATE64, independently of
 * BSD PT_STEP. Build with xcrun clang -arch arm64 -O1 -Wall, then sign with
 * tests/fixtures/user/darwin/src/ptrace_get_task_allow.plist.
 */
#include <errno.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <mach/exc.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct shared {
  _Atomic uint64_t main_id;
  _Atomic unsigned after;
  _Atomic unsigned finish;
  _Atomic uint64_t value;
  _Atomic unsigned exclusive_status;
  char byte;
};
#if defined(STEP_SYSCALL) || defined(STEP_READ)
#define STEP_FIRST "svc #0x80\n"
#define STEP_NEXT "mov x20, #0x2345\n"
#elif defined(STEP_FAULT)
#define STEP_FIRST ".inst 0\n"
#define STEP_NEXT "mov x20, #0x2345\n"
#elif defined(STEP_EXCLUSIVE_LOAD)
#define STEP_FIRST "ldxr x19, [x21]\n"
#define STEP_NEXT "stxr w20, x19, [x21]\n"
#elif defined(STEP_EXCLUSIVE_STORE)
#define STEP_FIRST "stxr w20, x19, [x21]\n"
#define STEP_NEXT "mov x19, #0x2345\n"
#else
#define STEP_FIRST "mov x19, #0x1234\n"
#define STEP_NEXT "mov x20, #0x2345\n"
#endif
static volatile sig_atomic_t tracee;
extern char arm_step_after[];
static void timed_out(int sig) {
  (void)sig;
  if (tracee > 0)
    kill(tracee, SIGKILL);
  _exit(124);
}
static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static thread_t main_thread(task_t task, uint64_t main_id) {
  thread_act_array_t threads = NULL;
  mach_msg_type_number_t count = 0;
  if (task_threads(task, &threads, &count))
    return MACH_PORT_NULL;
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
  return main;
}
static int parked(task_t task, thread_t thread, int holds) {
  uint64_t deadline = now_ns() + 60000000000ULL;
  do {
    task_basic_info_data_t task_info_data;
    mach_msg_type_number_t n = TASK_BASIC_INFO_COUNT;
    if (task_info(task, TASK_BASIC_INFO, (task_info_t)&task_info_data, &n))
      return 0;
    thread_basic_info_data_t thread_info_data;
    n = THREAD_BASIC_INFO_COUNT;
    if (thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&thread_info_data, &n))
      return 0;
    if (task_info_data.suspend_count == holds &&
        thread_info_data.run_state == TH_STATE_WAITING) {
#if defined(STEP_READ) && !defined(STEP_READ_READY)
      if (holds == 0) {
        arm_thread_state64_t entered;
        n = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&entered, &n))
          return 0;
        if (arm_thread_state64_get_pc(entered) != (uintptr_t)arm_step_after ||
            entered.__x[16] != 3) {
          usleep(1000);
          continue;
        }
      }
#endif
      return 1;
    }
    usleep(1000);
  } while (now_ns() < deadline);
  return 0;
}
int main(void) {
  setbuf(stdout, NULL);
  signal(SIGALRM, timed_out);
  alarm(180);
  struct shared *s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANON, -1, 0);
  if (s == MAP_FAILED)
    return 1;
  atomic_init(&s->main_id, 0);
  atomic_init(&s->after, 0);
  atomic_init(&s->finish, 0);
  atomic_init(&s->value, 0x1234);
  atomic_init(&s->exclusive_status, 0);
#ifdef STEP_READ
  int gate[2] = {-1, -1};
  if (pipe(gate))
    return 1;
#endif
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (!child) {
#ifdef STEP_READ
    close(gate[1]);
#endif
    uint64_t main_id;
    if (pthread_threadid_np(NULL, &main_id))
      _exit(81);
    atomic_store_explicit(&s->main_id, main_id, memory_order_release);
    uint64_t pid = getpid();
    unsigned status;
    __asm__ volatile("mov x19, #0\nmov x20, #0\nmov x0, %x1\nmov x21, %x2\n"
                     "mov x1, #17\nmov x16, #37\nsvc #0x80\n"
                     STEP_FIRST ".globl _arm_step_after\n_arm_step_after:\n"
                     STEP_NEXT "mov %w0, w20\n"
                     : "=r"(status) : "r"(pid), "r"(&s->value)
                     : "x0", "x1", "x16", "x19", "x20", "x21", "memory", "cc");
    atomic_store_explicit(&s->exclusive_status, status, memory_order_relaxed);
    atomic_store_explicit(&s->after, 1, memory_order_release);
    while (!atomic_load_explicit(&s->finish, memory_order_acquire)) {
    }
    _exit(42);
  }
  tracee = child;
#ifdef STEP_READ
  close(gate[0]);
#endif
  int status;
  if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
    goto fail;
  task_t task = MACH_PORT_NULL;
  if (task_for_pid(mach_task_self(), child, &task))
    goto fail;
  thread_t thread = main_thread(task, atomic_load_explicit(&s->main_id, memory_order_acquire));
  if (thread == MACH_PORT_NULL || !parked(task, thread, 1))
    goto fail;
  mach_port_t port = MACH_PORT_NULL;
  exception_mask_t mask = EXC_MASK_BREAKPOINT;
#ifdef STEP_FAULT
  mask |= EXC_MASK_BAD_INSTRUCTION;
#endif
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) ||
      mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) ||
      task_set_exception_ports(task, mask, port,
                               EXCEPTION_DEFAULT, THREAD_STATE_NONE))
    goto fail;
#if defined(STEP_SYSCALL) || defined(STEP_READ)
  arm_thread_state64_t syscall;
  mach_msg_type_number_t n = ARM_THREAD_STATE64_COUNT;
  if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&syscall, &n))
    goto fail;
#ifdef STEP_READ
  syscall.__x[16] = 3;
  syscall.__x[0] = gate[0];
  syscall.__x[1] = (uintptr_t)&s->byte;
  syscall.__x[2] = 1;
#else
  syscall.__x[16] = 20;
#endif
  if (thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&syscall,
                       ARM_THREAD_STATE64_COUNT))
    goto fail;
#endif
#ifdef STEP_READ_READY
  if (write(gate[1], "r", 1) != 1)
    goto fail;
  printf("read-ready=1\n");
#endif
  arm_debug_state64_t debug = {0};
  debug.__mdscr_el1 = 1;
  kern_return_t set = thread_set_state(thread, ARM_DEBUG_STATE64,
                                     (thread_state_t)&debug, ARM_DEBUG_STATE64_COUNT);
  printf("set=%d\n", set);
  if (set || task_resume(task))
    goto fail;
  struct {
    __Request__exception_raise_t request;
    mach_msg_trailer_t trailer;
  } message = {0};
#if defined(STEP_READ) && !defined(STEP_READ_READY)
  if (!parked(task, thread, 0))
    goto fail;
  printf("read-entered=1\n");
  kern_return_t deferred = mach_msg(&message.request.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0, sizeof message, port, 20, MACH_PORT_NULL);
  printf("deferred=%d\n", deferred == MACH_RCV_TIMED_OUT);
  if (deferred != MACH_RCV_TIMED_OUT)
    goto fail;
#if defined(STEP_READ_STATE) || defined(STEP_READ_ARGUMENT) || defined(STEP_READ_PC)
  arm_thread_state64_t pending;
  mach_msg_type_number_t pending_count = ARM_THREAD_STATE64_COUNT;
  if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&pending, &pending_count))
    goto fail;
  pending.__x[19] = 0x3456;
#ifdef STEP_READ_ARGUMENT
  pending.__x[0] = UINT64_MAX;
#endif
#ifdef STEP_READ_PC
  __darwin_arm_thread_state64_set_pc_fptr(pending, (void *)(arm_step_after + 4));
#endif
  if (thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&pending,
                       ARM_THREAD_STATE64_COUNT))
    goto fail;
  printf("wrote-state=1\n");
#endif
  if (write(gate[1], "r", 1) != 1)
    goto fail;
#endif
  kern_return_t received = mach_msg(&message.request.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0, sizeof message, port, 10000, MACH_PORT_NULL);
  printf("receive=%d type=%d code=%d,%d\n", received, message.request.exception,
         message.request.code[0], message.request.code[1]);
  if (received)
    goto fail;
  arm_thread_state64_t state;
  mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
  if (thread_get_state(message.request.thread.name, ARM_THREAD_STATE64,
                        (thread_state_t)&state, &count))
    goto fail;
  arm_exception_state64_t exception;
  count = ARM_EXCEPTION_STATE64_COUNT;
  if (thread_get_state(message.request.thread.name, ARM_EXCEPTION_STATE64,
                        (thread_state_t)&exception, &count))
    goto fail;
  count = ARM_DEBUG_STATE64_COUNT;
  if (thread_get_state(message.request.thread.name, ARM_DEBUG_STATE64,
                        (thread_state_t)&debug, &count))
    goto fail;
  printf("pc-after-first=%d x19=%llx x20=%llx\n",
         arm_thread_state64_get_pc(state) == (uintptr_t)arm_step_after,
         (unsigned long long)state.__x[19], (unsigned long long)state.__x[20]);
  printf("ss=%llu saved-ss-daif=%x esr-ec=%x esr-il=%u\n",
         (unsigned long long)(debug.__mdscr_el1 & 1), state.__cpsr & 0x2003c0,
         exception.__esr >> 26, (exception.__esr >> 25) & 1);
  printf("esr=%08x\n", exception.__esr);
#ifdef STEP_READ
  uintptr_t expected_pc = (uintptr_t)arm_step_after;
  uint64_t expected_x20 = 0;
  uint32_t expected_esr = 0xca000022;
#ifndef STEP_READ_READY
  expected_pc += 4;
  expected_x20 = 0x2345;
  expected_esr = 0xcb000022;
#endif
#ifdef STEP_READ_PC
  expected_pc += 4;
  expected_x20 = 0;
#endif
  if (arm_thread_state64_get_pc(state) != expected_pc || state.__x[20] != expected_x20 ||
      state.__x[0] != 1 || exception.__esr != expected_esr)
    goto fail;
#if defined(STEP_READ_STATE) || defined(STEP_READ_ARGUMENT) || defined(STEP_READ_PC)
  if (state.__x[19] != 0x3456)
    goto fail;
#endif
#endif
#if defined(STEP_SYSCALL) || defined(STEP_READ)
#ifdef STEP_READ
  printf("syscall-result=%d\n", state.__x[0] == 1);
#else
  printf("syscall-result=%d\n", state.__x[0] == (uint64_t)child);
#endif
#endif
#ifdef STEP_FAULT
  // Skip the faulting word; retrying it would take the same exception.
  __darwin_arm_thread_state64_set_pc_fptr(state, (void *)arm_step_after);
  if (thread_set_state(message.request.thread.name, ARM_THREAD_STATE64,
                        (thread_state_t)&state, ARM_THREAD_STATE64_COUNT))
    goto fail;
#endif
  // Explicitly disarm before replying, as a debugger does at the stop.
  // The observations above check the kernel's already-cleared stored SS.
  debug.__mdscr_el1 = 0;
  if (thread_set_state(message.request.thread.name, ARM_DEBUG_STATE64,
                        (thread_state_t)&debug, ARM_DEBUG_STATE64_COUNT))
    goto fail;
  __Reply__exception_raise_t reply = {0};
  reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  reply.Head.msgh_size = sizeof reply;
  reply.Head.msgh_remote_port = message.request.Head.msgh_remote_port;
  reply.Head.msgh_id = message.request.Head.msgh_id + 100;
  reply.NDR = NDR_record;
  reply.RetCode = KERN_SUCCESS;
  kern_return_t replied = mach_msg(&reply.Head, MACH_SEND_MSG, sizeof reply, 0,
                                   MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  printf("reply=%d\n", replied);
  if (replied)
    goto fail;
  mach_port_deallocate(mach_task_self(), message.request.thread.name);
  mach_port_deallocate(mach_task_self(), message.request.task.name);
  uint64_t deadline = now_ns() + 60000000000ULL;
  while (!atomic_load_explicit(&s->after, memory_order_acquire) && now_ns() < deadline)
    usleep(1000);
  if (!atomic_load_explicit(&s->after, memory_order_acquire))
    goto fail;
#if defined(STEP_EXCLUSIVE_LOAD) || defined(STEP_EXCLUSIVE_STORE)
  printf("exclusive-store-failed=%d\n",
         atomic_load_explicit(&s->exclusive_status, memory_order_relaxed) == 1);
#endif
  atomic_store_explicit(&s->finish, 1, memory_order_release);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
    goto fail;
  tracee = 0;
  printf("exit=%d\n", WEXITSTATUS(status));
  return WEXITSTATUS(status) == 42 ? 0 : 1;
fail:
  kill(child, SIGKILL);
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
  }
  tracee = 0;
  return 1;
}
