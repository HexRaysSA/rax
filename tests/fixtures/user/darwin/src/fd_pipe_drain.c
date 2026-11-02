/* Independent Darwin read/close lifetime observation, without an assumed
 * close outcome. Mach saved state establishes entry into the blocked read. */
#include <errno.h>
#if defined(__aarch64__)
#include <mach/arm/thread_status.h>
#else
#include <mach/i386/thread_status.h>
#endif
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

extern long entered_read(int, void *, size_t, unsigned *, unsigned);
extern long entered_close(int, unsigned *, unsigned);
extern long entered_dup2(int, int, unsigned *);
extern char entered_read_return[], entered_close_return[];
extern char entered_dup2_return[];
#if defined(__aarch64__)
__asm__(".text\n.globl _entered_read\n_entered_read:\n"
        "stp x19, x30, [sp, #-16]!\nmov x19, x3\nmov x16, x4\n"
        "adds xzr, xzr, xzr\nsvc #0x80\n"
        ".globl _entered_read_return\n_entered_read_return:\n"
        "cset w4, cs\nstr w4, [x19]\nldp x19, x30, [sp], #16\nret\n"
        ".globl _entered_close\n_entered_close:\n"
        "stp x19, x30, [sp, #-16]!\nmov x19, x1\nmov x16, x2\nsvc #0x80\n"
        ".globl _entered_close_return\n_entered_close_return:\n"
        "cset w4, cs\nstr w4, [x19]\nldp x19, x30, [sp], #16\nret\n"
        ".globl _entered_dup2\n_entered_dup2:\n"
        "stp x19, x30, [sp, #-16]!\nmov x19, x2\nmov x16, #90\nsvc #0x80\n"
        ".globl _entered_dup2_return\n_entered_dup2_return:\n"
        "cset w4, cs\nstr w4, [x19]\nldp x19, x30, [sp], #16\nret\n");
#else
__asm__(".text\n.globl _entered_read\n_entered_read:\n"
        "pushq %rbx\nmovq %rcx, %rbx\nmovl %r8d, %eax\norl $0x2000000, "
        "%eax\nsyscall\n"
        ".globl _entered_read_return\n_entered_read_return:\n"
        "setc %dl\nmovzbl %dl, %edx\nmovl %edx, (%rbx)\npopq %rbx\nretq\n"
        ".globl _entered_close\n_entered_close:\n"
        "pushq %rbx\nmovq %rsi, %rbx\nmovl %edx, %eax\norl $0x2000000, "
        "%eax\nsyscall\n"
        ".globl _entered_close_return\n_entered_close_return:\n"
        "setc %dl\nmovzbl %dl, %edx\nmovl %edx, (%rbx)\npopq %rbx\nretq\n"
        ".globl _entered_dup2\n_entered_dup2:\n"
        "pushq %rbx\nmovq %rdx, %rbx\nmovl $0x200005a, %eax\nsyscall\n"
        ".globl _entered_dup2_return\n_entered_dup2_return:\n"
        "setc %dl\nmovzbl %dl, %edx\nmovl %edx, (%rbx)\npopq %rbx\nretq\n");
#endif

struct read_op {
  int fd;
  unsigned number, carry;
  long result;
  unsigned char byte;
  _Atomic unsigned done;
};
struct close_op {
  int fd, source;
  unsigned number, carry;
  long result;
};
static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    _exit(80);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static void timed_out(int sig) {
  (void)sig;
  _exit(124);
}
static void *reader(void *opaque) {
  struct read_op *op = opaque;
  struct iovec vector = {&op->byte, 1};
  void *buffer =
      (op->number == 120 || op->number == 411) ? (void *)&vector : &op->byte;
  op->result = entered_read(op->fd, buffer, 1, &op->carry, op->number);
  atomic_store_explicit(&op->done, 1, memory_order_release);
  return NULL;
}
static void *closer(void *opaque) {
  struct close_op *op = opaque;
  op->result = op->number == 90 ? entered_dup2(op->source, op->fd, &op->carry)
                                : entered_close(op->fd, &op->carry, op->number);
  return NULL;
}
/* 1: observed waiting inside this exact entry; 0: caller completed; -1: no
 * conclusive classification within the bounded observation interval. */
static int classify(pthread_t thread, uintptr_t successor, uint64_t nr,
                    _Atomic unsigned *done) {
  thread_t port = pthread_mach_thread_np(thread);
  uint64_t deadline = now_ns() + 10000000000ULL;
  int64_t last_delta = INT64_MIN;
  uint64_t last_number = UINT64_MAX;
  while (now_ns() < deadline) {
    if (atomic_load_explicit(done, memory_order_acquire))
      return 0;
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (!thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&info, &count) &&
        info.run_state == TH_STATE_WAITING) {
#if defined(__aarch64__)
      arm_thread_state64_t state;
      count = ARM_THREAD_STATE64_COUNT;
      if (!thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&state,
                            &count)) {
        last_delta = (int64_t)(arm_thread_state64_get_pc(state) - successor);
        last_number = state.__x[16];
        if (last_delta == 0 && last_number == nr)
          return 1;
      }
#else
      x86_thread_state64_t state;
      count = x86_THREAD_STATE64_COUNT;
      if (!thread_get_state(port, x86_THREAD_STATE64, (thread_state_t)&state,
                            &count)) {
        last_delta = (int64_t)(state.__rip - successor);
        last_number = state.__rax;
        if (last_delta == 0 && last_number == (nr | 0x2000000))
          return 1;
      }
#endif
    }
    usleep(1000);
  }
  printf("entry-unclassified successor-delta=%lld number=%llx\n",
         (long long)last_delta, (unsigned long long)last_number);
  return -1;
}

static int run_case(unsigned number, unsigned close_number, unsigned action) {
  int original[2], replacement[2];
  if (pipe(original) || pipe(replacement) || write(replacement[1], "b", 1) != 1)
    return 1;
  int alias = -1;
  if ((action >= 2 && action <= 4) || action == 7) {
    alias = dup(original[0]);
    if (alias < 0)
      return 1;
  }
  int count = action >= 6 ? 2 : 1;
  struct read_op reads[2] = {{0}};
  pthread_t reading[2], closing;
  for (int i = 0; i < count; ++i) {
    reads[i].fd = (i == 0 ? (action == 3 || action == 4) : action == 7)
                      ? alias
                      : original[0];
    reads[i].number = number;
    reads[i].byte = 0xa5;
    atomic_init(&reads[i].done, 0);
    if (pthread_create(&reading[i], NULL, reader, &reads[i]) ||
        classify(reading[i], (uintptr_t)entered_read_return, number,
                 &reads[i].done) != 1)
      return 1;
  }
  struct close_op closed = {0};
  closed.fd = action == 2 ? alias : original[0];
  closed.source = action == 5 ? original[0] : replacement[0];
  closed.number = action == 1 || action == 4 || action == 5 ? 90 : close_number;
  if (pthread_create(&closing, NULL, closer, &closed) ||
      pthread_join(closing, NULL))
    return 1;
  int cancelled[2], remaining = 0;
  for (int i = 0; i < count; ++i) {
    cancelled[i] = action != 5 && reads[i].fd == closed.fd;
    remaining += !cancelled[i];
  }
  long written = 0;
  int error = 0;
  if (remaining) {
    errno = 0;
    written = write(original[1], "aa", (size_t)remaining);
    error = written < 0 ? errno : 0;
  }
  for (int i = 0; i < count; ++i)
    if (pthread_join(reading[i], NULL))
      return 1;
  if (!remaining) {
    errno = 0;
    written = write(original[1], "a", 1);
    error = written < 0 ? errno : 0;
  }
  int valid =
      !closed.carry && closed.result == (closed.number == 90 ? closed.fd : 0);
  valid &= remaining ? written == remaining && error == 0
                     : written == -1 && error == EPIPE;
  printf("case=%u read=%u close=%u close-ok=%d write=%ld errno=%d", action,
         number, close_number,
         !closed.carry &&
             closed.result == (closed.number == 90 ? closed.fd : 0),
         written, error);
  for (int i = 0; i < count; ++i) {
    printf(" r%d=%ld/%u/%u", i, reads[i].result, reads[i].carry, reads[i].byte);
    valid &= !reads[i].carry && reads[i].result == !cancelled[i] &&
             reads[i].byte == (cancelled[i] ? 0xa5 : 'a');
  }
  putchar('\n');
  if (closed.number != 90 && closed.fd == original[0] &&
      dup2(replacement[0], original[0]) != original[0])
    return 1;
  if (close(original[0]) || close(original[1]) || close(replacement[0]) ||
      close(replacement[1]))
    return 1;
  if (alias >= 0 && alias != closed.fd && close(alias))
    return 1;
  return !valid;
}

/* Suspend an entered reader before close. Join the closer before inspecting
 * the held state: observing the closer's transient wait state is racy. An
 * unchanged state write is distinct from leaving the saved state untouched. */
static int held_case(unsigned number, unsigned close_number, unsigned mode) {
  int original[2], replacement[2];
  if (pipe(original) || pipe(replacement))
    return 1;
  struct read_op read = {.fd = original[0], .number = number, .byte = 0xa5};
  atomic_init(&read.done, 0);
  pthread_t reading, closing;
  if (pthread_create(&reading, NULL, reader, &read) ||
      classify(reading, (uintptr_t)entered_read_return, number, &read.done) !=
          1)
    return 1;
  thread_t port = pthread_mach_thread_np(reading);
  if (thread_suspend(port))
    return 1;
  struct close_op closed = {
      .fd = original[0], .source = replacement[0], .number = close_number};
  if (pthread_create(&closing, NULL, closer, &closed) ||
      pthread_join(closing, NULL))
    return 1;
  mach_msg_type_number_t count;
  uint64_t held_value, held_pc;
  unsigned held_carry;
#if defined(__aarch64__)
  arm_thread_state64_t state;
  count = ARM_THREAD_STATE64_COUNT;
  if (thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&state,
                       &count))
    return 1;
  held_value = state.__x[0];
  held_pc = arm_thread_state64_get_pc(state);
  held_carry = (state.__cpsr >> 29) & 1;
  if (mode == 1) {
    state.__x[0] = 0x1234;
    state.__cpsr |= 0x20000000;
  }
  if (mode && thread_set_state(port, ARM_THREAD_STATE64, (thread_state_t)&state,
                               ARM_THREAD_STATE64_COUNT))
    return 1;
#else
  x86_thread_state64_t state;
  count = x86_THREAD_STATE64_COUNT;
  if (thread_get_state(port, x86_THREAD_STATE64, (thread_state_t)&state,
                       &count))
    return 1;
  held_value = state.__rax;
  held_pc = state.__rip;
  held_carry = state.__rflags & 1;
  if (mode == 1) {
    state.__rax = 0x1234;
    state.__rflags |= 1;
  }
  if (mode && thread_set_state(port, x86_THREAD_STATE64, (thread_state_t)&state,
                               x86_THREAD_STATE64_COUNT))
    return 1;
#endif
  if (thread_resume(port) || pthread_join(reading, NULL))
    return 1;
  long expected = mode == 1 ? 0x1234 : mode == 2 ? (long)held_value : 0;
  unsigned carry = mode == 1 ? 1 : mode == 2 ? held_carry : 0;
  int valid = held_pc == (uintptr_t)entered_read_return && !closed.carry &&
              closed.result == (close_number == 90 ? original[0] : 0) &&
              read.result == expected && read.carry == carry &&
              read.byte == 0xa5;
  printf("held read=%u close=%u mode=%u value=%llu carry=%u pc-ok=%d "
         "close-ok=%d result=%ld/%u/%u\n",
         number, close_number, mode, (unsigned long long)held_value, held_carry,
         held_pc == (uintptr_t)entered_read_return,
         !closed.carry &&
             closed.result == (close_number == 90 ? original[0] : 0),
         read.result, read.carry, read.byte);
  if (close_number == 90 && close(original[0]))
    return 1;
  if (close(original[1]) || close(replacement[0]) || close(replacement[1]))
    return 1;
  return !valid;
}

int main(void) {
  setbuf(stdout, NULL);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGALRM, timed_out);
  alarm(180);
  const unsigned numbers[] = {3, 120, 396, 411};
  const unsigned closings[] = {6, 399};
  for (unsigned i = 0; i < sizeof numbers / sizeof numbers[0]; ++i)
    for (unsigned j = 0; j < sizeof closings / sizeof closings[0]; ++j)
      for (unsigned action = 0; action < 8; ++action)
        if (run_case(numbers[i], closings[j], action))
          return 1;
  const unsigned held_closings[] = {6, 399, 90};
  for (unsigned i = 0; i < sizeof numbers / sizeof numbers[0]; ++i)
    for (unsigned j = 0; j < sizeof held_closings / sizeof held_closings[0];
         ++j)
      for (unsigned mode = 0; mode < 3; ++mode)
        if (held_case(numbers[i], held_closings[j], mode))
          return 1;
  return 0;
}
