/* Independent native FIFO closing-slot observation. Mach saved state proves
 * both entered read and close before a third operation probes the descriptor.
 */
#include <errno.h>
#include <fcntl.h>
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern long entered_read(int, void *, size_t, unsigned *, unsigned);
extern long entered_close(int, unsigned *, unsigned);
extern long entered_dup2(int, int, unsigned *);
extern char entered_read_return[], entered_close_return[];
extern char entered_dup2_return[];
#if defined(__aarch64__)
__asm__(".text\n.globl _entered_read\n_entered_read:\n"
        "stp x19, x30, [sp, #-16]!\nmov x19, x3\nmov x16, x4\nsvc #0x80\n"
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

static int original[2], replacement[2];
static _Atomic unsigned read_done, close_done;
static long read_result, close_result;
static unsigned read_carry, close_carry;
static unsigned char byte;
static int reading_fd, closing_fd, replacing, same_slot;
static unsigned read_number = 3;
static unsigned close_number = 6;
static int named;
static char fifo_paths[2][4096];
static unsigned held_kind;
static struct iovec read_vector;
static unsigned char redirected_byte;
static const char *operation;
static _Atomic unsigned operation_done;
static long operation_result;
static unsigned operation_carry;
static unsigned char operation_byte;

static void *observer(void *unused) {
  (void)unused;
  unsigned number;
  int fd = closing_fd;
  void *argument = NULL;
  size_t third = 0;
  if (!strcmp(operation, "getfd")) {
    number = 92;
    argument = (void *)(uintptr_t)F_GETFD;
  } else if (!strcmp(operation, "allocate")) {
    number = 41;
    fd = original[1];
  } else if (!strcmp(operation, "read")) {
    number = 3;
    argument = &operation_byte;
    third = 1;
  } else if (!strcmp(operation, "same-dup")) {
    number = 90;
    argument = (void *)(uintptr_t)closing_fd;
  } else if (!strcmp(operation, "replace-target")) {
    number = 90;
    fd = replacement[0];
    argument = (void *)(uintptr_t)closing_fd;
  } else if (!strcmp(operation, "close-source")) {
    number = 6;
    fd = replacement[0];
  } else {
    _exit(81);
  }
  operation_result =
      entered_read(fd, argument, third, &operation_carry, number);
  atomic_store_explicit(&operation_done, 1, memory_order_release);
  return NULL;
}

static int make_pair(int descriptors[2], const char *label) {
  if (!named)
    return pipe(descriptors);
  const char *temporary = getenv("TMPDIR");
  char path[4096];
  if (!temporary)
    return 1;
  int n = snprintf(path, sizeof path, "%s/fd-lifetime-%d-%s", temporary,
                   getpid(), label);
  if (n < 0 || (size_t)n >= sizeof path || mkfifo(path, 0600))
    return 1;
  descriptors[0] = open(path, O_RDONLY | O_NONBLOCK);
  descriptors[1] = descriptors[0] < 0 ? -1 : open(path, O_WRONLY | O_NONBLOCK);
  int removed = named == 1 ? unlink(path) : 0;
  if (named == 2)
    strcpy(fifo_paths[!strcmp(label, "replacement")], path);
  if (descriptors[0] < 0 || descriptors[1] < 0 || removed)
    return 1;
  for (unsigned i = 0; i != 2; ++i) {
    int flags = fcntl(descriptors[i], F_GETFL);
    if (flags < 0 || fcntl(descriptors[i], F_SETFL, flags & ~O_NONBLOCK))
      return 1;
  }
  return 0;
}

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    _exit(80);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void timed_out(int signal_number) {
  (void)signal_number;
  _exit(124);
}

static void *reader(void *unused) {
  (void)unused;
  read_vector = (struct iovec){&byte, 1};
  read_result = entered_read(
      reading_fd,
      (read_number == 120 || read_number == 411) ? (void *)&read_vector : &byte,
      1, &read_carry, read_number);
  atomic_store_explicit(&read_done, 1, memory_order_release);
  return NULL;
}

static void *closer(void *unused) {
  (void)unused;
  close_result = replacing
                     ? entered_dup2(same_slot ? original[0] : replacement[0],
                                    closing_fd, &close_carry)
                     : entered_close(closing_fd, &close_carry, close_number);
  atomic_store_explicit(&close_done, 1, memory_order_release);
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
  int last_state = -1, last_error = -1;
  while (now_ns() < deadline) {
    if (atomic_load_explicit(done, memory_order_acquire))
      return 0;
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    kern_return_t information =
        thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&info, &count);
    last_error = information;
    if (!information)
      last_state = info.run_state;
    if (!information && (info.run_state == TH_STATE_WAITING ||
                         ((nr == 6 || nr == 399 || nr == 90) &&
                          info.run_state == TH_STATE_UNINTERRUPTIBLE))) {
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
  printf("entry-unclassified successor-delta=%lld number=%llx state=%d "
         "info-error=%d\n",
         (long long)last_delta, (unsigned long long)last_number, last_state,
         last_error);
  return -1;
}

static int run_case(int argc, char **argv) {
  if (argc != 7)
    return 82;
  operation = argv[5];
  if (!strcmp(argv[6], "held-close"))
    held_kind = 1;
  else if (!strcmp(argv[6], "held-read"))
    held_kind = 2;
  else if (!strcmp(argv[6], "vector-rewrite"))
    held_kind = 3;
  else if (strcmp(argv[6], "ordinary"))
    return 95;
  setbuf(stdout, NULL);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGALRM, timed_out);
  alarm(60);
  if (argc >= 5) {
    if (strcmp(argv[4], "fifo") && strcmp(argv[4], "fifo-linked"))
      return 1;
    named = !strcmp(argv[4], "fifo") ? 1 : 2;
  }
  if (make_pair(original, "original") ||
      make_pair(replacement, "replacement") ||
      write(replacement[1], "b", 1) != 1)
    return 1;
  const char *name = argc >= 2 ? argv[1] : "close";
  if (argc >= 3) {
    if (!strcmp(argv[2], "readv"))
      read_number = 120;
    else if (!strcmp(argv[2], "read-nocancel"))
      read_number = 396;
    else if (!strcmp(argv[2], "readv-nocancel"))
      read_number = 411;
    else if (strcmp(argv[2], "read"))
      return 1;
  }
  if (argc >= 4) {
    if (!strcmp(argv[3], "close-nocancel"))
      close_number = 399;
    else if (strcmp(argv[3], "close"))
      return 1;
  }
  int alias = -1;
  reading_fd = closing_fd = original[0];
  if (!strcmp(name, "close")) {
  } else if (!strcmp(name, "dup2")) {
    replacing = 1;
  } else if (!strcmp(name, "close-alias")) {
    closing_fd = alias = dup(original[0]);
  } else if (!strcmp(name, "read-alias")) {
    reading_fd = alias = dup(original[0]);
  } else if (!strcmp(name, "dup2-alias")) {
    reading_fd = alias = dup(original[0]);
    replacing = 1;
  } else if (!strcmp(name, "same-slot-dup")) {
    replacing = same_slot = 1;
  } else {
    return 1;
  }
  if (reading_fd < 0 || closing_fd < 0)
    return 1;
  printf("case=%s read-number=%u close-number=%u named=%d\n", name, read_number,
         close_number, named);
  pthread_t reading, closing;
  if (pthread_create(&reading, NULL, reader, NULL))
    return 1;
  int read_entered = classify(reading, (uintptr_t)entered_read_return,
                              read_number, &read_done);
  printf("read-entered=%d\n", read_entered);
  if (read_entered != 1 || pthread_create(&closing, NULL, closer, NULL))
    return 1;
  if (held_kind == 3) {
    read_vector.iov_base = &redirected_byte;
    read_vector.iov_len = 1;
  }
  int close_state = classify(
      closing,
      (uintptr_t)(replacing ? entered_dup2_return : entered_close_return),
      replacing ? 90 : close_number, &close_done);
  printf("close-wait-observed=%d\n", close_state);
  if (close_state < 0)
    return 1;
  if (close_state != 1)
    return 83;
  thread_t held_port = 0;
  if (held_kind == 1 || held_kind == 2) {
    held_port = pthread_mach_thread_np(held_kind == 1 ? closing : reading);
    if (thread_suspend(held_port))
      return 89;
  }
  pthread_t observing;
  if (pthread_create(&observing, NULL, observer, NULL))
    return 84;
  unsigned observer_number = !strcmp(operation, "getfd")          ? 92
                             : !strcmp(operation, "allocate")     ? 41
                             : !strcmp(operation, "read")         ? 3
                             : !strcmp(operation, "close-source") ? 6
                                                                  : 90;
  int observer_state = classify(observing, (uintptr_t)entered_read_return,
                                observer_number, &operation_done);
  printf("operation=%s observed-wait=%d completed-before-release=%u\n",
         operation, observer_state,
         atomic_load_explicit(&operation_done, memory_order_acquire));
  if (observer_state < 0)
    return 85;
  unsigned read_before_release =
      atomic_load_explicit(&read_done, memory_order_acquire);
  printf("read-complete-before-release=%u\n", read_before_release);
  errno = 0;
  ssize_t written = write(original[1], "ac", 2);
  int write_error = written < 0 ? errno : 0;
  if (held_port) {
    if (pthread_join(observing, NULL))
      return 90;
    if (held_kind == 1 && pthread_join(reading, NULL))
      return 90;
    int released = 0, closing_joined = 0;
    uint64_t release_deadline = now_ns() + 10000000000ULL;
    while (now_ns() < release_deadline) {
      if (replacing) {
        if (fcntl(original[0], F_GETFD) >= 0) {
          released = 1;
          break;
        }
      } else {
        int allocated = dup(original[1]);
        if (allocated < 0)
          return 91;
        released = allocated == original[0];
        if (close(allocated))
          return 92;
        if (released)
          break;
      }
      usleep(1000);
    }
    if (held_kind == 2 && released) {
      if (pthread_join(closing, NULL))
        return 90;
      closing_joined = 1;
    }
    printf("reservation-released-while-held=%d close-done=%u\n", released,
           atomic_load_explicit(&close_done, memory_order_acquire));
#if defined(__aarch64__)
    arm_thread_state64_t held;
    mach_msg_type_number_t held_count = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(held_port, ARM_THREAD_STATE64, (thread_state_t)&held,
                         &held_count))
      return 93;
    printf("held-result=%llu carry=%u\n", (unsigned long long)held.__x[0],
           (held.__cpsr >> 29) & 1);
#else
    x86_thread_state64_t held;
    mach_msg_type_number_t held_count = x86_THREAD_STATE64_COUNT;
    if (thread_get_state(held_port, x86_THREAD_STATE64, (thread_state_t)&held,
                         &held_count))
      return 93;
    printf("held-result=%llu carry=%u\n", (unsigned long long)held.__rax,
           (unsigned)(held.__rflags & 1));
#endif
    if (thread_resume(held_port))
      return 94;
    if (held_kind == 2 && pthread_join(reading, NULL))
      return 94;
    if (!closing_joined && pthread_join(closing, NULL))
      return 94;
  } else if (pthread_join(reading, NULL) || pthread_join(closing, NULL) ||
             pthread_join(observing, NULL))
    return 1;
  printf("original-write=%ld errno=%d\n", (long)written, write_error);
  printf("read-result=%ld carry=%u byte=%u\n", read_result, read_carry, byte);
  printf("close-result=%ld carry=%u\n", close_result, close_carry);
  printf("redirected-byte=%u\n", redirected_byte);
  printf("operation-result=%ld carry=%u byte=%u\n", operation_result,
         operation_carry, operation_byte);
  if (!strcmp(operation, "allocate") && !operation_carry &&
      operation_result >= 0 && close((int)operation_result))
    return 86;
  errno = 0;
  int destination_flags = fcntl(original[0], F_GETFD);
  int destination_error = destination_flags < 0 ? errno : 0;
  printf("destination-flags=%d errno=%d\n", destination_flags,
         destination_error);
  int cleanup[] = {original[0], original[1], replacement[0], replacement[1]};
  for (unsigned i = 0; i < sizeof cleanup / sizeof *cleanup; ++i) {
    if (fcntl(cleanup[i], F_GETFD) < 0) {
      if (errno != EBADF)
        return 87;
    } else if (close(cleanup[i]))
      return 88;
  }
  if (alias >= 0 && alias != closing_fd && close(alias))
    return 1;
  if (named == 2 && (unlink(fifo_paths[0]) || unlink(fifo_paths[1])))
    return 96;
  return 0;
}

/* Each child begins with independent descriptors, Mach threads and static
 * state. The parent reports observed results; the Rust harness compares the
 * complete native transcript with the emulator, including every nonzero child
 * status. */
static unsigned case_count;
static int one(char *mode, char *read_mode, char *close_mode, char *kind,
               char *op, char *control) {
  printf("fixture-case=%u control=%s\n", ++case_count, control);
  pid_t child = fork();
  if (child < 0)
    return 97;
  if (child == 0) {
    char *args[] = {"fd_fifo_lifetime",
                    mode,
                    read_mode,
                    close_mode,
                    kind,
                    op,
                    control,
                    NULL};
    _exit(run_case(7, args));
  }
  int status;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
    return 98;
  int result = WEXITSTATUS(status);
  if (result)
    printf("child-status=%d\n", result);
  return result;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  if (argc != 1)
    return run_case(argc, argv);
  char *kinds[] = {"fifo", "fifo-linked"};
  char *modes[] = {"close", "dup2"};
  char *reads[] = {"read", "read-nocancel", "readv", "readv-nocancel"};
  char *closes[] = {"close", "close-nocancel"};
  char *operations[] = {"getfd",    "allocate",       "read",
                        "same-dup", "replace-target", "close-source"};
  for (unsigned k = 0; k < 2; ++k) {
    for (unsigned m = 0; m < 2; ++m) {
      for (unsigned r = 0; r < 4; ++r) {
        for (unsigned c = 0; c < (m ? 1u : 2u); ++c) {
          for (unsigned o = 0; o < 6; ++o) {
            int result = one(modes[m], reads[r], closes[c], kinds[k],
                             operations[o], "ordinary");
            if (result)
              return result;
          }
          for (unsigned h = 0; h < 2; ++h) {
            int result = one(modes[m], reads[r], closes[c], kinds[k], "getfd",
                             h ? "held-read" : "held-close");
            if (result)
              return result;
          }
        }
        if (r >= 2) {
          int result = one(modes[m], reads[r], "close", kinds[k], "getfd",
                           "vector-rewrite");
          if (result)
            return result;
        }
      }
    }
  }
  printf("fifo-lifetime-complete cases=%u\n", case_count);
  return case_count == 200 ? 0 : 99;
}
