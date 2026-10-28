/* Darwin x86-64 TF boundaries shared by Intel's specification and the covered
 * macOS 27.2 Rosetta observations. MOV/POP SS and REP iteration behavior have
 * separate specification-derived CPU tests because Rosetta differs there.
 * Build: clang -arch x86_64 -O0 -Wall -Wextra x86_tf_probe.c -o /tmp/x86-tf
 * Intel SDM 086 Vol. 3B 19.3.1.4; XNU xnu-12377.121.6 x86_64/idt64.s.
 */
#include <signal.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t count, correct, trapno, code;
static volatile uintptr_t expected;
static volatile intptr_t delta;
static int failed;
static _Atomic int read_started, read_released;
static volatile sig_atomic_t read_early;
static int read_parked, write_fd;
static thread_t reader;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal handler needs lock-free flags");

static void trap(int sig, siginfo_t *info, void *ctx) {
  (void)sig;
  ucontext_t *uc = ctx;
  ++count;
  if (atomic_load_explicit(&read_started, memory_order_acquire) &&
      !atomic_load_explicit(&read_released, memory_order_acquire))
    read_early = 1;
  correct = uc->uc_mcontext->__ss.__rip == expected;
  delta = (intptr_t)uc->uc_mcontext->__ss.__rip - (intptr_t)expected;
  trapno = uc->uc_mcontext->__es.__trapno;
  code = info->si_code;
  uc->uc_mcontext->__ss.__rflags &= ~0x100ULL;
}

static void *release_read(void *unused) {
  (void)unused;
  for (unsigned attempt = 0; attempt != 10000; ++attempt) {
    if (atomic_load_explicit(&read_started, memory_order_acquire)) {
      thread_basic_info_data_t info;
      mach_msg_type_number_t size = THREAD_BASIC_INFO_COUNT;
      if (thread_info(reader, THREAD_BASIC_INFO, (thread_info_t)&info, &size) !=
          KERN_SUCCESS)
        break;
      if (info.run_state == TH_STATE_WAITING && info.suspend_count == 0) {
        read_parked = 1;
        atomic_store_explicit(&read_released, 1, memory_order_release);
        int ok = write(write_fd, "r", 1) == 1;
        close(write_fd);
        return (void *)(uintptr_t)!ok;
      }
    }
    usleep(1000);
  }
  atomic_store_explicit(&read_released, 1, memory_order_release);
  close(write_fd);
  return (void *)(uintptr_t)1;
}

#define ENABLE_TF "pushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\t"

static void report(const char *name) {
  printf("%s: count=%d correct=%d trap=%d code=%d delta_bytes=%ld\n", name,
         count, correct, trapno, code, (long)delta);
  failed |= count != 1 || !correct || trapno != 1 || code != 1 || delta != 0;
  count = correct = trapno = code = 0;
  delta = 0;
}

int main(void) {
  struct sigaction sa = {0};
  sa.sa_sigaction = trap;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGTRAP, &sa, NULL))
    return 1;
  alarm(120);
  extern char nop_after[], clear_after[], syscall_after[], read_after[];
  expected = (uintptr_t)nop_after;
  __asm__ volatile(ENABLE_TF "nop\n.globl _nop_after\n_nop_after:\n"
                   ::: "memory", "cc");
  report("nop");
  expected = (uintptr_t)clear_after;
  __asm__ volatile("pushfq\n\t" ENABLE_TF
                   "popfq\n.globl _clear_after\n_clear_after:\n"
                   ::: "memory", "cc");
  report("clear");
  expected = (uintptr_t)syscall_after;
  __asm__ volatile("mov $0x2000014, %%eax\n\t" ENABLE_TF
                   "syscall\n.globl _syscall_after\n_syscall_after:\n"
                   ::: "rax", "rcx", "r11", "memory", "cc");
  report("syscall");

  int pfd[2];
  if (pipe(pfd))
    return 2;
  reader = mach_thread_self();
  write_fd = pfd[1];
  pthread_t writer;
  if (pthread_create(&writer, NULL, release_read, NULL))
    return 3;
  char byte = 0;
  long value = 0x2000003;
  expected = (uintptr_t)read_after;
  atomic_store_explicit(&read_started, 1, memory_order_release);
  __asm__ volatile(ENABLE_TF "syscall\n.globl _read_after\n_read_after:\nnop\n"
                   : "+a"(value)
                   : "D"((long)pfd[0]), "S"(&byte), "d"(1L)
                   : "rcx", "r11", "memory", "cc");
  report("read");
  void *writer_status = NULL;
  if (pthread_join(writer, &writer_status) || writer_status)
    failed = 1;
  printf("read-result=%ld byte=%c parked=%d early=%d\n", value, byte,
         read_parked, read_early);
  mach_port_deallocate(mach_task_self(), reader);
  close(pfd[0]);
  return failed || value != 1 || byte != 'r' || !read_parked || read_early;
}
