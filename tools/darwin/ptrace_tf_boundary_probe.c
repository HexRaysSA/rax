/* Characterize guest-set x86-64 RFLAGS.TF at instruction boundaries.
 * Build: clang -arch x86_64 -O0 -Wall tools/darwin/ptrace_tf_boundary_probe.c -o
 * /tmp/ptrace-tf-boundary Run: arch -x86_64 /tmp/ptrace-tf-boundary rax-user --arch
 * x86_64 /tmp/ptrace-tf-boundary
 *
 * Intel SDM 086, Vol. 3B, 19.3.1.4 specifies post-instruction traps using
 * the incoming TF, excluding the instruction that sets TF and MOV/POP SS.
 * On macOS 27.2 Rosetta, MOV SS traps immediately (delta_bytes = -1),
 * unlike that specification. Physical Intel behavior is unknown here.
 * This diagnostic reports observations; its exit status is not a parity gate.
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ucontext.h>
#include <unistd.h>
static volatile sig_atomic_t count, correct, trapno, code;
static volatile uintptr_t expected;
static volatile intptr_t delta;
static void trap(int sig, siginfo_t *info, void *ctx) {
  (void)sig;
  ucontext_t *uc = ctx;
  ++count;
  correct = uc->uc_mcontext->__ss.__rip == expected;
  delta = (intptr_t)uc->uc_mcontext->__ss.__rip - (intptr_t)expected;
  trapno = uc->uc_mcontext->__es.__trapno;
  code = info->si_code;
  uc->uc_mcontext->__ss.__rflags &= ~0x100ULL;
}
#define ENABLE_TF "pushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\t"
static void report(const char *s) {
  printf("%s: count=%d correct=%d trap=%d code=%d delta_bytes=%ld\n", s, count, correct,
         trapno, code, (long)delta);
  count = correct = trapno = code = 0;
}
int main(void) {
  struct sigaction sa = {0};
  sa.sa_sigaction = trap;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGTRAP, &sa, NULL))
    return 1;
  alarm(10);
  extern char nop_after[], clear_after[], ss_after[], syscall_after[];
  expected = (uintptr_t)nop_after;
  __asm__ volatile(ENABLE_TF "nop\n.globl _nop_after\n_nop_after:\n" ::: "memory", "cc");
  report("nop");
  expected = (uintptr_t)clear_after;
  __asm__ volatile("pushfq\n\t" ENABLE_TF "popfq\n.globl _clear_after\n_clear_after:\n" ::
                       : "memory", "cc");
  report("clear");
  expected = (uintptr_t)ss_after;
  __asm__ volatile("mov %%ss, %%ax\n\t" ENABLE_TF
                   "mov %%ax, %%ss\n\tnop\n.globl _ss_after\n_ss_after:\n" ::
                       : "rax", "memory", "cc");
  report("movss");
  expected = (uintptr_t)syscall_after;
  __asm__ volatile("mov $0x2000014, %%eax\n\t" ENABLE_TF
                   "syscall\n.globl _syscall_after\n_syscall_after:\n" ::
                       : "rax", "rcx", "r11", "memory", "cc");
  report("syscall");
  return 0;
}
