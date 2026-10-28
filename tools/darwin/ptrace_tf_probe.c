/* Compare guest-set x86-64 RFLAGS.TF on native macOS and rax-user.
 * Build: clang -arch x86_64 -O0 tools/darwin/ptrace_tf_probe.c -o /tmp/ptrace-tf-probe
 * Run:   arch -x86_64 /tmp/ptrace-tf-probe
 *        target/debug/rax-user --arch x86_64 /tmp/ptrace-tf-probe
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ucontext.h>

static volatile sig_atomic_t count;
static volatile sig_atomic_t correct;
extern char tf_after[];

static void trap(int sig, siginfo_t *info, void *ctx) {
    (void)sig;
    (void)info;
    ucontext_t *uc = ctx;
    ++count;
    correct = uc->uc_mcontext->__ss.__rip == (uintptr_t)tf_after;
    uc->uc_mcontext->__ss.__rflags &= ~0x100ULL;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = trap;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGTRAP, &sa, NULL) != 0) return 1;
    __asm__ volatile("pushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\tnop\n\t"
                     ".globl _tf_after\n_tf_after:\n\t" ::: "memory", "cc");
    printf("count=%d correct=%d\n", count, correct);
    return 0;
}
