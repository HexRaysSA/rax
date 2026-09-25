/* A stopped tracee's other registers and queues (kernel/ptrace.c,
 * arch/x86/kernel/fpu/regset.c, and the architectures' ptrace.c) between a
 * parent and its child: the floating-point registers (NT_PRFPREG, each
 * architecture's layout, a register and the rounding mode read and
 * written, a length that is not whole registers; on x86-64 the whole-area
 * and MXCSR rules and PTRACE_GETFPREGS, elsewhere a partial write), the
 * thread pointer (x86-64's PTRACE_ARCH_PRCTL, AArch64's NT_ARM_TLS,
 * RISC-V's tp in NT_PRSTATUS), x86-64's XSAVE area (NT_X86_XSTATE),
 * PTRACE_PEEKSIGINFO over the thread's and the process's queues (order,
 * offsets, checks, faults), and PTRACE_GET_RSEQ_CONFIGURATION. The child
 * sets a vector register and stops in one piece of assembly and reads it
 * back as it goes on, so nothing else touches it. Every value that differs
 * between architectures is checked here, not printed. */
#define _GNU_SOURCE
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#ifndef NT_ARM_TLS
#define NT_ARM_TLS 0x401
#endif
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif
#ifndef PTRACE_ARCH_PRCTL
#define PTRACE_ARCH_PRCTL 30
#endif
#define ARCH_GET_FS 0x1003

#if defined(__x86_64__)
#define FP_SIZE 512
/* xmm15 in the FXSAVE area; MXCSR at 24. */
#define FP_REG 400
#define FP_CTL 24
#define CTL_VALUE 0x3f80u /* round down, exceptions masked */
#define CTL_MASK 0x6000u
#elif defined(__aarch64__)
#define FP_SIZE 528
/* v15 in user_fpsimd_state; fpcr at 516. */
#define FP_REG 240
#define FP_CTL 516
#define CTL_VALUE (2u << 22) /* RMode: toward minus infinity */
#define CTL_MASK (3u << 22)
#elif defined(__riscv)
#define FP_SIZE 264
/* fs11 (f27) in __riscv_d_ext_state; fcsr at 256. */
#define FP_REG 216
#define FP_CTL 256
#define CTL_VALUE (2u << 5) /* frm: RDN */
#define CTL_MASK (7u << 5)
#endif

#define BAD ((void *)16)
#define FIRST 0x1122334455667788ull
#define SECOND 0x0badc0dedeadbeefull

struct peek_args {
    uint64_t off;
    uint32_t flags;
    int32_t nr;
};

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static volatile uint64_t thread_pointer;

/* Sets the vector register to FIRST, stops (tkill SIGSTOP), and returns
 * what the register and the rounding control hold as the thread goes on. */
static uint64_t stop_with_register(uint32_t *ctl) {
    long nr = SYS_tkill, tid = syscall(SYS_gettid), sig = SIGSTOP;
    uint64_t out, first = FIRST;
#if defined(__x86_64__)
    uint32_t mxcsr;
    __asm__ volatile("movq %[v], %%xmm15\n\tsyscall\n\tmovq %%xmm15, %[o]\n\tstmxcsr %[m]"
                     : [o] "=r"(out), "+a"(nr), [m] "=m"(mxcsr)
                     : [v] "r"(first), "D"(tid), "S"(sig)
                     : "rcx", "r11", "memory", "xmm15");
    *ctl = mxcsr;
#elif defined(__aarch64__)
    uint64_t fpcr;
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = tid;
    register long x1 __asm__("x1") = sig;
    __asm__ volatile("fmov d15, %[v]\n\tsvc #0\n\tfmov %[o], d15\n\tmrs %[c], fpcr"
                     : [o] "=r"(out), [c] "=r"(fpcr), "+r"(x0)
                     : [v] "r"(first), "r"(x8), "r"(x1)
                     : "memory", "v15");
    *ctl = (uint32_t)fpcr;
#elif defined(__riscv)
    uint64_t fcsr;
    register long a7 __asm__("a7") = nr;
    register long a0 __asm__("a0") = tid;
    register long a1 __asm__("a1") = sig;
    __asm__ volatile("fmv.d.x fs11, %[v]\n\tecall\n\tfmv.x.d %[o], fs11\n\tfrcsr %[c]"
                     : [o] "=r"(out), [c] "=r"(fcsr), "+r"(a0)
                     : [v] "r"(first), "r"(a7), "r"(a1)
                     : "memory", "fs11");
    *ctl = (uint32_t)fcsr;
#endif
    return out;
}

static uint64_t read_tp(void) {
    uint64_t tp;
#if defined(__x86_64__)
    __asm__("movq %%fs:0, %0" : "=r"(tp));
#elif defined(__aarch64__)
    __asm__("mrs %0, tpidr_el0" : "=r"(tp));
#elif defined(__riscv)
    __asm__("mv %0, tp" : "=r"(tp));
#endif
    return tp;
}

static int child(void) {
    pt(PTRACE_TRACEME, 0, 0, 0);
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigaddset(&block, SIGUSR2);
    sigaddset(&block, SIGRTMIN);
    sigaddset(&block, SIGRTMIN + 1);
    sigprocmask(SIG_BLOCK, &block, NULL);
    pid_t me = getpid();
    /* The thread's queue: SIGUSR2, then SIGRTMIN twice with values. */
    raise(SIGUSR2);
    for (int v = 7; v <= 8; v++) {
        siginfo_t si = {.si_signo = SIGRTMIN, .si_code = SI_QUEUE, .si_pid = me};
        si.si_value.sival_int = v;
        syscall(SYS_rt_tgsigqueueinfo, me, syscall(SYS_gettid), SIGRTMIN, &si);
    }
    /* The process's queue: SIGUSR1, then SIGRTMIN+1 with a value. */
    kill(me, SIGUSR1);
    sigqueue(me, SIGRTMIN + 1, (union sigval){.sival_int = 9});
    thread_pointer = read_tp();
    uint32_t ctl = 0;
    uint64_t seen = stop_with_register(&ctl);
    return seen == SECOND && (ctl & CTL_MASK) == (CTL_VALUE & CTL_MASK) ? 0 : 1;
}

static int getregset(pid_t c, long nt, void *buf, size_t *len) {
    struct iovec iov = {buf, *len};
    int r = pt(PTRACE_GETREGSET, c, (void *)nt, &iov);
    *len = iov.iov_len;
    return r;
}

static int setregset(pid_t c, long nt, void *buf, size_t len) {
    struct iovec iov = {buf, len};
    return pt(PTRACE_SETREGSET, c, (void *)nt, &iov);
}

static void fp_registers(pid_t c) {
    unsigned char fp[1024], back[1024];
    size_t len = sizeof fp;
    uint64_t reg = 0;
    uint32_t ctl = 0;
    int got = getregset(c, NT_PRFPREG, fp, &len) == 0 && len == FP_SIZE;
    memcpy(&reg, fp + FP_REG, 8);
    CHECK("fpregs-get", got && reg == FIRST);
    size_t six = 6;
    CHECK_ERR("fpregs-length", getregset(c, NT_PRFPREG, back, &six), EINVAL);
    reg = SECOND;
    memcpy(fp + FP_REG, &reg, 8);
    memcpy(&ctl, fp + FP_CTL, 4);
    ctl = (ctl & ~CTL_MASK) | CTL_VALUE;
    memcpy(fp + FP_CTL, &ctl, 4);
    len = sizeof back;
    CHECK("fpregs-set", setregset(c, NT_PRFPREG, fp, FP_SIZE) == 0 &&
                            getregset(c, NT_PRFPREG, back, &len) == 0 && len == FP_SIZE &&
                            memcmp(fp, back, FP_SIZE) == 0);
#if defined(__x86_64__)
    /* xfpregs_set: the whole area only, and no reserved MXCSR bit;
     * PTRACE_GETFPREGS is the same set. */
    unsigned char bad[512];
    memcpy(bad, fp, 512);
    uint32_t reserved = 1u << 16;
    memcpy(bad + FP_CTL, &reserved, 4);
    int rules = setregset(c, NT_PRFPREG, fp, 256) == -1 && errno == EINVAL;
    rules &= setregset(c, NT_PRFPREG, bad, 512) == -1 && errno == EINVAL;
    rules &= pt(PTRACE_GETFPREGS, c, 0, back) == 0 && memcmp(fp, back, 512) == 0;
    CHECK("fpregs-rules", rules);
#else
    /* A prefix: the first register alone. */
    CHECK("fpregs-rules", setregset(c, NT_PRFPREG, fp, 8) == 0);
#endif
}

static void thread_pointer_of(pid_t c) {
    long tp = 0;
    int ok = pt(PTRACE_PEEKDATA, c, (void *)&thread_pointer, &tp) == 0 && tp != 0;
#if defined(__x86_64__)
    uint64_t fs = 0;
    ok &= pt(PTRACE_ARCH_PRCTL, c, &fs, (void *)ARCH_GET_FS) == 0 && fs == (uint64_t)tp;
    size_t len = 4096;
    static unsigned char xs[8192];
    uint64_t xmm15 = 0;
    int xstate = getregset(c, NT_X86_XSTATE, xs, &len) == 0 && len > 576;
    memcpy(&xmm15, xs + FP_REG, 8);
    xstate &= xmm15 == SECOND && *(uint32_t *)(xs + 464) == 0x46505853;
    CHECK("xstate", xstate);
#elif defined(__aarch64__)
    uint64_t tls[2] = {0, 1};
    size_t len = sizeof tls;
    ok &= getregset(c, NT_ARM_TLS, tls, &len) == 0 && len == 16 && tls[0] == (uint64_t)tp;
    size_t n = 64;
    CHECK("xstate", getregset(c, NT_X86_XSTATE, (void *)&tls, &n) == -1 && errno == EINVAL);
#elif defined(__riscv)
    uint64_t regs[32];
    size_t len = sizeof regs;
    ok &= getregset(c, NT_PRSTATUS, regs, &len) == 0 && regs[4] == (uint64_t)tp;
    size_t n = 64;
    CHECK("xstate", getregset(c, NT_X86_XSTATE, regs, &n) == -1 && errno == EINVAL);
#endif
    CHECK("thread-pointer", ok);
}

static void peek(pid_t c) {
    siginfo_t si[8];
    struct peek_args a = {0, 0, 8};
    long n = pt(PTRACE_PEEKSIGINFO, c, &a, si);
    CHECK("peek-thread", n == 3 && si[0].si_signo == SIGUSR2 && si[0].si_code == SI_TKILL &&
                             si[1].si_signo == SIGRTMIN && si[1].si_value.sival_int == 7 &&
                             si[2].si_signo == SIGRTMIN && si[2].si_value.sival_int == 8 &&
                             si[2].si_code == SI_QUEUE && si[2].si_pid == c);
    a = (struct peek_args){1, 0, 1};
    n = pt(PTRACE_PEEKSIGINFO, c, &a, si);
    CHECK("peek-offset", n == 1 && si[0].si_value.sival_int == 7);
    a = (struct peek_args){0, PTRACE_PEEKSIGINFO_SHARED, 8};
    n = pt(PTRACE_PEEKSIGINFO, c, &a, si);
    CHECK("peek-process", n == 2 && si[0].si_signo == SIGUSR1 && si[0].si_code == SI_USER &&
                              si[1].si_signo == SIGRTMIN + 1 && si[1].si_value.sival_int == 9);
    a = (struct peek_args){5, 0, 8};
    CHECK("peek-past-end", pt(PTRACE_PEEKSIGINFO, c, &a, si) == 0);
    a = (struct peek_args){0, 0, 0};
    CHECK("peek-none", pt(PTRACE_PEEKSIGINFO, c, &a, si) == 0);
    a = (struct peek_args){0, 2, 1};
    CHECK_ERR("peek-flags", pt(PTRACE_PEEKSIGINFO, c, &a, si), EINVAL);
    a = (struct peek_args){0, 0, -1};
    CHECK_ERR("peek-count", pt(PTRACE_PEEKSIGINFO, c, &a, si), EINVAL);
    CHECK_ERR("peek-args-fault", pt(PTRACE_PEEKSIGINFO, c, BAD, si), EFAULT);
    a = (struct peek_args){0, 0, 1};
    CHECK_ERR("peek-fault", pt(PTRACE_PEEKSIGINFO, c, &a, BAD), EFAULT);
}

static void rseq_configuration(pid_t c) {
    unsigned char conf[32];
    memset(conf, 0x5a, sizeof conf);
    /* musl registers no rseq area: all zero; a short buffer gets its
     * part, and the size comes back whole. */
    long n = pt(0x420f, c, (void *)8, conf);
    int zero = 1;
    for (int i = 0; i < 8; i++)
        zero &= conf[i] == 0;
    CHECK("rseq-configuration", n == 24 && zero && conf[8] == 0x5a);
}

int main(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0)
        _exit(child());
    int st = 0;
    CHECK("stop", waitpid(c, &st, 0) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
    fp_registers(c);
    thread_pointer_of(c);
    peek(c);
    rseq_configuration(c);
    pt(PTRACE_CONT, c, 0, 0);
    CHECK("tracee-saw-writes", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    FINISH();
}
