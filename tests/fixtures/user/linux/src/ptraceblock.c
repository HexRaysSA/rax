/* x86-64's block steps and its register sets without contents
 * (kernel/ptrace.c, arch/x86/kernel/{step,traps,ptrace}.c,
 * arch/x86/kernel/fpu/regset.c, kernel/regset.c; Intel SDM Vol. 3B
 * §19.4.3): PTRACE_SINGLEBLOCK traps (SIGTRAP, TRAP_TRACE, at the branch's
 * target) only after an instruction that branches: not after a nop or a
 * jz not taken, but after a jmp or a jz taken to the very next
 * instruction, a call, a ret, and a jmp; NT_386_IOPERM reads ENXIO (no
 * I/O permission bitmap) and has no writer (EOPNOTSUPP), and NT_X86_SHSTK
 * is ENODEV without shadow stacks. Elsewhere PTRACE_SINGLEBLOCK is an
 * unknown request (EIO) that leaves the tracee stopped, and the x86 sets
 * do not exist (EINVAL). The checks have the same names everywhere. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#ifndef PTRACE_SINGLEBLOCK
#define PTRACE_SINGLEBLOCK 33
#endif
#ifndef NT_386_IOPERM
#define NT_386_IOPERM 0x201
#endif
#ifndef NT_X86_SHSTK
#define NT_X86_SHSTK 0x204
#endif

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

#ifdef __x86_64__
/* Branches and non-branches, ending in int3. */
extern char blk_start[], blk_jmp[], blk_jz[], blk_callee[], blk_ret[], blk_end[];
__asm__(".text\n"
        ".globl blk_start\n"
        "blk_start:\n"
        "  nop\n"
        "  mov $1, %eax\n"
        "  test %eax, %eax\n" /* ZF clear */
        "  jz 1f\n"           /* not taken */
        "1:\n"
        "  jmp blk_jmp\n" /* taken, to the next instruction */
        ".globl blk_jmp\n"
        "blk_jmp:\n"
        "  xor %eax, %eax\n" /* ZF set */
        "  jz blk_jz\n"      /* taken, to the next instruction */
        ".globl blk_jz\n"
        "blk_jz:\n"
        "  call blk_callee\n"
        ".globl blk_ret\n"
        "blk_ret:\n"
        "  jmp blk_end\n"
        ".globl blk_callee\n"
        "blk_callee:\n"
        "  ret\n"
        ".globl blk_end\n"
        "blk_end:\n"
        "  int3\n");
#endif

/* The next stop's signal (-1 if none), and its siginfo. */
static int next(pid_t c, siginfo_t *si) {
    int st = 0;
    if (waitpid(c, &st, 0) != c || !WIFSTOPPED(st))
        return -1;
    memset(si, 0, sizeof *si);
    pt(PTRACE_GETSIGINFO, c, 0, si);
    return WSTOPSIG(st);
}

static void block_steps(pid_t c) {
    siginfo_t si;
#ifdef __x86_64__
    struct user_regs_struct r;
    pt(PTRACE_GETREGS, c, 0, &r);
    r.rip = (uintptr_t)blk_start;
    pt(PTRACE_SETREGS, c, 0, &r);
    char *want[] = {blk_jmp, blk_jz, blk_callee, blk_ret, blk_end};
    int ok = 1;
    for (int i = 0; i < 5; i++) {
        int s = pt(PTRACE_SINGLEBLOCK, c, 0, 0) == 0 ? next(c, &si) : -1;
        if (s != SIGTRAP || si.si_code != TRAP_TRACE || si.si_addr != want[i]) {
            printf("  trap %d: signal %d code %d at %p, not %p\n", i, s, si.si_code, si.si_addr,
                   (void *)want[i]);
            ok = 0;
        }
    }
    CHECK("block-steps", ok);
    /* The int3 at the end: its own SIGTRAP (SI_KERNEL). */
    int s = pt(PTRACE_SINGLEBLOCK, c, 0, 0) == 0 ? next(c, &si) : -1;
    CHECK("block-end", s == SIGTRAP && si.si_code == SI_KERNEL);
#else
    CHECK("block-steps", pt(PTRACE_SINGLEBLOCK, c, 0, 0) == -1 && errno == EIO);
    /* Still in its SIGSTOP stop. */
    memset(&si, 0, sizeof si);
    CHECK("block-end", pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 && si.si_signo == SIGSTOP);
#endif
}

static void empty_sets(pid_t c) {
    static char buf[8192];
    struct iovec io = {buf, sizeof buf};
#ifdef __x86_64__
    int ioperm_read = ENXIO, ioperm_write = EOPNOTSUPP, shstk = ENODEV;
#else
    int ioperm_read = EINVAL, ioperm_write = EINVAL, shstk = EINVAL;
#endif
    CHECK_ERR("ioperm-read", pt(PTRACE_GETREGSET, c, (void *)NT_386_IOPERM, &io), ioperm_read);
    CHECK_ERR("ioperm-write", pt(PTRACE_SETREGSET, c, (void *)NT_386_IOPERM, &io), ioperm_write);
    io.iov_len = 8;
    CHECK_ERR("shstk-read", pt(PTRACE_GETREGSET, c, (void *)NT_X86_SHSTK, &io), shstk);
    CHECK_ERR("shstk-write", pt(PTRACE_SETREGSET, c, (void *)NT_X86_SHSTK, &io), shstk);
}

int main(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        _exit(0);
    }
    siginfo_t si;
    CHECK("stopped", next(c, &si) == SIGSTOP);
    empty_sets(c);
    block_steps(c);
    kill(c, SIGKILL);
    int st = 0;
    CHECK("killed", waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
    FINISH();
}
