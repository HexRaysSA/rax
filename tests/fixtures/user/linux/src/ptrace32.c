/* Tracing by an i386 tracer (i386 only): compat_ptrace_request's 32-bit
 * words (PEEKDATA and POKEDATA at a page's end, GETEVENTMSG), struct
 * compat_siginfo, and struct compat_iovec; ia32_arch_ptrace's struct
 * user_regs_struct32, struct user32 offsets (PEEKUSR, POKEUSR), the FSAVE
 * environment (GETFPREGS) and FXSAVE area (GETFPXREGS), the TLS entries
 * (GET_THREAD_AREA, NT_386_TLS); the i386 register view of a 32-bit
 * tracee (GETREGSET); and a stop the tracer has not waited for, which a
 * SIGKILL ends at once. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "ptrace32 is an i386 program"
#endif

#define GETFPXREGS 18
#define GET_THREAD_AREA 25
#define SET_THREAD_AREA 26
#define ARCH_PRCTL 30
#define NT_PRXFPREG 0x46e62b7f
#define NT_386_TLS 0x200
#define NT_386_IOPERM 0x201
#define NT_X86_SHSTK 0x204

static long pt(long req, pid_t pid, long addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

/* A page whose successor is not mapped, shared with the child. */
static char *page;

static void child(void) {
    pt(PTRACE_TRACEME, 0, 0, 0);
    memcpy(page + 4088, "abcdefgh", 8);
    raise(SIGSTOP);
    /* Resumed: a second stop the tracer never waits for. */
    raise(SIGUSR1);
    _exit(0);
}

int main(void) {
    fflush(stdout);
    page = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    munmap(page + 4096, 4096);
    pid_t c = fork();
    if (c == 0) child();
    int st = 0;
    CHECK("stopped", waitpid(c, &st, 0) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);

    /* 32-bit words: a word read and written at a page's end, the bytes
     * past it untouched. */
    uint32_t w = 0;
    CHECK("peekdata", pt(PTRACE_PEEKDATA, c, (long)(page + 4092), &w) == 0 &&
                          w == 0x68676665);
    CHECK("pokedata", pt(PTRACE_POKEDATA, c, (long)(page + 4088), (void *)0x44434241) == 0 &&
                          !memcmp(page + 4088, "ABCDefgh", 8));

    /* struct compat_siginfo of the stop. */
    unsigned char si[128];
    memset(si, 0xEE, sizeof si);
    int32_t v;
    CHECK("getsiginfo", pt(PTRACE_GETSIGINFO, c, 0, si) == 0 &&
                            (memcpy(&v, si, 4), v == SIGSTOP) &&
                            (memcpy(&v, si + 12, 4), v == c));

    /* struct user_regs_struct32, and struct user32's words. */
    struct user_regs_struct r;
    memset(&r, 0xEE, sizeof r);
    CHECK("getregs", pt(PTRACE_GETREGS, c, 0, &r) == 0 && r.xcs == 0x23 && r.xss == 0x2b &&
                         r.orig_eax != -1);
    uint32_t u = 0;
    CHECK("peekusr-eip",
          pt(PTRACE_PEEKUSER, c, offsetof(struct user, regs.eip), &u) == 0 && u == r.eip);
    CHECK("peekusr-end", pt(PTRACE_PEEKUSER, c, sizeof(struct user), &u) == 0 && u == 0);
    CHECK_ERR("peekusr-past", pt(PTRACE_PEEKUSER, c, sizeof(struct user) + 4, &u), EIO);
    CHECK_ERR("peekusr-misaligned", pt(PTRACE_PEEKUSER, c, 2, &u), EIO);
    CHECK_ERR("pokeusr-cs", pt(PTRACE_POKEUSER, c, offsetof(struct user, regs.xcs), (void *)0x20),
              EIO);
    long ebx = r.ebx;
    CHECK("pokeusr-ebx",
          pt(PTRACE_POKEUSER, c, offsetof(struct user, regs.ebx), (void *)0x1234) == 0 &&
              pt(PTRACE_PEEKUSER, c, offsetof(struct user, regs.ebx), &u) == 0 && u == 0x1234);
    r.ebx = ebx;
    CHECK("setregs", pt(PTRACE_SETREGS, c, 0, &r) == 0 &&
                         pt(PTRACE_PEEKUSER, c, offsetof(struct user, regs.ebx), &u) == 0 &&
                         u == (uint32_t)ebx);

    /* The FSAVE environment and the FXSAVE area. */
    struct user_fpregs_struct fp;
    CHECK("getfpregs", pt(PTRACE_GETFPREGS, c, 0, &fp) == 0 && (fp.cwd & 0xffff) == 0x37f &&
                           ((unsigned long)fp.cwd >> 16) == 0xffff && (fp.fcs & 0xffff) == 0x23);
    CHECK("setfpregs", pt(PTRACE_SETFPREGS, c, 0, &fp) == 0);
    unsigned char fx[512];
    CHECK("getfpxregs", pt(GETFPXREGS, c, 0, fx) == 0 && fx[0] == 0x7f && fx[1] == 0x03 &&
                            (memcpy(&v, fx + 24, 4), v == 0x1f80));

    /* The i386 view through struct compat_iovec: each set's size. */
    static unsigned char buf[8192];
    uint32_t iov[2] = {(uintptr_t)buf, sizeof buf};
    CHECK("regset-prstatus",
          pt(PTRACE_GETREGSET, c, NT_PRSTATUS, iov) == 0 && iov[1] == 68 && iov[0] == (uintptr_t)buf);
    iov[1] = sizeof buf;
    CHECK("regset-prfpreg", pt(PTRACE_GETREGSET, c, NT_PRFPREG, iov) == 0 && iov[1] == 108);
    iov[1] = sizeof buf;
    CHECK("regset-prxfpreg", pt(PTRACE_GETREGSET, c, NT_PRXFPREG, iov) == 0 && iov[1] == 512);
    iov[1] = sizeof buf;
    CHECK("regset-tls", pt(PTRACE_GETREGSET, c, NT_386_TLS, iov) == 0 && iov[1] == 48 &&
                            (memcpy(&v, buf, 4), v == 12) && (memcpy(&v, buf + 32, 4), v == 14));
    iov[1] = 6;
    CHECK_ERR("regset-tls-unit", pt(PTRACE_GETREGSET, c, NT_386_TLS, iov), EINVAL);
    iov[1] = sizeof buf;
    CHECK_ERR("regset-ioperm", pt(PTRACE_GETREGSET, c, NT_386_IOPERM, iov), ENXIO);
    iov[1] = 8;
    CHECK_ERR("regset-shstk", pt(PTRACE_GETREGSET, c, NT_X86_SHSTK, iov), EINVAL);

    /* The TLS entries: musl's thread pointer is entry 12's base. */
    unsigned char desc[16];
    CHECK("get-thread-area", pt(GET_THREAD_AREA, c, 12, desc) == 0 &&
                                 (memcpy(&v, desc, 4), v == 12));
    CHECK_ERR("get-thread-area-range", pt(GET_THREAD_AREA, c, 5, desc), EINVAL);
    CHECK_ERR("get-thread-area-negative", pt(GET_THREAD_AREA, c, -1, desc), EIO);
    memset(desc, 0, sizeof desc);
    desc[12] = 1 << 5; /* seg_not_present without the rest of "empty" */
    CHECK_ERR("set-thread-area-bad", pt(SET_THREAD_AREA, c, 13, desc), EINVAL);
    CHECK_ERR("arch-prctl", pt(ARCH_PRCTL, c, 0, 0), EIO);

    /* The second stop, not waited for: a SIGKILL ends it, and the tracer
     * sees the death. */
    CHECK("cont", pt(PTRACE_CONT, c, 0, 0) == 0);
    siginfo_t info;
    memset(&info, 0, sizeof info);
    CHECK("second-stop", waitid(P_PID, c, &info, WSTOPPED | WNOWAIT) == 0 &&
                             info.si_status == SIGUSR1);
    kill(c, SIGKILL);
    CHECK("killed", waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
    FINISH();
}
