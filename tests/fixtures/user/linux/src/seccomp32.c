/* Seccomp filters of an i386 task (i386 only): struct compat_sock_fprog
 * (a 16-bit length and a 32-bit pointer, read at a page's end) through
 * seccomp and prctl, and the struct seccomp_data a 32-bit call gives the
 * filter: AUDIT_ARCH_I386, i386 call numbers, zero-extended arguments, and
 * a 32-bit instruction pointer; SECCOMP_RET_TRAP's SIGSYS with its
 * struct compat_siginfo fields, and the call's registers rolled back. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "seccomp32 is an i386 program"
#endif

#define NR_SECCOMP 354

static volatile int trapped_nr, trapped_errno;
static volatile unsigned trapped_arch;
static volatile uintptr_t trapped_addr;

static void on_sigsys(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    trapped_nr = si->si_syscall;
    trapped_arch = si->si_arch;
    trapped_addr = (uintptr_t)si->si_call_addr;
    trapped_errno = si->si_errno;
}

/* A struct compat_sock_fprog for `prog` at the end of `page`. */
static void *fprog_at(char *end, struct sock_filter *prog, unsigned short len) {
    uint32_t *f = (uint32_t *)(end - 8);
    f[0] = len;
    f[1] = (uintptr_t)prog;
    return f;
}

int main(void) {
    char *page = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(page + 4096, 4096);
    char *end = page + 4096;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, 0);
    CHECK("no-new-privs", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    /* The architecture, then getpid (trapped), then the high word of the
     * first argument and of the instruction pointer. */
    struct sock_filter prog[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | 42),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    unsigned short n = sizeof prog / sizeof prog[0];
    CHECK_ERR("empty-program", syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, 0,
                                       fprog_at(end, prog, 0)),
              EINVAL);
    CHECK("install", syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, fprog_at(end, prog, n)) ==
                         0);
    /* A 32-bit -1 argument reaches the filter zero-extended. */
    CHECK_ERR("zero-extended-argument", close(-1), EBADF);
    /* The trap: SIGSYS with the call, the architecture, the address after
     * the call, and the filter's data; the call's registers rolled back,
     * so it returns its own number. */
    long r = syscall(SYS_getpid);
    CHECK("trap", r == SYS_getpid && trapped_nr == SYS_getpid &&
                      trapped_arch == AUDIT_ARCH_I386 && trapped_addr != 0 &&
                      trapped_errno == 42);

    /* prctl(PR_SET_SECCOMP) reads the same structure: getppid refused
     * with EPERM. */
    struct sock_filter deny[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    CHECK("prctl-install",
          prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog_at(end, deny, 4), 0, 0) == 0);
    CHECK_ERR("prctl-filter", syscall(SYS_getppid), EPERM);
    FINISH();
}
