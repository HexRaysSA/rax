/* Seccomp under tracing without CAP_SYS_ADMIN (kernel/ptrace.c,
 * kernel/seccomp.c, CONFIG_CHECKPOINT_RESTORE): PTRACE_O_SUSPEND_SECCOMP
 * refused (EPERM) by PTRACE_SETOPTIONS and PTRACE_SEIZE, after unknown
 * options (EINVAL, and EIO for PTRACE_SEIZE); PTRACE_SECCOMP_GET_FILTER and
 * PTRACE_SECCOMP_GET_METADATA refused (EACCES) before their arguments are
 * looked at, and after ptrace_check_attach (ESRCH for a running tracee);
 * and the tracee's filter still in force. Runs as an unprivileged user
 * (root drops to 65534 first, then makes itself dumpable again, which the
 * change of user undid), as CAP_SYS_ADMIN would decide every check. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER 0x420c
#endif
#ifndef PTRACE_SECCOMP_GET_METADATA
#define PTRACE_SECCOMP_GET_METADATA 0x420d
#endif
#ifndef PTRACE_O_SUSPEND_SECCOMP
#define PTRACE_O_SUSPEND_SECCOMP (1 << 21)
#endif

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

/* SECCOMP_RET_ERRNO | EPERM for getppid. */
static void filter(void) {
    struct sock_filter prog[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fp = {sizeof prog / sizeof prog[0], prog};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fp);
}

int main(void) {
    if (geteuid() == 0 && (setgid(65534) || setuid(65534))) {
        printf("FAIL drop privileges\n");
        return 1;
    }
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    int go[2];
    pipe(go);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        filter();
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        /* Still filtered once resumed. */
        errno = 0;
        int ok = syscall(SYS_getppid) == -1 && errno == EPERM;
        char b;
        read(go[0], &b, 1);
        _exit(ok ? 0 : 1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    CHECK("stopped", WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
    CHECK_ERR("suspend-unknown", pt(PTRACE_SETOPTIONS, c, 0, (void *)(PTRACE_O_SUSPEND_SECCOMP | (1 << 22))),
              EINVAL);
    CHECK_ERR("suspend", pt(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_SUSPEND_SECCOMP), EPERM);
    CHECK_ERR("get-filter", pt(PTRACE_SECCOMP_GET_FILTER, c, 0, 0), EACCES);
    CHECK_ERR("get-filter-past", pt(PTRACE_SECCOMP_GET_FILTER, c, (void *)9, 0), EACCES);
    uint64_t md[2] = {0, 0};
    CHECK_ERR("get-metadata", pt(PTRACE_SECCOMP_GET_METADATA, c, (void *)sizeof md, md), EACCES);
    CHECK_ERR("get-metadata-small", pt(PTRACE_SECCOMP_GET_METADATA, c, (void *)4, md), EACCES);
    pt(PTRACE_CONT, c, 0, 0);
    /* Running: ptrace_check_attach refuses first. */
    CHECK_ERR("get-filter-running", pt(PTRACE_SECCOMP_GET_FILTER, c, 0, 0), ESRCH);
    write(go[1], "x", 1);
    CHECK("filtered", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* PTRACE_SEIZE: unknown options EIO, then the option EPERM. */
    fflush(stdout);
    pid_t d = fork();
    if (d == 0) {
        pause();
        _exit(0);
    }
    CHECK_ERR("seize-unknown", pt(PTRACE_SEIZE, d, 0, (void *)(PTRACE_O_SUSPEND_SECCOMP | (1 << 22))), EIO);
    CHECK_ERR("seize-suspend", pt(PTRACE_SEIZE, d, 0, (void *)PTRACE_O_SUSPEND_SECCOMP), EPERM);
    CHECK("seize", pt(PTRACE_SEIZE, d, 0, (void *)PTRACE_O_EXITKILL) == 0);
    kill(d, SIGKILL);
    CHECK("seize-killed", waitpid(d, &st, 0) == d && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
    FINISH();
}
