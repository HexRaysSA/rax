/* Seccomp (kernel/seccomp.c). The operations and their checks in order;
 * installing filters (no_new_privs or CAP_SYS_ADMIN, the program checks,
 * the instruction bound, the mode rules) with prctl and seccomp; what
 * filters decide (errno, capped; the lowest action winning, the newest on
 * a tie; TRACE and USER_NOTIF without a tracer or listener) and what they
 * see (the architecture, the number, the arguments); SECCOMP_RET_TRAP's
 * SIGSYS, fatal when SIGSYS is blocked or ignored; the kill actions
 * against the number of threads; strict mode, for the process and for one
 * thread; inheritance by threads, children, and executed programs; TSYNC;
 * the /proc status lines. Each part runs in a child process, as filters
 * cannot be removed. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#if defined(__x86_64__)
#define ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#elif defined(__riscv) && __riscv_xlen == 64
#define ARCH AUDIT_ARCH_RISCV64
#endif

#define NR offsetof(struct seccomp_data, nr)
#define ARG0 offsetof(struct seccomp_data, args[0])
#define RET(k) BPF_STMT(BPF_RET | BPF_K, (k))
#define LD(off) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (off))
/* Returns `hit` for call `nr`, and SECCOMP_RET_ALLOW for the others. */
#define ON(nr, hit) {LD(NR), BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), RET(hit), \
                     RET(SECCOMP_RET_ALLOW)}

static char **self_argv;

static long sc(unsigned op, unsigned flags, void *args) {
    return syscall(SYS_seccomp, op, flags, args);
}

static long install(struct sock_filter *f, unsigned short n, unsigned flags) {
    struct sock_fprog p = {n, f};
    return sc(SECCOMP_SET_MODE_FILTER, flags, &p);
}

static int nnp(void) {
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

/* The value of a /proc status line of `path`, or -1. */
static long status(const char *path, const char *key) {
    static char buf[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    char want[64];
    snprintf(want, sizeof want, "\n%s:\t", key);
    char *p = strstr(buf, want);
    return p ? strtol(p + strlen(want), NULL, 10) : -1;
}

static int status_is(const char *path, long nnp_, long mode, long filters) {
    return status(path, "NoNewPrivs") == nnp_ && status(path, "Seccomp") == mode &&
           status(path, "Seccomp_filters") == filters;
}

/* Runs `fn` in a child process; returns its wait status. */
static int run(void (*fn)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        failures = 0;
        fn();
        fflush(stdout);
        _exit(failures ? 1 : 0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return st;
}

static int clean(int st) {
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static int killed_by(int st, int sig) {
    return WIFSIGNALED(st) && WTERMSIG(st) == sig;
}

/* The operations that do not install anything. */
static void operations(void) {
    CHECK("mode-none", prctl(PR_GET_SECCOMP) == 0);
    CHECK("status-none", status_is("/proc/self/status", 0, 0, 0));
    static const unsigned actions[] = {
        SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP,
        SECCOMP_RET_ERRNO,        SECCOMP_RET_USER_NOTIF,  SECCOMP_RET_TRACE,
        SECCOMP_RET_LOG,          SECCOMP_RET_ALLOW,
    };
    int avail = 1;
    for (unsigned i = 0; i < sizeof actions / sizeof actions[0]; i++)
        avail &= sc(SECCOMP_GET_ACTION_AVAIL, 0, (void *)&actions[i]) == 0;
    CHECK("actions-available", avail);
    unsigned unknown = 0x00010000, with_data = SECCOMP_RET_ERRNO | 1;
    CHECK_ERR("action-unknown", sc(SECCOMP_GET_ACTION_AVAIL, 0, &unknown), EOPNOTSUPP);
    CHECK_ERR("action-with-data", sc(SECCOMP_GET_ACTION_AVAIL, 0, &with_data), EOPNOTSUPP);
    CHECK_ERR("action-flags", sc(SECCOMP_GET_ACTION_AVAIL, 1, &unknown), EINVAL);
    CHECK_ERR("action-fault", sc(SECCOMP_GET_ACTION_AVAIL, 0, (void *)8), EFAULT);
    struct seccomp_notif_sizes sizes = {0};
    CHECK("notif-sizes", sc(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0 && sizes.seccomp_notif == 80 &&
                             sizes.seccomp_notif_resp == 24 && sizes.seccomp_data == 64);
    CHECK_ERR("notif-sizes-flags", sc(SECCOMP_GET_NOTIF_SIZES, 1, &sizes), EINVAL);
    CHECK_ERR("notif-sizes-fault", sc(SECCOMP_GET_NOTIF_SIZES, 0, (void *)8), EFAULT);
    CHECK_ERR("op-unknown", sc(4, 0, NULL), EINVAL);
    CHECK_ERR("strict-flags", sc(SECCOMP_SET_MODE_STRICT, 1, NULL), EINVAL);
    CHECK_ERR("strict-args", sc(SECCOMP_SET_MODE_STRICT, 0, &sizes), EINVAL);
    CHECK_ERR("prctl-mode-unknown", prctl(PR_SET_SECCOMP, 3, 0, 0, 0), EINVAL);
    struct sock_filter allow[] = {RET(SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {1, allow};
    CHECK_ERR("flag-unknown", sc(SECCOMP_SET_MODE_FILTER, 0x40, &p), EINVAL);
    CHECK_ERR("flag-tsync-listener",
              sc(SECCOMP_SET_MODE_FILTER,
                 SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER, &p),
              EINVAL);
    CHECK_ERR("flag-killable-alone",
              sc(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, &p), EINVAL);
    CHECK_ERR("fprog-fault", sc(SECCOMP_SET_MODE_FILTER, 0, (void *)8), EFAULT);
    struct sock_fprog empty = {0, allow}, big = {BPF_MAXINSNS + 1, allow};
    CHECK_ERR("length-zero", sc(SECCOMP_SET_MODE_FILTER, 0, &empty), EINVAL);
    CHECK_ERR("length-over", sc(SECCOMP_SET_MODE_FILTER, 0, &big), EINVAL);
}

/* Without no_new_privs, as a user without CAP_SYS_ADMIN. */
static void unprivileged(void) {
    if (geteuid() == 0 && (setgid(65534) || setuid(65534))) {
        CHECK("drop-privileges", 0);
        return;
    }
    struct sock_filter allow[] = {RET(SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {1, allow}, empty = {0, allow};
    CHECK_ERR("needs-no-new-privs", sc(SECCOMP_SET_MODE_FILTER, 0, &p), EACCES);
    CHECK_ERR("prctl-needs-no-new-privs", prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p, 0, 0),
              EACCES);
    CHECK_ERR("length-before-privilege", sc(SECCOMP_SET_MODE_FILTER, 0, &empty), EINVAL);
    CHECK("mode-still-none", prctl(PR_GET_SECCOMP) == 0);
}

static struct sock_filter bigprog[BPF_MAXINSNS];

/* bigprog as `n` returns of K, with a return of A after them if `ret_a`:
 * as converted to eBPF, 3 + 2 * n instructions, and one more with it. */
static struct sock_filter *returns(int n, int ret_a) {
    for (int i = 0; i < n; i++)
        bigprog[i] = (struct sock_filter)RET(SECCOMP_RET_ALLOW);
    if (ret_a)
        bigprog[n] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
    return bigprog;
}

static void installing(void) {
    CHECK("nnp-off", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
    CHECK_ERR("nnp-set-args", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 1), EINVAL);
    CHECK_ERR("nnp-set-value", prctl(PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0), EINVAL);
    CHECK("nnp-set", nnp() == 0);
    CHECK_ERR("nnp-get-args", prctl(PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0), EINVAL);
    CHECK("nnp-on", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    struct sock_fprog null = {1, NULL}, far = {1, (void *)8};
    CHECK_ERR("program-null", sc(SECCOMP_SET_MODE_FILTER, 0, &null), EINVAL);
    CHECK_ERR("program-fault", sc(SECCOMP_SET_MODE_FILTER, 0, &far), EFAULT);
    struct sock_filter no_ret[] = {LD(NR)};
    struct sock_filter past_data[] = {LD(64), RET(SECCOMP_RET_ALLOW)};
    struct sock_filter unaligned[] = {LD(2), RET(SECCOMP_RET_ALLOW)};
    struct sock_filter jump_out[] = {BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0),
                                     RET(SECCOMP_RET_ALLOW)};
    struct sock_filter div_zero[] = {BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 0),
                                     RET(SECCOMP_RET_ALLOW)};
    struct sock_filter indirect[] = {BPF_STMT(BPF_LD | BPF_W | BPF_IND, 0),
                                     RET(SECCOMP_RET_ALLOW)};
    struct sock_filter unset_mem[] = {BPF_STMT(BPF_LD | BPF_MEM, 3), RET(SECCOMP_RET_ALLOW)};
    CHECK_ERR("program-no-return", install(no_ret, 1, 0), EINVAL);
    CHECK_ERR("program-past-data", install(past_data, 2, 0), EINVAL);
    CHECK_ERR("program-unaligned", install(unaligned, 2, 0), EINVAL);
    CHECK_ERR("program-jump-out", install(jump_out, 2, 0), EINVAL);
    CHECK_ERR("program-divide-zero", install(div_zero, 2, 0), EINVAL);
    CHECK_ERR("program-indirect", install(indirect, 2, 0), EINVAL);
    CHECK_ERR("program-unset-memory", install(unset_mem, 2, 0), EINVAL);
    CHECK("status-nnp", status_is("/proc/self/status", 1, 0, 0));
    struct sock_filter allow[] = {RET(SECCOMP_RET_ALLOW)};
    CHECK("install", install(allow, 1, SECCOMP_FILTER_FLAG_LOG) == 0);
    CHECK("mode-filter", prctl(PR_GET_SECCOMP) == 2);
    CHECK("status-filter", status_is("/proc/self/status", 1, 2, 1));
    CHECK_ERR("then-strict", sc(SECCOMP_SET_MODE_STRICT, 0, NULL), EINVAL);
    CHECK_ERR("then-prctl-strict", prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0), EINVAL);
    struct sock_fprog p = {1, allow};
    CHECK("prctl-install", prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p, 0, 0) == 0);
    /* MAX_INSNS_PER_PATH counts eBPF instructions, each filter 4 more:
     * the two returns of K are 3 + 2 = 5 each, 4096 of them 8195, and
     * 2 * (5 + 4) + 3 * (8195 + 4) + 8195 > 32768. */
    int fit = 1;
    for (int i = 0; i < 3; i++)
        fit &= install(returns(BPF_MAXINSNS, 0), BPF_MAXINSNS, 0) == 0;
    CHECK("chain-fits", fit);
    CHECK_ERR("chain-over", install(returns(BPF_MAXINSNS, 0), BPF_MAXINSNS, 0), ENOMEM);
    /* 32768 - 18 - 3 * 8199 = 8153 = 3 + 2 * 4075. */
    CHECK_ERR("chain-over-by-one", install(returns(4075, 1), 4076, 0), ENOMEM);
    CHECK("chain-exact", install(returns(4075, 0), 4075, 0) == 0);
    CHECK("status-chain", status_is("/proc/self/status", 1, 2, 6));
}

/* Every kind of conversion to eBPF: 19 instructions that become 30. */
static struct sock_filter every[] = {
    LD(NR),
    BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
    BPF_STMT(BPF_LDX | BPF_W | BPF_LEN, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 1),
    BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 5, 1, 1),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 1, 0, 1),
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x80000000, 0, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0),
    BPF_STMT(BPF_ALU | BPF_DIV | BPF_X, 0),
    BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 3),
    BPF_STMT(BPF_ALU | BPF_NEG, 0),
    BPF_STMT(BPF_ST, 0),
    BPF_STMT(BPF_LD | BPF_MEM, 0),
    BPF_STMT(BPF_MISC | BPF_TAX, 0),
    BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),
    BPF_STMT(BPF_LD | BPF_IMM, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_A, 0),
    RET(SECCOMP_RET_ALLOW),
};

/* 3 * (8195 + 4) + (filler + 4) + 30 = 32768 with a filler of 8137
 * = 3 + 2 * 4067; `over` makes the filler one longer. */
static void conversion(int over) {
    if (nnp())
        return;
    int fit = 1;
    for (int i = 0; i < 3; i++)
        fit &= install(returns(BPF_MAXINSNS, 0), BPF_MAXINSNS, 0) == 0;
    fit &= install(returns(4067, over), 4067 + over, 0) == 0;
    CHECK(over ? "conversion-base-over" : "conversion-base", fit);
    unsigned short n = sizeof every / sizeof every[0];
    if (over)
        CHECK_ERR("conversion-over", install(every, n, 0), ENOMEM);
    else
        CHECK("conversion-exact", install(every, n, 0) == 0 && syscall(SYS_getppid) > 0);
}

static void conversion_exact(void) {
    conversion(0);
}

static void conversion_over(void) {
    conversion(1);
}

static void deciding(void) {
    long euid = syscall(SYS_geteuid);
    struct sock_filter prog[] = {
        LD(offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 1, 0),
        RET(SECCOMP_RET_KILL_PROCESS),
        LD(NR),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        RET(SECCOMP_RET_ERRNO | 42),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 4),
        LD(ARG0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 99, 0, 1),
        RET(SECCOMP_RET_ERRNO | 0xFFFF),
        RET(SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        RET(SECCOMP_RET_ERRNO | 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x7777, 0, 1),
        RET(SECCOMP_RET_ERRNO | 5),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getuid, 0, 1),
        RET(SECCOMP_RET_TRACE | 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getgid, 0, 1),
        RET(SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_geteuid, 0, 1),
        RET(SECCOMP_RET_LOG),
        RET(SECCOMP_RET_ALLOW),
    };
    CHECK("nnp", nnp() == 0);
    CHECK("install", install(prog, sizeof prog / sizeof prog[0], 0) == 0);
    CHECK_ERR("errno", syscall(SYS_getpid), 42);
    CHECK_ERR("errno-capped", syscall(SYS_write, 99, "x", 1), 4095);
    CHECK("argument-allowed", syscall(SYS_write, 1, "", 0) == 0);
    CHECK("errno-zero", syscall(SYS_getppid) == 0);
    CHECK_ERR("unknown-number", syscall(0x7777), 5);
    CHECK_ERR("trace-no-tracer", syscall(SYS_getuid), ENOSYS);
    CHECK_ERR("notify-no-listener", syscall(SYS_getgid), ENOSYS);
    CHECK("log", syscall(SYS_geteuid) == euid);
    /* Equal actions: the newest filter's; a higher action loses. */
    struct sock_filter second[] = ON(SYS_getpid, SECCOMP_RET_ERRNO | 7);
    struct sock_filter third[] = ON(SYS_getpid, SECCOMP_RET_ALLOW);
    CHECK("install-second", install(second, 4, 0) == 0);
    CHECK("install-third", install(third, 4, 0) == 0);
    CHECK_ERR("newest-on-tie", syscall(SYS_getpid), 7);
    CHECK("status", status_is("/proc/self/status", 1, 2, 3));
}

static volatile int traps, trap_code, trap_errno, trap_syscall;
static volatile unsigned trap_arch;
static void *volatile trap_addr;

static void on_sigsys(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    traps++;
    trap_code = si->si_code;
    trap_errno = si->si_errno;
    trap_syscall = si->si_syscall;
    trap_arch = si->si_arch;
    trap_addr = si->si_call_addr;
}

static void handle_sigsys(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, NULL);
}

static void trapping(void) {
    handle_sigsys();
    struct sock_filter first[] = ON(SYS_gettid, SECCOMP_RET_ERRNO | 1);
    struct sock_filter second[] = ON(SYS_gettid, SECCOMP_RET_TRAP | 0x1234);
    struct sock_filter third[] = ON(SYS_gettid, SECCOMP_RET_TRAP | 0x77);
    CHECK("nnp", nnp() == 0);
    CHECK("install", install(first, 4, 0) == 0 && install(second, 4, 0) == 0 &&
                         install(third, 4, 0) == 0);
    syscall(SYS_gettid);
    CHECK("trap-once", traps == 1);
    CHECK("trap-code", trap_code == SYS_SECCOMP);
    CHECK("trap-data", trap_errno == 0x77);
    CHECK("trap-syscall", trap_syscall == SYS_gettid);
    CHECK("trap-arch", trap_arch == ARCH);
    CHECK("trap-address", trap_addr != NULL);
    syscall(SYS_gettid);
    CHECK("trap-again", traps == 2);
}

static void trap_blocked(void) {
    handle_sigsys();
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSYS);
    sigprocmask(SIG_BLOCK, &set, NULL);
    struct sock_filter prog[] = ON(SYS_gettid, SECCOMP_RET_TRAP);
    if (nnp() || install(prog, 4, 0))
        return;
    syscall(SYS_gettid);
    CHECK("survived", 0);
}

static void trap_ignored(void) {
    signal(SIGSYS, SIG_IGN);
    struct sock_filter prog[] = ON(SYS_gettid, SECCOMP_RET_TRAP);
    if (nnp() || install(prog, 4, 0))
        return;
    syscall(SYS_gettid);
    CHECK("survived", 0);
}

static int pipefd[2];

static void *sleeper(void *arg) {
    (void)arg;
    char c;
    read(pipefd[0], &c, 1);
    return NULL;
}

static void kill_process(void) {
    handle_sigsys();
    pthread_t t;
    pipe(pipefd);
    pthread_create(&t, NULL, sleeper, NULL);
    struct sock_filter prog[] = ON(SYS_getpid, SECCOMP_RET_KILL_PROCESS);
    if (nnp() || install(prog, 4, 0))
        return;
    syscall(SYS_getpid);
    CHECK("survived", 0);
}

static void kill_last_thread(void) {
    struct sock_filter prog[] = ON(SYS_getpid, SECCOMP_RET_KILL_THREAD);
    if (nnp() || install(prog, 4, 0))
        return;
    syscall(SYS_getpid);
    CHECK("survived", 0);
}

static void kill_unknown_action(void) {
    struct sock_filter prog[] = ON(SYS_getpid, 0x00010000);
    if (nnp() || install(prog, 4, 0))
        return;
    syscall(SYS_getpid);
    CHECK("survived", 0);
}

static volatile long victim;

/* Whether thread `tid` of `pid` has gone. A thread the kernel ends cannot
 * be joined: only pthread_exit marks it exited. */
static int gone(pid_t pid) {
    for (int i = 0; i < 5000; i++) {
        if (victim && syscall(SYS_tgkill, pid, victim, 0) == -1 && errno == ESRCH)
            return 1;
        usleep(1000);
    }
    return 0;
}

static void *getpid_thread(void *arg) {
    (void)arg;
    victim = syscall(SYS_gettid);
    syscall(SYS_getpid);
    victim = -1;
    return NULL;
}

static void kill_one_thread(void) {
    pid_t pid = getpid();
    struct sock_filter prog[] = ON(SYS_getpid, SECCOMP_RET_KILL_THREAD);
    CHECK("install", nnp() == 0 && install(prog, 4, 0) == 0);
    pthread_t t;
    pthread_create(&t, NULL, getpid_thread, NULL);
    CHECK("thread-gone", gone(pid));
    CHECK("thread-alone", victim != -1 && syscall(SYS_gettid) == pid);
}

static void say(const char *s) {
    syscall(SYS_write, 1, s, strlen(s));
}

static void strict_process(void) {
    fflush(stdout);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0)
        return;
    say("ok strict-write\n");
    long r = syscall(SYS_read, -1, NULL, 0);
    say(r == -1 && errno == EBADF ? "ok strict-read\n" : "FAIL strict-read\n");
    syscall(SYS_getpid);
    say("FAIL strict-survived\n");
}

static void strict_exit(void) {
    fflush(stdout);
    if (sc(SECCOMP_SET_MODE_STRICT, 0, NULL) != 0)
        return;
    syscall(SYS_exit, 3);
}

static void *strict_thread(void *arg) {
    (void)arg;
    long tid = syscall(SYS_gettid);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0)
        return NULL;
    victim = tid;
    syscall(SYS_getpid);
    victim = -1;
    return NULL;
}

static void strict_one_thread(void) {
    pthread_t t;
    pthread_create(&t, NULL, strict_thread, NULL);
    CHECK("strict-thread-gone", gone(getpid()));
    CHECK("strict-thread-alone", victim != -1 && prctl(PR_GET_SECCOMP) == 0);
}

static void *errno3_thread(void *arg) {
    (void)arg;
    errno = 0;
    return (void *)(long)(syscall(SYS_getpid) == -1 && errno == 3);
}

static void inheriting(void) {
    struct sock_filter prog[] = ON(SYS_getpid, SECCOMP_RET_ERRNO | 3);
    CHECK("install", nnp() == 0 && install(prog, 4, 0) == 0);
    pthread_t t;
    void *r = NULL;
    pthread_create(&t, NULL, errno3_thread, NULL);
    pthread_join(t, &r);
    CHECK("thread-inherits", r == (void *)1);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        errno = 0;
        int ok = syscall(SYS_getpid) == -1 && errno == 3 &&
                 status_is("/proc/self/status", 1, 2, 1);
        _exit(ok ? 0 : 1);
    }
    int st = 0;
    waitpid(p, &st, 0);
    CHECK("child-inherits", clean(st));
    fflush(stdout);
    p = fork();
    if (p == 0) {
        char *argv[] = {self_argv[0], "probe", NULL};
        execv("/proc/self/exe", argv);
        _exit(2);
    }
    waitpid(p, &st, 0);
    CHECK("exec-keeps", clean(st));
}

/* The executed program of `inheriting`. */
static int probe(void) {
    errno = 0;
    int ok = syscall(SYS_getpid) == -1 && errno == 3 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 &&
             status_is("/proc/self/status", 1, 2, 1);
    return ok ? 0 : 1;
}

static int go[2], done[2];
static volatile long peer_tid;
static volatile int peer_ok;

static void *synced_thread(void *arg) {
    (void)arg;
    char c;
    peer_tid = syscall(SYS_gettid);
    write(done[1], "r", 1);
    read(go[0], &c, 1);
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%ld/status", peer_tid);
    errno = 0;
    peer_ok = syscall(SYS_getpid) == -1 && errno == 9 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 &&
              status_is(path, 1, 2, 1);
    struct sock_filter own[] = ON(SYS_getppid, SECCOMP_RET_ERRNO | 10);
    peer_ok &= install(own, 4, 0) == 0;
    write(done[1], "d", 1);
    read(go[0], &c, 1);
    return NULL;
}

static void synchronizing(void) {
    pipe(go);
    pipe(done);
    pthread_t t;
    char c;
    pthread_create(&t, NULL, synced_thread, NULL);
    read(done[0], &c, 1);
    struct sock_filter prog[] = ON(SYS_getpid, SECCOMP_RET_ERRNO | 9);
    CHECK("nnp", nnp() == 0);
    CHECK("tsync", install(prog, 4, SECCOMP_FILTER_FLAG_TSYNC) == 0);
    write(go[1], "g", 1);
    read(done[0], &c, 1);
    CHECK("tsync-joined", peer_ok);
    struct sock_filter more[] = ON(SYS_getegid, SECCOMP_RET_ERRNO | 11);
    CHECK("tsync-diverged", install(more, 4, SECCOMP_FILTER_FLAG_TSYNC) == peer_tid);
    CHECK_ERR("tsync-esrch",
              install(more, 4, SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH), ESRCH);
    CHECK("tsync-unchanged", status_is("/proc/self/status", 1, 2, 1));
    write(go[1], "g", 1);
    pthread_join(t, NULL);
    /* The thread has exited: nothing stops the sync now. */
    CHECK("tsync-after-exit", install(more, 4, SECCOMP_FILTER_FLAG_TSYNC) == 0);
}

int main(int argc, char **argv) {
    self_argv = argv;
    if (argc > 1 && strcmp(argv[1], "probe") == 0)
        return probe();
    operations();
    CHECK("unprivileged", clean(run(unprivileged)));
    CHECK("installing", clean(run(installing)));
    CHECK("conversion-exact", clean(run(conversion_exact)));
    CHECK("conversion-over", clean(run(conversion_over)));
    CHECK("deciding", clean(run(deciding)));
    CHECK("trapping", clean(run(trapping)));
    CHECK("trap-blocked-kills", killed_by(run(trap_blocked), SIGSYS));
    CHECK("trap-ignored-kills", killed_by(run(trap_ignored), SIGSYS));
    CHECK("kill-process", killed_by(run(kill_process), SIGSYS));
    CHECK("kill-last-thread", killed_by(run(kill_last_thread), SIGSYS));
    CHECK("kill-unknown-action", killed_by(run(kill_unknown_action), SIGSYS));
    CHECK("kill-one-thread", clean(run(kill_one_thread)));
    CHECK("strict-kills", killed_by(run(strict_process), SIGKILL));
    int st = run(strict_exit);
    CHECK("strict-exit", WIFEXITED(st) && WEXITSTATUS(st) == 3);
    CHECK("strict-one-thread", clean(run(strict_one_thread)));
    CHECK("inheriting", clean(run(inheriting)));
    CHECK("synchronizing", clean(run(synchronizing)));
    FINISH();
}
