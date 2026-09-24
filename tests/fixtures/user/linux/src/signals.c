/* Signal handlers, masks, queues, alternate stacks, faults, and returning
 * from handlers with an edited context. Handlers only record; main prints. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include "check.h"

static volatile sig_atomic_t count, depth, max_depth, entries;
static volatile int last_signo, last_code, last_pid, last_uid, order_n;
static volatile int order[8];
static volatile uintptr_t last_addr, handler_sp;
static volatile uint64_t mask_in_handler;
static volatile int altstack_flags;
static sigjmp_buf jump;

static uint64_t current_mask(void) {
    sigset_t s;
    sigprocmask(SIG_BLOCK, NULL, &s);
    uint64_t m = 0;
    for (int i = 1; i < 64; i++)
        if (sigismember(&s, i)) m |= 1ull << (i - 1);
    return m;
}

static void record(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    count++;
    last_signo = sig;
    last_code = si->si_code;
    last_pid = si->si_pid;
    last_uid = si->si_uid;
    last_addr = (uintptr_t)si->si_addr;
    mask_in_handler = current_mask();
    if (order_n < 8) order[order_n++] = sig;
}

/* Re-raises itself until it has run three times. */
static void nested(int sig, siginfo_t *si, void *uc) {
    entries++;
    depth++;
    if (depth > max_depth) max_depth = depth;
    if (entries < 3) raise(sig);
    depth--;
    (void)si, (void)uc;
}

static void on_altstack(int sig) {
    int local;
    handler_sp = (uintptr_t)&local;
    stack_t cur;
    sigaltstack(NULL, &cur);
    altstack_flags = cur.ss_flags;
    (void)sig;
}

static void recover(int sig, siginfo_t *si, void *uc) {
    last_signo = sig;
    last_code = si->si_code;
    last_addr = (uintptr_t)si->si_addr;
    (void)uc;
    siglongjmp(jump, 1);
}

/* Skips the faulting store by advancing the saved PC. */
static void skip_store(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    last_signo = sig;
    last_addr = (uintptr_t)si->si_addr;
#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RIP] += 6; /* movl $0, (%rdi) */
#elif defined(__aarch64__)
    uc->uc_mcontext.pc += 4; /* str wzr, [x0] */
#elif defined(__riscv)
    uc->uc_mcontext.__gregs[0] += 4; /* sw zero, 0(a0) */
#endif
}

static void faulting_store(volatile int *p) {
#if defined(__x86_64__)
    __asm__ volatile("movl $0, (%%rdi)" : : "D"(p) : "memory");
#elif defined(__aarch64__)
    register volatile int *x0 __asm__("x0") = p;
    __asm__ volatile("str wzr, [x0]" : : "r"(x0) : "memory");
#elif defined(__riscv)
    register volatile int *a0 __asm__("a0") = p;
    __asm__ volatile("sw zero, 0(a0)" : : "r"(a0) : "memory");
#endif
}

static void on_abort(int sig) {
    (void)sig;
    count++;
}

static void set(int sig, void (*h)(int, siginfo_t *, void *), int flags, sigset_t *mask) {
    struct sigaction sa = {0};
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO | flags;
    if (mask) sa.sa_mask = *mask;
    sigaction(sig, &sa, NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    long page = sysconf(_SC_PAGESIZE);
    uint64_t bit = 1;

    /* raise() is tgkill: SI_TKILL from this process. */
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR2);
    set(SIGUSR1, record, 0, &m);
    raise(SIGUSR1);
    CHECK("raise-runs-handler", count == 1 && last_signo == SIGUSR1);
    CHECK("raise-si-code", last_code == SI_TKILL);
    CHECK("raise-si-pid", last_pid == getpid() && last_uid == (int)getuid());
    CHECK("mask-in-handler", mask_in_handler == ((bit << (SIGUSR1 - 1)) | (bit << (SIGUSR2 - 1))));
    CHECK("mask-restored", current_mask() == 0);
    kill(getpid(), SIGUSR1);
    CHECK("kill-si-code", count == 2 && last_code == SI_USER);

    /* SA_NODEFER lets a handler interrupt itself; without it the nested
     * raise stays pending until the handler returns. */
    set(SIGUSR2, nested, SA_NODEFER, NULL);
    depth = max_depth = entries = 0;
    raise(SIGUSR2);
    CHECK("nodefer-nests", entries == 3 && max_depth == 3);
    set(SIGUSR2, nested, 0, NULL);
    depth = max_depth = entries = 0;
    raise(SIGUSR2);
    CHECK("defer-serializes", entries == 3 && max_depth == 1);

    /* SA_RESETHAND restores SIG_DFL on delivery. */
    set(SIGUSR2, record, SA_RESETHAND, NULL);
    raise(SIGUSR2);
    struct sigaction old;
    sigaction(SIGUSR2, NULL, &old);
    CHECK("resethand", old.sa_handler == SIG_DFL);

    /* Blocked signals stay pending; unblocking delivers them. All three
     * are dequeued lowest-first, each frame above the last, so the last
     * one dequeued runs first. */
    set(SIGUSR1, record, 0, NULL);
    set(SIGUSR2, record, 0, NULL);
    set(SIGTERM, record, 0, NULL);
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigaddset(&block, SIGUSR2);
    sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, NULL);
    raise(SIGTERM);
    raise(SIGUSR2);
    raise(SIGUSR1);
    sigset_t pend;
    sigpending(&pend);
    CHECK("pending-set", sigismember(&pend, SIGUSR1) && sigismember(&pend, SIGUSR2) &&
                             sigismember(&pend, SIGTERM));
    order_n = 0;
    sigprocmask(SIG_UNBLOCK, &block, NULL);
    CHECK("unblock-delivers-all", order_n == 3);
    printf("delivery order: %d %d %d\n", order[0], order[1], order[2]);

    /* Standard signals coalesce; real-time signals queue with values. */
    sigset_t rt;
    sigemptyset(&rt);
    sigaddset(&rt, SIGRTMIN + 1);
    sigaddset(&rt, SIGUSR1);
    sigprocmask(SIG_BLOCK, &rt, NULL);
    for (int i = 0; i < 3; i++) {
        raise(SIGUSR1);
        sigqueue(getpid(), SIGRTMIN + 1, (union sigval){.sival_int = 40 + i});
    }
    siginfo_t si;
    struct timespec zero = {0, 0};
    int got = sigtimedwait(&rt, &si, &zero);
    CHECK("timedwait-lowest-first", got == SIGUSR1);
    int vals = 0;
    for (int i = 0; i < 3; i++) {
        got = sigtimedwait(&rt, &si, &zero);
        if (got == SIGRTMIN + 1 && si.si_code == SI_QUEUE && si.si_value.sival_int == 40 + i)
            vals++;
    }
    CHECK("rt-queue-in-order", vals == 3);
    CHECK_ERR("timedwait-empty", sigtimedwait(&rt, &si, &zero), EAGAIN);
    CHECK_ERR("timedwait-einval", sigtimedwait(&rt, &si, &(struct timespec){0, 1000000000}), EINVAL);
    sigprocmask(SIG_UNBLOCK, &rt, NULL);

    /* sigsuspend: the handler runs, then it returns EINTR with the old
     * mask back. */
    sigprocmask(SIG_BLOCK, &block, NULL);
    raise(SIGUSR1);
    int before = count;
    sigset_t empty;
    sigemptyset(&empty);
    CHECK_ERR("sigsuspend", sigsuspend(&empty), EINTR);
    CHECK("sigsuspend-ran-handler", count == before + 1);
    CHECK("sigsuspend-restores-mask", current_mask() == ((bit << (SIGUSR1 - 1)) |
                                                          (bit << (SIGUSR2 - 1)) |
                                                          (bit << (SIGTERM - 1))));
    sigprocmask(SIG_UNBLOCK, &block, NULL);

    /* Default-ignored and ignored signals do nothing. */
    kill(getpid(), SIGCHLD);
    kill(getpid(), SIGWINCH);
    signal(SIGUSR2, SIG_IGN);
    raise(SIGUSR2);
    CHECK("ignored-signals", 1);

    /* The alternate stack. */
    stack_t ss = {.ss_size = 64 * 1024, .ss_flags = 0};
    ss.ss_sp = malloc(ss.ss_size);
    CHECK("sigaltstack", sigaltstack(&ss, NULL) == 0);
    struct sigaction alt = {0};
    alt.sa_handler = on_altstack;
    alt.sa_flags = SA_ONSTACK;
    sigaction(SIGUSR1, &alt, NULL);
    raise(SIGUSR1);
    CHECK("onstack-runs-on-altstack", handler_sp > (uintptr_t)ss.ss_sp &&
                                          handler_sp < (uintptr_t)ss.ss_sp + ss.ss_size);
    CHECK("onstack-flags", altstack_flags == SS_ONSTACK);
    stack_t cur;
    sigaltstack(NULL, &cur);
    CHECK("altstack-kept", cur.ss_sp == ss.ss_sp && cur.ss_flags == 0);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);

    /* Faults: recover with siglongjmp and check si_code/si_addr. */
    set(SIGSEGV, recover, 0, NULL);
    set(SIGBUS, recover, 0, NULL);
    if (!sigsetjmp(jump, 1)) *(volatile int *)0x1000 = 1;
    CHECK("segv-maperr", last_signo == SIGSEGV && last_code == SEGV_MAPERR && last_addr == 0x1000);
    char *ro = mmap(NULL, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!sigsetjmp(jump, 1)) *(volatile char *)(ro + 8) = 1;
    CHECK("segv-accerr", last_signo == SIGSEGV && last_code == SEGV_ACCERR &&
                             last_addr == (uintptr_t)(ro + 8));
    CHECK("longjmp-restored-mask", current_mask() == 0);
    char path[] = "/tmp/rax-signals-XXXXXX";
    int fd = mkstemp(path);
    write(fd, "x", 1);
    char *f = mmap(NULL, 2 * page, PROT_READ, MAP_SHARED, fd, 0);
    if (!sigsetjmp(jump, 1)) (void)*(volatile char *)(f + page);
    CHECK("sigbus-adrerr", last_signo == SIGBUS && last_code == BUS_ADRERR &&
                               last_addr == (uintptr_t)(f + page));
    close(fd);
    unlink(path);
    set(SIGILL, recover, 0, NULL);
    set(SIGTRAP, recover, 0, NULL);
    if (!sigsetjmp(jump, 1)) __builtin_trap();
    printf("trap caught: signal %d code %d\n", last_signo, last_code);

    /* Editing the saved PC skips the faulting store. */
    set(SIGSEGV, skip_store, 0, NULL);
    last_signo = 0;
    faulting_store((volatile int *)(ro + 16));
    CHECK("edited-context", last_signo == SIGSEGV && last_addr == (uintptr_t)(ro + 16));

    /* SIGPIPE comes with EPIPE. */
    int p[2];
    pipe(p);
    close(p[0]);
    set(SIGPIPE, record, 0, NULL);
    before = count;
    CHECK_ERR("epipe", write(p[1], "x", 1), EPIPE);
    CHECK("sigpipe", count == before + 1 && last_signo == SIGPIPE && last_code == SI_USER);

    /* abort() after its handler returns still ends the process. */
    signal(SIGABRT, on_abort);
    before = count;
    printf("aborting\n");
    abort();
}
