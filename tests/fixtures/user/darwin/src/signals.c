// Signal delivery: handlers and their siginfo_t and ucontext_t, masks,
// SA_RESETHAND, SA_NODEFER, SA_ONSTACK, pending and ignored signals,
// sigsuspend, sigwait, interval timers, interrupted and restarted calls,
// machine faults recovered with siglongjmp, SIGPIPE, and nested handlers.
// Everything printed is independent of addresses and timing.
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t hits[32];
static volatile int got_code, got_status, got_errno, self_blocked, usr2_blocked;
static volatile pid_t got_pid;
static volatile uid_t got_uid;
static volatile uintptr_t got_addr, got_local;
static volatile size_t got_mcsize, got_ss_size;
static volatile int got_onstack, got_uc_onstack;
static volatile int order[8], order_n;
static sigjmp_buf jb;
static int pipe_fds[2];

static void trad(int sig) { hits[sig]++; }

static void info(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    sigset_t cur;
    hits[sig]++;
    got_code = si->si_code;
    got_pid = si->si_pid;
    got_uid = si->si_uid;
    got_status = si->si_status;
    got_addr = (uintptr_t)si->si_addr;
    got_mcsize = uc->uc_mcsize;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    self_blocked = sigismember(&cur, sig);
    usr2_blocked = sigismember(&cur, SIGUSR2);
}

static void on_stack(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    stack_t now;
    int local;
    (void)si;
    hits[sig]++;
    got_local = (uintptr_t)&local;
    got_ss_size = uc->uc_stack.ss_size;
    got_uc_onstack = uc->uc_onstack;
    sigaltstack(NULL, &now);
    got_onstack = (now.ss_flags & SS_ONSTACK) != 0;
}

static void fault(int sig, siginfo_t *si, void *ucv) {
    (void)ucv;
    hits[sig]++;
    got_code = si->si_code;
    got_addr = (uintptr_t)si->si_addr;
    siglongjmp(jb, sig);
}

static void writer(int sig) {
    hits[sig]++;
    char c = 'x';
    write(pipe_fds[1], &c, 1);
}

static void inner(int sig) { order[order_n++] = sig; }

static void outer(int sig) {
    order[order_n++] = sig;
    raise(SIGUSR2);
    order[order_n++] = -sig;
}

static void fp_clobber(int sig) {
    volatile double x = 1.0;
    for (int i = 0; i < 100; i++) {
        x = x * 1.5 + 0.25;
    }
    hits[sig] += x > 0;
}

static void set(int sig, void (*h)(int), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

static void set_info(int sig, void (*h)(int, siginfo_t *, void *), int flags, int extra) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&sa.sa_mask);
    if (extra) {
        sigaddset(&sa.sa_mask, extra);
    }
    sigaction(sig, &sa, NULL);
}

static void timer_ms(int ms) {
    struct itimerval it = {{0, 0}, {ms / 1000, (ms % 1000) * 1000}};
    setitimer(ITIMER_REAL, &it, NULL);
}

static int blocked(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    return sigismember(&cur, sig);
}

int main(void) {
    struct sigaction oact;
    sigset_t set_, old, pend;

    // An untouched action restarts calls; SIGKILL has no action.
    sigaction(SIGHUP, NULL, &oact);
    printf("default: handler=%d flags=%#x\n", oact.sa_handler == SIG_DFL, oact.sa_flags);
    errno = 0;
    printf("sigaction(SIGKILL): %d errno=%d\n", sigaction(SIGKILL, NULL, &oact), errno);
    printf("sigaction(0): %d errno=%d\n", sigaction(0, NULL, &oact), errno);

    // A traditional handler, via raise (pthread_kill) and kill.
    set(SIGUSR1, trad, 0);
    raise(SIGUSR1);
    kill(getpid(), SIGUSR1);
    printf("trad: hits=%d\n", hits[SIGUSR1]);

    // SA_SIGINFO: the sender, the codes, the mask during the handler.
    set_info(SIGUSR1, info, 0, SIGUSR2);
    kill(getpid(), SIGUSR1);
    printf("info: hits=%d code=%d pid_ok=%d uid_ok=%d status=%d self=%d usr2=%d\n",
           hits[SIGUSR1], got_code, got_pid == getpid(), got_uid == getuid(), got_status,
           self_blocked, usr2_blocked);
    printf("info: mcsize=%zu after: self=%d usr2=%d\n", got_mcsize, blocked(SIGUSR1),
           blocked(SIGUSR2));
    sigaction(SIGUSR1, NULL, &oact);
    printf("info: reported flags=%#x mask_usr2=%d\n", oact.sa_flags,
           sigismember(&oact.sa_mask, SIGUSR2));

    // SA_NODEFER leaves the signal unblocked; SA_RESETHAND resets it.
    set_info(SIGUSR1, info, SA_NODEFER | SA_RESETHAND, 0);
    raise(SIGUSR1);
    sigaction(SIGUSR1, NULL, &oact);
    printf("nodefer: self=%d\n", self_blocked);
#if defined(__arm64__)
    // XNU resets the action (and its SA_SIGINFO and SA_NODEFER) when the
    // handler is entered. (Rosetta, the x86-64 oracle, does not.)
    printf("resethand: reset=%d flags=%#x\n", oact.sa_handler == SIG_DFL, oact.sa_flags);
#endif

    // A blocked signal stays pending and arrives when unblocked.
    hits[SIGUSR2] = 0;
    set(SIGUSR2, trad, 0);
    sigemptyset(&set_);
    sigaddset(&set_, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set_, &old);
    raise(SIGUSR2);
    raise(SIGUSR2);
    sigpending(&pend);
    printf("pending: member=%d hits=%d\n", sigismember(&pend, SIGUSR2), hits[SIGUSR2]);
    sigprocmask(SIG_SETMASK, &old, NULL);
    sigpending(&pend);
    printf("pending: after unblock hits=%d member=%d\n", hits[SIGUSR2],
           sigismember(&pend, SIGUSR2));

    // Ignored signals are discarded, even while blocked.
    set(SIGUSR2, SIG_IGN, 0);
    sigprocmask(SIG_BLOCK, &set_, &old);
    raise(SIGUSR2);
    sigpending(&pend);
    printf("ignored: pending=%d\n", sigismember(&pend, SIGUSR2));
    sigprocmask(SIG_SETMASK, &old, NULL);
    // Signals the default ignores: nothing happens.
    raise(SIGWINCH);
    raise(SIGCHLD);
    raise(SIGURG);
    printf("default-ignored: survived\n");

    // sigwait takes a pending signal, or waits for one.
    set(SIGUSR2, trad, 0);
    hits[SIGUSR2] = 0;
    sigprocmask(SIG_BLOCK, &set_, &old);
    raise(SIGUSR2);
    int got = 0;
    int r = sigwait(&set_, &got);
    sigpending(&pend);
    printf("sigwait: r=%d sig=%d hits=%d pending=%d\n", r, got, hits[SIGUSR2],
           sigismember(&pend, SIGUSR2));
    sigprocmask(SIG_SETMASK, &old, NULL);
    sigset_t alrm;
    sigemptyset(&alrm);
    sigaddset(&alrm, SIGALRM);
    sigprocmask(SIG_BLOCK, &alrm, &old);
    timer_ms(20);
    got = 0;
    r = sigwait(&alrm, &got);
    printf("sigwait timer: r=%d sig=%d\n", r, got);
    sigprocmask(SIG_SETMASK, &old, NULL);

    // sigsuspend: the handler runs with the suspend mask's complement
    // restored afterwards; the call always fails with EINTR.
    set(SIGALRM, trad, 0);
    sigprocmask(SIG_BLOCK, &alrm, &old);
    timer_ms(20);
    sigset_t none;
    sigemptyset(&none);
    errno = 0;
    r = sigsuspend(&none);
    printf("sigsuspend: r=%d errno=%d hits=%d alrm_blocked=%d\n", r, errno, hits[SIGALRM],
           blocked(SIGALRM));
    sigprocmask(SIG_SETMASK, &old, NULL);

    // Interval timers.
    struct itimerval it = {{0, 250000}, {5, 0}}, cur;
    setitimer(ITIMER_REAL, &it, NULL);
    getitimer(ITIMER_REAL, &cur);
    printf("getitimer: interval=%ld.%06d value_ok=%d\n", (long)cur.it_interval.tv_sec,
           (int)cur.it_interval.tv_usec,
           cur.it_value.tv_sec == 4 || (cur.it_value.tv_sec == 5 && cur.it_value.tv_usec == 0));
    struct itimerval zero = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &zero, &cur);
    getitimer(ITIMER_REAL, &cur);
    printf("getitimer: cleared=%d\n", cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0);
    struct itimerval bad = {{0, 0}, {0, 1000000}};
    errno = 0;
    printf("setitimer(usec=1e6): %d errno=%d\n", setitimer(ITIMER_REAL, &bad, NULL), errno);
    errno = 0;
    printf("setitimer(which=3): %d errno=%d\n", setitimer(3, &zero, NULL), errno);

    // A blocking read is interrupted (EINTR) without SA_RESTART and
    // restarted with it.
    pipe(pipe_fds);
    set(SIGALRM, writer, 0);
    timer_ms(20);
    char c;
    errno = 0;
    ssize_t n = read(pipe_fds[0], &c, 1);
    printf("read: n=%zd errno=%d\n", n, errno);
    n = read(pipe_fds[0], &c, 1);
    printf("read: drained=%zd\n", n);
    set(SIGALRM, writer, SA_RESTART);
    timer_ms(20);
    errno = 0;
    n = read(pipe_fds[0], &c, 1);
    printf("read restarted: n=%zd errno=%d c=%c\n", n, errno, c);

    // nanosleep is interrupted and reports the time left.
    set(SIGALRM, trad, SA_RESTART);
    timer_ms(20);
    struct timespec req = {2, 0}, rem = {0, 0};
    errno = 0;
    r = nanosleep(&req, &rem);
    printf("nanosleep: r=%d errno=%d rem_ok=%d\n", r, errno, rem.tv_sec >= 1);

    // An alternate stack.
    stack_t ss, oss;
    ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    sigaltstack(NULL, &oss);
    printf("altstack: initially disabled=%d\n", (oss.ss_flags & SS_DISABLE) != 0);
    errno = 0;
    stack_t tiny = {ss.ss_sp, 4096, 0};
    printf("altstack: tiny=%d errno=%d\n", sigaltstack(&tiny, NULL), errno);
    printf("altstack: set=%d\n", sigaltstack(&ss, NULL));
    set_info(SIGUSR1, on_stack, SA_ONSTACK, 0);
    raise(SIGUSR1);
    uintptr_t lo = (uintptr_t)ss.ss_sp, hi = lo + ss.ss_size;
    printf("altstack: on=%d onstack_flag=%d uc_onstack=%d ss_size_ok=%d\n",
           got_local >= lo && got_local < hi, got_onstack, got_uc_onstack,
           got_ss_size == SIGSTKSZ);
    sigaltstack(NULL, &oss);
    printf("altstack: after flags=%d\n", oss.ss_flags);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    raise(SIGUSR1);
    printf("altstack: disabled on=%d\n", got_local >= lo && got_local < hi);

    // Faults, recovered with siglongjmp.
    long page = sysconf(_SC_PAGESIZE);
    char *noaccess = mmap(NULL, page, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    char *ro = mmap(NULL, page, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    // Page zero is never mapped (a munmapped page could be reused by
    // Rosetta's own allocations).
    char *gone = NULL;
    set_info(SIGSEGV, fault, SA_NODEFER, 0);
    set_info(SIGBUS, fault, SA_NODEFER, 0);
    set_info(SIGILL, fault, SA_NODEFER, 0);
    set_info(SIGTRAP, fault, SA_NODEFER, 0);
    set_info(SIGFPE, fault, SA_NODEFER, 0);
    struct {
        const char *name;
        volatile char *p;
    } cases[] = {{"prot_none read", noaccess}, {"read_only write", ro}, {"null read", gone}};
    for (int i = 0; i < 3; i++) {
        int sig = sigsetjmp(jb, 1);
        if (sig == 0) {
            if (i == 1) {
                cases[i].p[8] = 1;
            } else {
                (void)cases[i].p[8];
            }
            printf("%s: no fault\n", cases[i].name);
        } else {
            printf("%s: sig=%d addr_ok=%d\n", cases[i].name, sig,
                   got_addr == (uintptr_t)(cases[i].p + 8));
        }
    }
    int sig = sigsetjmp(jb, 1);
    if (sig == 0) {
        __builtin_trap();
    } else {
        printf("trap: sig=%s\n", sig == SIGTRAP ? "SIGTRAP" : sig == SIGILL ? "SIGILL" : "?");
    }
#if defined(__x86_64__)
    sig = sigsetjmp(jb, 1);
    if (sig == 0) {
        volatile int a = 1, b = 0;
        printf("div: %d\n", a / b);
    } else {
        printf("div: sig=%d code=%d\n", sig, got_code);
    }
#else
    // arm64 division by zero does not trap: the quotient is 0.
    volatile int a = 1, b = 0;
    printf("div: %d\n", a / b);
#endif

    // SIGPIPE: caught, ignored, and suppressed by F_SETNOSIGPIPE.
    int p[2];
    pipe(p);
    close(p[0]);
    set(SIGPIPE, trad, 0);
    errno = 0;
    n = write(p[1], "x", 1);
    printf("sigpipe caught: n=%zd errno=%d hits=%d\n", n, errno, hits[SIGPIPE]);
    set(SIGPIPE, SIG_IGN, 0);
    errno = 0;
    n = write(p[1], "x", 1);
    printf("sigpipe ignored: n=%zd errno=%d hits=%d\n", n, errno, hits[SIGPIPE]);
    set(SIGPIPE, trad, 0);
    fcntl(p[1], F_SETNOSIGPIPE, 1);
    errno = 0;
    n = write(p[1], "x", 1);
    printf("sigpipe nosigpipe: n=%zd errno=%d hits=%d\n", n, errno, hits[SIGPIPE]);

    // A handler that raises another signal runs it nested.
    set(SIGUSR1, outer, 0);
    set(SIGUSR2, inner, 0);
    raise(SIGUSR1);
    printf("nested:");
    for (int i = 0; i < order_n; i++) {
        printf(" %d", order[i]);
    }
    printf("\n");

    // The interrupted code's floating-point state survives a handler.
    set(SIGUSR1, fp_clobber, 0);
    volatile double d = 3.25;
    double before = d * 2.0;
    raise(SIGUSR1);
    printf("fp: %.2f %.2f\n", before, d * 2.0);

    // A signal to the process group (after leaving the parent's group, so
    // that only this process is in it) reaches this process before kill
    // returns.
    setpgid(0, 0);
    hits[SIGUSR1] = hits[SIGUSR2] = 0;
    set(SIGUSR1, trad, 0);
    set(SIGUSR2, trad, 0);
    kill(0, SIGUSR1);
    int usr1 = hits[SIGUSR1];
    kill(-getpgrp(), SIGUSR2);
    printf("group: usr1=%d usr2=%d\n", usr1, hits[SIGUSR2]);

    fflush(stdout);
    // Finally the default action of SIGTERM ends the process.
    set(SIGTERM, SIG_DFL, 0);
    raise(SIGTERM);
    printf("not reached\n");
    return 0;
}
