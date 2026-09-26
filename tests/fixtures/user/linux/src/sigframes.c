/* i386 signal frames and the 32-bit signal calls (i386 only).
 *
 * Handlers run on an alternate stack at a fixed address, and every frame
 * field is printed relative to that stack or the frame, so a kernel and an
 * emulator whose XSAVE areas differ in size print the same lines: the frame
 * layouts (struct sigframe_ia32, struct rt_sigframe_ia32), the FSAVE header
 * converted from the FXSAVE image, the XSAVE epilog, the context a handler
 * edits (EAX, EIP, the x87 control word, XMM0), the page-fault error code
 * it records, the vDSO trampolines, the one-word mask calls, and a bad frame
 * found after its mask was set. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __i386__
#error "sigframes is an i386 program"
#endif

static unsigned char alt[65536] __attribute__((aligned(4096)));
#define TOP ((uintptr_t)alt + sizeof alt)

/* struct compat_sigaction, as rt_sigaction reads it. */
struct ksa {
    uint32_t handler, flags, restorer;
    uint32_t mask[2];
};

static long sys(long nr, long a, long b, long c, long d) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(nr), "b"(a), "c"(b), "d"(c), "S"(d) : "memory");
    return r;
}

/* Return trampolines of our own (SA_RESTORER). */
void restorer_rt(void);
void restorer_old(void);
__asm__(".text\n"
        ".globl restorer_rt\n"
        "restorer_rt: movl $173, %eax; int $0x80\n"
        ".globl restorer_old\n"
        "restorer_old: popl %eax; movl $119, %eax; int $0x80\n");

static uint32_t u32(const void *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint16_t u16(const void *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static void put32(void *p, uint32_t v) { memcpy(p, &v, 4); }

/* The struct sigcontext_32 at `sc` of the frame at `frame`, and the FPU
 * state it points to: the FSAVE header, then the XSAVE area. */
static void dump_sc(const char *tag, const unsigned char *sc, uintptr_t frame) {
    printf("%s gs=%x fs=%x es=%x ds=%x cs=%x ss=%x\n", tag, u16(sc), u16(sc + 4), u16(sc + 8),
           u16(sc + 12), u16(sc + 60), u16(sc + 72));
    printf("%s flags&0xcd5=%x oldmask=%x trapno=%u err=%u sp_eq=%d\n", tag, u32(sc + 64) & 0xcd5,
           u32(sc + 80), u32(sc + 48), u32(sc + 52), u32(sc + 28) == u32(sc + 68));
    uint32_t fp = u32(sc + 76);
    const unsigned char *h = (const void *)fp;
    printf("%s fsave cw=%x sw=%x tag=%x cssel=%x datasel=%x status=%x magic=%x\n", tag, u32(h),
           u32(h + 4), u32(h + 8), u32(h + 16), u32(h + 24), u16(h + 108), u16(h + 110));
    const unsigned char *fx = h + 112;
    int size = (int)u32(fx + 464 + 16);
    printf("%s fx align=%u magic1=%x ext-size=%d xfeat&3=%x magic2=%x bv&3=%x\n", tag,
           (unsigned)(fp + 112) % 64, u32(fx + 464), (int)u32(fx + 468) - size,
           (unsigned)(u32(fx + 472) & 3), u32(fx + size), (unsigned)(u32(fx + 512) & 3));
    /* The XSAVE area 64-byte aligned below the stack top with room for
     * FP_XSTATE_MAGIC2, the header below it, the frame below that. */
    uintptr_t buf_fx = (TOP - (size + 4)) & ~(uintptr_t)63;
    printf("%s placed=%d frame-align=%u buf-frame=%u\n", tag, fp == buf_fx - 112,
           (unsigned)((frame + 4) % 16), (unsigned)(fp - frame));
}

static volatile int got;

static void rt_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *uc = ucv;
    uintptr_t frame = (uintptr_t)uc - 144;
    const unsigned char *f = (const void *)frame;
    printf("rt sig=%d pinfo=%d puc=%d pretcode=%s\n", u32(f + 4), (int)(u32(f + 8) - frame),
           (int)(u32(f + 12) - frame),
           u32(f) == (uint32_t)(uintptr_t)restorer_rt ? "restorer" : "other");
    printf("rt retcode=%02x%02x%02x%02x%02x%02x%02x%02x\n", f[260], f[261], f[262], f[263], f[264],
           f[265], f[266], f[267]);
    printf("rt uc_flags=%x link=%x ss_sp=%d ss_flags=%x ss_size=%u\n", u32(uc), u32(uc + 4),
           (int)(u32(uc + 8) - (uintptr_t)alt), u32(uc + 12), u32(uc + 16));
    int rest0 = 1;
    for (int i = 20; i < 128; i++) rest0 &= ((unsigned char *)si)[i] == 0;
    printf("rt info signo=%d code=%d pid_ok=%d uid_ok=%d rest0=%d\n", si->si_signo, si->si_code,
           u32((unsigned char *)si + 12) == (uint32_t)getpid(),
           u32((unsigned char *)si + 16) == (uint32_t)getuid(), rest0);
    printf("rt sigmask=%x:%x\n", u32(uc + 108), u32(uc + 112));
    dump_sc("rt", uc + 20, frame);
    /* Edit the context: EAX, the x87 control word in the FSAVE header, and
     * XMM0 in the XSAVE area. */
    unsigned char *sc = uc + 20;
    put32(sc + 44, 0x1234);
    unsigned char *h = (void *)(uintptr_t)u32(sc + 76);
    put32(h, 0xffff0c7f);
    memset(h + 112 + 160, 0x44, 16);
    got = sig;
}

static void old_handler(int sig) {
    /* The i386 ABI passes the argument on the stack: the frame's `sig`. */
    uintptr_t frame = (uintptr_t)&sig - 4;
    const unsigned char *f = (const void *)frame;
    printf("old sig=%d pretcode=%s extramask=%x\n", u32(f + 4),
           u32(f) == (uint32_t)(uintptr_t)restorer_old ? "restorer" : "other", u32(f + 720));
    printf("old retcode=%02x%02x%02x%02x%02x%02x%02x%02x\n", f[724], f[725], f[726], f[727],
           f[728], f[729], f[730], f[731]);
    dump_sc("old", f + 8, frame);
    got = sig;
}

static void noret_handler(int sig, siginfo_t *si, void *uc) { got = sig; }

/* Skips `movl $0, (%edi)` (6 bytes) by editing the saved EIP. */
static void skip_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *sc = (unsigned char *)ucv + 20;
    printf("skip sig=%d code=%d trapno=%u err=%u cr2_eq_addr=%d\n", sig, si->si_code,
           u32(sc + 48), u32(sc + 52), u32(sc + 84) == (uint32_t)(uintptr_t)si->si_addr);
    put32(sc + 56, u32(sc + 56) + 6);
}

static void segv_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *uc = ucv;
    printf("segv sig=%d code=%d mask=%x:%x eax=%x\n", sig, si->si_code, u32(uc + 108),
           u32(uc + 112), u32(uc + 20 + 44));
    _exit(3);
}

/* Blocks SIGUSR2 and signal 33 through the frame, then breaks the FPU
 * state's pointer: rt_sigreturn sets the mask, then fails. */
static void bad_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *uc = ucv;
    put32(uc + 108, 1u << (SIGUSR2 - 1));
    put32(uc + 112, 1u << 0);
    put32(uc + 20 + 76, 0x1000);
}

static void returning_abort(int sig) { printf("abort handler returns\n"); }

static void install(int sig, void *h, uint32_t flags, void *rest) {
    struct ksa a = {(uint32_t)(uintptr_t)h, flags, (uint32_t)(uintptr_t)rest, {0, 0}};
    long r = sys(SYS_rt_sigaction, sig, (long)&a, 0, 8);
    if (r) printf("rt_sigaction %d -> %ld\n", sig, r);
}

static long raise_self(int sig) {
    return sys(SYS_tgkill, getpid(), syscall(SYS_gettid), sig, 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t ss[3] = {(uint32_t)(uintptr_t)alt, 0, sizeof alt};
    printf("sigaltstack %ld\n", sys(SYS_sigaltstack, (long)ss, 0, 0, 0));
    uint32_t old[3] = {1, 1, 1};
    printf("sigaltstack old %ld %d %x %u\n", sys(SYS_sigaltstack, 0, (long)old, 0, 0),
           (int)(old[0] - (uintptr_t)alt), old[1], old[2]);

    /* The RT frame: x87 1.0 and 0.0 on the stack, FCW 0x27f, XMM0 set. */
    install(SIGUSR1, rt_handler, SA_SIGINFO | SA_RESTORER | SA_ONSTACK, restorer_rt);
    uint32_t rtmask[2] = {1u << (SIGHUP - 1), 1u << 1};
    sys(SYS_rt_sigprocmask, SIG_SETMASK, (long)rtmask, 0, 8);
    unsigned short cw = 0x27f;
    __asm__ volatile("fldcw %0; fldz; fld1" ::"m"(cw));
    __asm__ volatile("pcmpeqb %%xmm0, %%xmm0" ::: "xmm0");
    long r = raise_self(SIGUSR1);
    unsigned short cw2;
    double a, b;
    unsigned char x0[16];
    __asm__ volatile("fnstcw %0" : "=m"(cw2));
    __asm__ volatile("fstpl %0; fstpl %1" : "=m"(a), "=m"(b));
    __asm__ volatile("movdqu %%xmm0, %0" : "=m"(x0));
    printf("after rt: eax=%lx cw=%x st=%g,%g xmm0=%02x\n", r, cw2, a, b, x0[0]);
    uint32_t cur[2];
    sys(SYS_rt_sigprocmask, SIG_SETMASK, 0, (long)cur, 8);
    printf("after rt: mask=%x:%x\n", cur[0], cur[1]);

    /* The non-RT frame. */
    install(SIGUSR2, old_handler, SA_RESTORER | SA_ONSTACK, restorer_old);
    uint32_t m2[2] = {1u << (SIGHUP - 1), 1u << 2};
    sys(SYS_rt_sigprocmask, SIG_SETMASK, (long)m2, 0, 8);
    r = raise_self(SIGUSR2);
    printf("after old: eax=%ld got=%d\n", r, got);

    /* Without SA_RESTORER: the vDSO trampolines. */
    got = 0;
    install(SIGUSR1, noret_handler, SA_SIGINFO | SA_ONSTACK, 0);
    raise_self(SIGUSR1);
    printf("vdso rt returned got=%d\n", got);
    got = 0;
    install(SIGUSR2, old_handler, SA_ONSTACK, 0);
    raise_self(SIGUSR2);
    printf("vdso old returned got=%d\n", got);

    /* The one-word mask calls. */
    uint32_t zero[2] = {0, 0};
    sys(SYS_rt_sigprocmask, SIG_SETMASK, (long)zero, 0, 8);
    printf("ssetmask(-1) -> %lx\n", sys(SYS_ssetmask, -1, 0, 0, 0));
    sys(SYS_rt_sigprocmask, SIG_SETMASK, 0, (long)cur, 8);
    printf("mask after ssetmask(-1) %x:%x sgetmask %lx\n", cur[0], cur[1],
           sys(SYS_sgetmask, 0, 0, 0, 0));
    uint32_t w = 1u << (SIGINT - 1), ow = 0;
    printf("sigprocmask setmask %ld old %x\n",
           sys(SYS_sigprocmask, SIG_SETMASK, (long)&w, (long)&ow, 0), ow);
    sys(SYS_rt_sigprocmask, SIG_SETMASK, 0, (long)cur, 8);
    printf("mask after sigprocmask %x:%x\n", cur[0], cur[1]);
    printf("sigprocmask how=3 %ld\n", sys(SYS_sigprocmask, 3, (long)&w, 0, 0));
    printf("ssetmask(4) -> %lx\n", sys(SYS_ssetmask, 4, 0, 0, 0));
    uint32_t only_int[2] = {1u << (SIGINT - 1), 0}, pend = 0;
    sys(SYS_rt_sigprocmask, SIG_SETMASK, (long)only_int, 0, 8);
    raise_self(SIGINT);
    printf("sigpending %ld %x\n", sys(SYS_sigpending, (long)&pend, 0, 0, 0), pend);
    printf("signal(SIGINT) -> %lx\n", sys(SYS_signal, SIGINT, 1, 0, 0));
    printf("signal(SIGINT) -> %lx\n", sys(SYS_signal, SIGINT, 0, 0, 0));
    struct { uint32_t h, m, f, r; } oa;
    printf("sigaction old %ld h=%x m=%x f=%x\n", sys(SYS_sigaction, SIGINT, 0, (long)&oa, 0),
           oa.h, oa.m, oa.f);
    struct ksa ra;
    sys(SYS_rt_sigaction, SIGUSR1, 0, (long)&ra, 8);
    printf("rt_sigaction flags %x\n", ra.flags);
    printf("rt_sigaction size4 %ld\n", sys(SYS_rt_sigaction, SIGUSR1, 0, (long)&ra, 4));
    sys(SYS_rt_sigprocmask, SIG_SETMASK, (long)zero, 0, 8);

    /* Editing the saved EIP skips a faulting store to a read-only page. */
    volatile int *ro = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    install(SIGSEGV, skip_handler, SA_SIGINFO | SA_RESTORER, restorer_rt);
    __asm__ volatile("movl $0, (%0)" : : "D"(ro + 4) : "memory");
    printf("store skipped\n");
    /* The #PF error code's P bit is the entry's presence: set once a read
     * mapped the page (the zero page), clear for PROT_NONE. */
    (void)ro[8];
    __asm__ volatile("movl $0, (%0)" : : "D"(ro + 8) : "memory");
    volatile int *none = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    none[0] = 1;
    mprotect((void *)none, 4096, PROT_NONE);
    __asm__ volatile("movl $0, (%0)" : : "D"(none) : "memory");

    /* abort() after its handler returns still ends the process. */
    pid_t child = fork();
    if (child == 0) {
        signal(SIGABRT, returning_abort);
        abort();
    }
    int st = 0;
    waitpid(child, &st, 0);
    printf("abort child signaled=%d sig=%d\n", WIFSIGNALED(st), WTERMSIG(st));

    /* A bad frame after the mask: SIGSEGV with the frame's mask. */
    install(SIGSEGV, segv_handler, SA_SIGINFO | SA_RESTORER | SA_ONSTACK, restorer_rt);
    install(SIGUSR1, bad_handler, SA_SIGINFO | SA_RESTORER | SA_ONSTACK, restorer_rt);
    raise_self(SIGUSR1);
    printf("not reached\n");
    return 0;
}
