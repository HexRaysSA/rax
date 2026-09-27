/* AArch32 signal frames and the 32-bit signal calls of an arm64 kernel's
 * compatibility task (ARM EABI only; arch/arm64/kernel/signal32.c).
 *
 * Handlers run on an alternate stack at a fixed address, and every value is
 * printed relative to that stack, the frame, or the [sigpage], so a kernel
 * and an emulator that place the page differently print the same lines: the
 * registers a handler starts with (compat_setup_return), the frame layouts
 * (struct compat_sigframe, struct compat_rt_sigframe), the ucontext, the
 * VFP record, the return code in the [sigpage] and SA_RESTORER, a context
 * the handler edits (R0, D8, FPSCR's rounding mode), the fault records of a
 * write to a read-only page, an unaligned LDM, an UNDEFINED instruction, and
 * BKPT, the one-word mask calls, and a bad frame found after its mask was
 * set. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__arm__) || defined(__thumb__)
#error "armframes is an A32 ARM EABI program"
#endif

static unsigned char alt[65536] __attribute__((aligned(4096)));
#define TOP ((uintptr_t)alt + sizeof alt)

/* struct compat_sigaction, as rt_sigaction reads it. */
struct ksa {
    uint32_t handler, flags, restorer;
    uint32_t mask[2];
};

/* R0-R3, SP, and LR as the handler got them (the entry stubs below). */
static volatile uint32_t entry[6];

/* Handler entries: record the registers, then run the C handler. */
#define ENTRY(name, handler)                                                 \
    void name(void);                                                         \
    __asm__(".text\n.arm\n.globl " #name "\n" #name ":\n"                    \
            "ldr r12, 1f\n"                                                  \
            "stmia r12, {r0, r1, r2, r3}\n"                                  \
            "str sp, [r12, #16]\n"                                           \
            "str lr, [r12, #20]\n"                                           \
            "b " #handler "\n"                                               \
            "1: .word entry\n");

/* Return code of our own (SA_RESTORER): sigreturn and rt_sigreturn. */
void restorer_old(void);
void restorer_rt(void);
__asm__(".text\n.arm\n"
        ".globl restorer_old\nrestorer_old: mov r7, #119\nsvc #0\n"
        ".globl restorer_rt\nrestorer_rt: mov r7, #173\nsvc #0\n");

/* One instruction that faults each way, then a return: a write through
 * R0, an LDM from R0, UDF, BKPT. */
void fault_str(void *);
void fault_ldm(void *);
void fault_udf(void *);
void fault_bkpt(void *);
__asm__(".text\n.arm\n"
        ".globl fault_str\nfault_str: str r1, [r0]\nbx lr\n"
        ".globl fault_ldm\nfault_ldm: ldm r0, {r2, r3}\nbx lr\n"
        ".globl fault_udf\nfault_udf: udf #18\nbx lr\n"
        ".globl fault_bkpt\nfault_bkpt: bkpt #0x34\nbx lr\n");
static void *expected;
/* What a fault's address is printed relative to. */
static uintptr_t fault_base;

static uint32_t u32(const void *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t u64(const void *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static void put32(void *p, uint32_t v) { memcpy(p, &v, 4); }

/* Where `addr` is: our restorers, or the [sigpage] and the offset in it. */
static const char *where(uint32_t addr, uint32_t *off) {
    static char line[256];
    *off = addr & 0xfff;
    if (addr == (uint32_t)(uintptr_t)restorer_old) return "restorer_old";
    if (addr == (uint32_t)(uintptr_t)restorer_rt) return "restorer_rt";
    FILE *f = fopen("/proc/self/maps", "r");
    const char *what = "elsewhere";
    while (f && fgets(line, sizeof line, f)) {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && addr >= lo && addr < hi &&
            strstr(line, "[sigpage]"))
            what = "sigpage";
    }
    if (f) fclose(f);
    return what;
}

/* The struct compat_ucontext at `uc` of the frame at `frame`. */
static void dump_uc(const char *tag, const unsigned char *uc, uintptr_t frame) {
    const unsigned char *mc = uc + 20;
    printf("%s uc_flags=%x link=%x ss_sp=%d ss_flags=%x ss_size=%u\n", tag, u32(uc), u32(uc + 4),
           (int)(u32(uc + 8) - (uintptr_t)alt), u32(uc + 12), u32(uc + 16));
    printf("%s trap_no=%u error_code=%x oldmask=%x r0=%x r2=%x r4=%x\n", tag, u32(mc),
           u32(mc + 4), u32(mc + 8), u32(mc + 12), u32(mc + 20), u32(mc + 28));
    printf("%s sp_is_main=%d cpsr&0xff0fffff=%x fault_address=%x\n", tag,
           u32(mc + 64) != (uint32_t)frame, u32(mc + 76) & 0xff0fffff, u32(mc + 80));
    printf("%s sigmask=%x:%x unused0=%d\n", tag, u32(uc + 104), u32(uc + 108),
           u32(uc + 112) == 0 && u32(uc + 228) == 0);
    const unsigned char *vfp = uc + 232;
    printf("%s vfp magic=%x size=%u d8=%llx fpscr=%x fpexc=%x fpinst=%x end=%x:%x\n", tag,
           u32(vfp), u32(vfp + 4), (unsigned long long)u64(vfp + 8 + 8 * 8), u32(vfp + 264),
           u32(vfp + 272), u32(vfp + 276), u32(vfp + 288), u32(vfp + 292));
}

static volatile int got;

void rt_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *uc = ucv;
    uintptr_t sp = entry[4];
    uint32_t off;
    const char *lr = where(entry[5], &off);
    printf("rt r0=%u r1-sp=%d r2-sp=%d top-sp=%u lr=%s+%x\n", entry[0], (int)(entry[1] - sp),
           (int)(entry[2] - sp), (unsigned)(TOP - sp), lr, off);
    int rest0 = 1;
    for (int i = 20; i < 128; i++) rest0 &= ((unsigned char *)si)[i] == 0;
    printf("rt info signo=%d code=%d pid_ok=%d uid_ok=%d rest0=%d\n", si->si_signo, si->si_code,
           u32((unsigned char *)si + 12) == (uint32_t)getpid(),
           u32((unsigned char *)si + 16) == (uint32_t)getuid(), rest0);
    dump_uc("rt", uc, sp);
    /* Edit the context: R0 (the interrupted call's result), D8, and
     * FPSCR's rounding mode (toward zero). */
    unsigned char *mc = uc + 20, *vfp = uc + 232;
    put32(mc + 12, 0x1234);
    memset(vfp + 8 + 8 * 8, 0x44, 8);
    put32(vfp + 264, (u32(vfp + 264) & ~(3u << 22)) | (3u << 22));
    got = sig;
}
ENTRY(rt_entry, rt_handler)

void old_handler(int sig) {
    uintptr_t sp = entry[4];
    uint32_t off;
    const char *lr = where(entry[5], &off);
    printf("old r0=%u top-sp=%u lr=%s+%x retcode=%x:%x\n", entry[0], (unsigned)(TOP - sp), lr, off,
           u32((void *)(sp + 744)), u32((void *)(sp + 748)));
    dump_uc("old", (void *)sp, sp);
    got = sig;
}
ENTRY(old_entry, old_handler)

/* The [sigpage]'s return code, as the handler's LR finds it. */
void code_handler(int sig) {
    uint32_t base = entry[5] & ~0xfffu;
    const uint32_t *code = (const void *)(uintptr_t)base;
    printf("sigpage code %08x %08x %08x %08x %08x %08x tail=%08x\n", code[0], code[1], code[2],
           code[3], code[4], code[5], code[6]);
    got = sig;
}
ENTRY(code_entry, code_handler)

/* A fault: the record, then the faulting instruction skipped. */
void fault_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *mc = (unsigned char *)ucv + 20;
    printf("fault sig=%d code=%d addr=%d/%d trap_no=%u error_code=%x at_insn=%d\n", sig,
           si->si_code, (int)((uintptr_t)si->si_addr - fault_base),
           (int)(u32(mc + 80) - fault_base), u32(mc), u32(mc + 4),
           u32(mc + 72) == (uint32_t)(uintptr_t)expected);
    put32(mc + 72, u32(mc + 72) + 4);
}

void segv_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *uc = ucv;
    printf("segv sig=%d code=%d mask=%x:%x\n", sig, si->si_code, u32(uc + 104), u32(uc + 108));
    _exit(3);
}

/* Blocks SIGUSR2 and signal 33 through the frame, then breaks the VFP
 * record's magic: rt_sigreturn sets the mask, then fails. */
void bad_handler(int sig, siginfo_t *si, void *ucv) {
    unsigned char *uc = ucv;
    put32(uc + 104, 1u << (SIGUSR2 - 1));
    put32(uc + 108, 1u << 0);
    put32(uc + 232, 0);
}

static void install(int sig, void *h, uint32_t flags, void *rest) {
    struct ksa a = {(uint32_t)(uintptr_t)h, flags, (uint32_t)(uintptr_t)rest, {0, 0}};
    long r = syscall(SYS_rt_sigaction, sig, &a, 0, 8);
    if (r) printf("rt_sigaction %d -> %ld\n", sig, r);
}

static long raise_self(int sig) { return syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), sig); }

/* tgkill(self, sig) with D8 and FPSCR set around it: what the handler's
 * return leaves in R0, D8, and FPSCR. */
static void raise_with_vfp(int sig, uint32_t *r0, uint64_t *d8, uint32_t *fpscr) {
    uint32_t pid = getpid(), tid = syscall(SYS_gettid);
    uint64_t pattern = 0x0123456789abcdefull;
    uint32_t mode = 1u << 22; /* toward plus infinity */
    register uint32_t a0 __asm__("r0") = pid;
    register uint32_t a1 __asm__("r1") = tid;
    register uint32_t a2 __asm__("r2") = sig;
    register uint32_t nr __asm__("r7") = SYS_tgkill;
    uint32_t lo, hi, f;
    __asm__ volatile("vmov d8, %Q[p], %R[p]\n\t"
                     "vmsr fpscr, %[m]\n\t"
                     "svc #0\n\t"
                     "vmov %[lo], %[hi], d8\n\t"
                     "vmrs %[f], fpscr"
                     : "+r"(a0), [lo] "=&r"(lo), [hi] "=&r"(hi), [f] "=&r"(f)
                     : "r"(a1), "r"(a2), "r"(nr), [p] "r"(pattern), [m] "r"(mode)
                     : "d8", "memory");
    *r0 = a0;
    *d8 = (uint64_t)hi << 32 | lo;
    *fpscr = f;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    stack_t ss = {.ss_sp = alt, .ss_size = sizeof alt};
    printf("sigaltstack %d\n", sigaltstack(&ss, 0));

    /* The RT frame, with SA_RESTORER. */
    install(SIGUSR1, rt_entry, SA_SIGINFO | SA_RESTORER | SA_ONSTACK, restorer_rt);
    uint32_t rtmask[2] = {1u << (SIGHUP - 1), 1u << 1};
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, rtmask, 0, 8);
    uint32_t r0, fpscr;
    uint64_t d8;
    raise_with_vfp(SIGUSR1, &r0, &d8, &fpscr);
    printf("after rt: r0=%x d8=%llx fpscr&0xc00000=%x\n", r0, (unsigned long long)d8,
           fpscr & 0xc00000);
    uint32_t cur[2];
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, 0, cur, 8);
    printf("after rt: mask=%x:%x\n", cur[0], cur[1]);

    /* The non-RT frame, with SA_RESTORER, then both from the [sigpage]. */
    install(SIGUSR2, old_entry, SA_RESTORER | SA_ONSTACK, restorer_old);
    uint32_t m2[2] = {1u << (SIGHUP - 1), 1u << 2};
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, m2, 0, 8);
    printf("after old: r0=%ld got=%d\n", raise_self(SIGUSR2), got);
    install(SIGUSR2, old_entry, SA_ONSTACK, 0);
    printf("sigpage old: r0=%ld\n", raise_self(SIGUSR2));
    install(SIGUSR1, rt_entry, SA_SIGINFO | SA_ONSTACK, 0);
    raise_with_vfp(SIGUSR1, &r0, &d8, &fpscr);
    printf("sigpage rt: r0=%x\n", r0);
    install(SIGUSR1, code_entry, SA_ONSTACK, 0);
    raise_self(SIGUSR1);
    uint32_t zero[2] = {0, 0};
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, zero, 0, 8);

    /* The one-word mask calls (EABI has no sgetmask, ssetmask, or
     * signal). */
    uint32_t w = 1u << (SIGINT - 1), ow = 7;
    printf("sigprocmask setmask %ld old %x\n", syscall(SYS_sigprocmask, SIG_SETMASK, &w, &ow), ow);
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, 0, cur, 8);
    printf("mask after sigprocmask %x:%x\n", cur[0], cur[1]);
    printf("sigprocmask how=3 %ld\n", syscall(SYS_sigprocmask, 3, &w, 0));
    uint32_t pend = 0;
    raise_self(SIGINT);
    printf("sigpending %ld %x\n", syscall(SYS_sigpending, &pend), pend);
    struct { uint32_t h, m, f, r; } na = {1, 0, 0, 0}, oa = {9, 9, 9, 9};
    printf("sigaction set %ld\n", syscall(SYS_sigaction, SIGINT, &na, 0));
    printf("sigaction old %ld h=%x m=%x f=%x\n", syscall(SYS_sigaction, SIGINT, 0, &oa), oa.h,
           oa.m, oa.f);
    struct ksa ra;
    syscall(SYS_rt_sigaction, SIGUSR1, 0, &ra, 8);
    printf("rt_sigaction flags %x size4 %ld\n", ra.flags,
           syscall(SYS_rt_sigaction, SIGUSR1, 0, &ra, 4));
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, zero, 0, 8);

    /* Faults, each skipped by editing the saved PC: a write to a read-only
     * page, an unaligned LDM, UDF, BKPT. */
    volatile uint32_t *ro = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    install(SIGSEGV, fault_handler, SA_SIGINFO, 0);
    install(SIGBUS, fault_handler, SA_SIGINFO, 0);
    install(SIGILL, fault_handler, SA_SIGINFO, 0);
    install(SIGTRAP, fault_handler, SA_SIGINFO, 0);
    /* The data address for an abort (fault_address too); the instruction's
     * for UDF and BKPT, whose record keeps the last abort's address. */
    expected = (void *)fault_str;
    fault_base = (uintptr_t)ro;
    fault_str((void *)(ro + 4));
    expected = (void *)fault_ldm;
    fault_base = (uintptr_t)alt;
    fault_ldm(alt + 2);
    expected = (void *)fault_udf;
    fault_base = (uintptr_t)fault_udf;
    fault_udf(0);
    expected = (void *)fault_bkpt;
    fault_base = (uintptr_t)fault_bkpt;
    fault_bkpt(0);
    printf("faults skipped\n");

    /* A bad frame after the mask: SIGSEGV with the frame's mask. */
    install(SIGSEGV, segv_handler, SA_SIGINFO | SA_ONSTACK, 0);
    install(SIGUSR1, bad_handler, SA_SIGINFO | SA_ONSTACK, 0);
    raise_self(SIGUSR1);
    printf("not reached\n");
    return 0;
}
