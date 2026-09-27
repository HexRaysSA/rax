// Top-byte-ignore on arm64: data accesses through tagged pointers (loads,
// stores, pairs, vectors, exclusives, atomics, compare-and-swap), the
// tagged address a data fault reports, a branch to a tagged address (whose
// top byte counts: instruction addresses have no top-byte-ignore), and the
// Objective-C runtime's tagged method lists (class_addMethod).
#include <dlfcn.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#if !defined(__arm64__)
#error "arm64 only"
#endif

#define TAG(p, t) ((void *)((uintptr_t)(p) | ((uint64_t)(t) << 56)))

static sigjmp_buf jb;
static volatile uintptr_t expect;

static void on_fault(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    uintptr_t a = (uintptr_t)si->si_addr;
    printf("  %s code %d, address %s (tag %#llx)\n", sig == SIGSEGV ? "SIGSEGV" : "SIGBUS",
           si->si_code, a == expect ? "as formed" : "other",
           (unsigned long long)(a >> 56));
    siglongjmp(jb, 1);
}

static void plain(void) {
    uint64_t *buf = calloc(4, sizeof *buf);
    static const unsigned tags[] = {0x01, 0x5a, 0x80, 0xff};
    for (int i = 0; i < 4; i++) {
        volatile uint64_t *t = TAG(buf, tags[i]);
        *t = 0x1000 + tags[i];
        printf("tag %#04x: stored %#llx, read back %#llx\n", tags[i],
               (unsigned long long)buf[0], (unsigned long long)*t);
    }
    volatile uint8_t *b = TAG((uint8_t *)buf + 13, 0x33);
    *b = 0xab;
    volatile uint32_t *w = TAG((uint8_t *)buf + 20, 0x34);
    *w = 0xdeadbeef;
    printf("byte %#x, word %#x\n", ((uint8_t *)buf)[13], *(uint32_t *)((uint8_t *)buf + 20));
    free(buf);
}

static void pairs_and_vectors(void) {
    uint64_t src[4] = {1, 2, 3, 4}, dst[4] = {0};
    uint64_t a, b;
    __asm__ volatile("ldp %0, %1, [%2]" : "=r"(a), "=r"(b) : "r"(TAG(src, 0x42)) : "memory");
    __asm__ volatile("stp %0, %1, [%2]" ::"r"(b), "r"(a), "r"(TAG(dst, 0x43)) : "memory");
    printf("ldp/stp: %llu %llu\n", (unsigned long long)dst[0], (unsigned long long)dst[1]);
    __asm__ volatile("ld1 {v0.16b}, [%1]\n\tst1 {v0.16b}, [%0]" ::"r"(TAG(&dst[2], 0x7f)),
                     "r"(TAG(src, 0x09))
                     : "v0", "memory");
    printf("ld1/st1: %llu %llu\n", (unsigned long long)dst[2], (unsigned long long)dst[3]);
    __asm__ volatile("ldr q1, [%1]\n\tstr q1, [%0]" ::"r"(TAG(dst, 0x80)), "r"(TAG(&src[2], 0x81))
                     : "v1", "memory");
    printf("ldr/str q: %llu %llu\n", (unsigned long long)dst[0], (unsigned long long)dst[1]);
}

static void atomics(void) {
    uint64_t *p = calloc(2, sizeof *p);
    uint64_t *t = TAG(p, 0xc3);
    uint64_t old, fail;
    __asm__ volatile("1: ldxr %0, [%2]\n\t"
                     "add %0, %0, #5\n\t"
                     "stxr %w1, %0, [%3]\n\t"
                     "cbnz %w1, 1b"
                     : "=&r"(old), "=&r"(fail)
                     : "r"(t), "r"(TAG(p, 0x3c))
                     : "memory");
    printf("ldxr/stxr through two tags: %llu\n", (unsigned long long)*p);
    __asm__ volatile("ldaxr %0, [%2]\n\tstlxr %w1, %0, [%2]" : "=&r"(old), "=&r"(fail) : "r"(t) : "memory");
    printf("ldaxr/stlxr status %u\n", (unsigned)fail);
    __atomic_fetch_add(t, 10, __ATOMIC_SEQ_CST);
    uint64_t expected = 15;
    int swapped = __atomic_compare_exchange_n(t, &expected, 99, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    printf("fetch_add then cas: swapped %d value %llu\n", swapped, (unsigned long long)*p);
    free(p);
}

static void faults(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    void *ro = mmap(0, 16384, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    printf("store to a read-only page through tag 0x33:\n");
    expect = (uintptr_t)TAG((char *)ro + 8, 0x33);
    if (!sigsetjmp(jb, 1)) {
        *(volatile int *)expect = 1;
        printf("  no fault\n");
    }
    printf("load from an unmapped page through tag 0xee:\n");
    munmap(ro, 16384);
    expect = (uintptr_t)TAG((char *)ro + 0x40, 0xee);
    if (!sigsetjmp(jb, 1)) {
        (void)*(volatile int *)expect;
        printf("  no fault\n");
    }
    printf("branch to a tagged function address:\n");
    expect = (uintptr_t)TAG(&puts, 0x11);
    if (!sigsetjmp(jb, 1)) {
        ((int (*)(const char *))expect)("  branched");
        printf("  returned\n");
    }
}

static int method_imp(void) { return 42; }

static void objc(void) {
    void *h = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW);
    void *(*getClass)(const char *) = dlsym(h, "objc_getClass");
    void *(*allocPair)(void *, const char *, size_t) = dlsym(h, "objc_allocateClassPair");
    void (*registerPair)(void *) = dlsym(h, "objc_registerClassPair");
    int (*addMethod)(void *, void *, void (*)(void), const char *) = dlsym(h, "class_addMethod");
    void *(*registerName)(const char *) = dlsym(h, "sel_registerName");
    void *(*getMethod)(void *, void *) = dlsym(h, "class_getInstanceMethod");
    unsigned (*methodCount)(void *) = dlsym(h, "method_getNumberOfArguments");
    void *cls = allocPair(getClass("NSObject"), "RaxTaggedMethods", 0);
    int added = addMethod(cls, registerName("answer"), (void (*)(void))method_imp, "i@:");
    int again = addMethod(cls, registerName("answer"), (void (*)(void))method_imp, "i@:");
    int other = addMethod(cls, registerName("other:"), (void (*)(void))method_imp, "i@:i");
    registerPair(cls);
    void *m = getMethod(cls, registerName("other:"));
    printf("class_addMethod: %d %d %d, other: takes %u arguments\n", added, again, other,
           m ? methodCount(m) : 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    plain();
    pairs_and_vectors();
    atomics();
    faults();
    objc();
    return 0;
}
