// thread_get_state and thread_set_state on a suspended thread: the flavor
// lists, the thread state (its PC in the loop the thread spins in), the
// unified states' headers, the exception, vector, and debug states, a
// register changed and seen by the thread when it resumes, and the count,
// flavor, and target errors. Rosetta answers the x86 flavors itself: the
// flavor lists, the page-in state, the AVX counts and header, and the
// exception state's values, where it departs from an Intel kernel, run on
// arm64 only.
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// spin(flag): waits for *flag, then returns a callee-saved register
// (x20 / rbx) that only thread_set_state can have changed.
extern void *spin(void *flag);
extern char spin_loop[], spin_end[];
#if defined(__arm64__)
__asm__(".globl _spin\n_spin:\n"
        "    mov x20, #7\n"
        ".globl _spin_loop\n_spin_loop:\n"
        "    ldr w9, [x0]\n"
        "    cbz w9, _spin_loop\n"
        "    mov x0, x20\n"
        "    ret\n"
        ".globl _spin_end\n_spin_end:\n");
#define STATE64 ARM_THREAD_STATE64
#define STATE64_COUNT ARM_THREAD_STATE64_COUNT
#else
__asm__(".globl _spin\n_spin:\n"
        "    push %rbx\n"
        "    mov $7, %rbx\n"
        ".globl _spin_loop\n_spin_loop:\n"
        "    movl (%rdi), %eax\n"
        "    testl %eax, %eax\n"
        "    jz _spin_loop\n"
        "    mov %rbx, %rax\n"
        "    pop %rbx\n"
        "    ret\n"
        ".globl _spin_end\n_spin_end:\n");
#define STATE64 x86_THREAD_STATE64
#define STATE64_COUNT x86_THREAD_STATE64_COUNT
#endif

static volatile int go;

static void show_list(thread_t t, int flavor, mach_msg_type_number_t cnt) {
    natural_t s[16];
    memset(s, 0xff, sizeof s);
    mach_msg_type_number_t n = cnt;
    kern_return_t kr = thread_get_state(t, flavor, s, &n);
    printf("flavor list %d (room %u): kr=%d", flavor, cnt, kr);
    for (unsigned i = 0; kr == 0 && i < n; i++) printf(" %u", s[i]);
    printf("\n");
}

static void show_count(thread_t t, int flavor, mach_msg_type_number_t cnt, const char *name) {
    natural_t s[THREAD_STATE_MAX];
    mach_msg_type_number_t n = cnt;
    kern_return_t kr = thread_get_state(t, flavor, s, &n);
    printf("%s (flavor %d, room %u): kr=%d count=%u", name, flavor, cnt, kr, kr ? 0 : n);
    if (kr == 0 && n >= 2) printf(" header=%u,%u", s[0], s[1]);
    printf("\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t th;
    pthread_create(&th, NULL, spin, (void *)&go);
    thread_t t = pthread_mach_thread_np(th);
    usleep(100000);
    printf("suspend: %d\n", thread_suspend(t));

#if defined(__arm64__)
    // Flavor lists: the room each needs.
    show_list(t, 0, 3);
    show_list(t, 0, 4);
    show_list(t, 128, 3);
    show_list(t, 128, 4);
    show_list(t, 129, 5);
    show_list(t, 131, 4);
    show_list(t, 131, 5);
#endif

    // The thread state: its PC is in the loop.
    natural_t s[THREAD_STATE_MAX];
    mach_msg_type_number_t n = STATE64_COUNT;
    kern_return_t kr = thread_get_state(t, STATE64, s, &n);
#if defined(__arm64__)
    arm_thread_state64_t *ts = (arm_thread_state64_t *)s;
    uint64_t pc = __darwin_arm_thread_state64_get_pc(*ts);
    printf("thread state: kr=%d count=%u pc in loop %d x20=%llu flags=%#x\n", kr, n,
           pc >= (uint64_t)spin_loop && pc < (uint64_t)spin_end, (unsigned long long)ts->__x[20], s[67]);
#else
    x86_thread_state64_t *ts = (x86_thread_state64_t *)s;
    printf("thread state: kr=%d count=%u rip in loop %d rbx=%llu cs=%#llx\n", kr, n,
           ts->__rip >= (uint64_t)spin_loop && ts->__rip < (uint64_t)spin_end,
           (unsigned long long)ts->__rbx, (unsigned long long)ts->__cs);
#endif
    n = STATE64_COUNT - 1;
    printf("thread state, one word short: %d\n", thread_get_state(t, STATE64, s, &n));
    n = 9999;
    printf("flavor 9999: %d\n", thread_get_state(t, 9999, s, &n));

#if defined(__arm64__)
    show_count(t, ARM_THREAD_STATE, ARM_UNIFIED_THREAD_STATE_COUNT, "unified thread state");
    show_count(t, ARM_THREAD_STATE, ARM_UNIFIED_THREAD_STATE_COUNT - 1, "unified thread state, short");
    show_count(t, ARM_THREAD_STATE32, 100, "32-bit thread state");
    show_count(t, ARM_EXCEPTION_STATE64, ARM_EXCEPTION_STATE64_COUNT, "exception state");
    show_count(t, ARM_EXCEPTION_STATE64_V2, ARM_EXCEPTION_STATE64_V2_COUNT, "exception state v2");
    show_count(t, ARM_EXCEPTION_STATE, 100, "32-bit exception state");
    show_count(t, ARM_NEON_STATE64, ARM_NEON_STATE64_COUNT, "neon state");
    show_count(t, ARM_NEON_STATE, 100, "32-bit neon state");
    show_count(t, ARM_VFP_STATE, 100, "vfp state");
    show_count(t, ARM_VFP_STATE, 40, "vfp state, v2 room");
    show_count(t, ARM_VFP_STATE, 32, "vfp state, too little room");
    show_count(t, ARM_DEBUG_STATE64, ARM_DEBUG_STATE64_COUNT, "debug state");
    show_count(t, ARM_DEBUG_STATE, 100, "legacy debug state");
    show_count(t, ARM_PAGEIN_STATE, 1, "pagein state");
    // Debug state: context-ID breakpoints are refused; a breakpoint's
    // control word is masked and made user-mode.
    arm_debug_state64_t ds;
    memset(&ds, 0, sizeof ds);
    ds.__bcr[0] = 1u << 21;
    printf("debug state, context breakpoint: %d\n",
           thread_set_state(t, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT));
    ds.__bcr[0] = 0xffff01e7ull & ~(1u << 21 | 1u << 20);
    ds.__bvr[0] = 0x100000003ull;
    printf("debug state, set: %d\n",
           thread_set_state(t, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT));
    memset(&ds, 0, sizeof ds);
    n = ARM_DEBUG_STATE64_COUNT;
    kr = thread_get_state(t, ARM_DEBUG_STATE64, (thread_state_t)&ds, &n);
    printf("debug state, get: kr=%d bcr0=%#llx bvr0=%#llx mdscr=%#llx\n", kr, (unsigned long long)ds.__bcr[0],
           (unsigned long long)ds.__bvr[0], (unsigned long long)ds.__mdscr_el1);
    memset(&ds, 0, sizeof ds);
    printf("debug state, cleared: %d\n",
           thread_set_state(t, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT));
    printf("debug state, bad count: %d\n",
           thread_set_state(t, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT - 1));
    printf("exception state set: %d\n", thread_set_state(t, ARM_EXCEPTION_STATE64, s, ARM_EXCEPTION_STATE64_COUNT));
    printf("pagein state set: %d\n", thread_set_state(t, ARM_PAGEIN_STATE, s, 1));
#else
    show_count(t, x86_THREAD_STATE, x86_THREAD_STATE_COUNT, "unified thread state");
    show_count(t, x86_THREAD_STATE32, 100, "32-bit thread state");
    show_count(t, x86_FLOAT_STATE64, x86_FLOAT_STATE64_COUNT, "float state");
    show_count(t, x86_FLOAT_STATE, x86_FLOAT_STATE_COUNT, "unified float state");
    show_count(t, x86_AVX_STATE64, x86_AVX_STATE64_COUNT, "avx state");
    n = x86_EXCEPTION_STATE64_COUNT;
    printf("exception state: kr=%d count=%u\n", thread_get_state(t, x86_EXCEPTION_STATE64, s, &n), n);
    show_count(t, x86_EXCEPTION_STATE, x86_EXCEPTION_STATE_COUNT, "unified exception state");
    show_count(t, x86_DEBUG_STATE64, x86_DEBUG_STATE64_COUNT, "debug state");
    show_count(t, x86_DEBUG_STATE, x86_DEBUG_STATE_COUNT, "unified debug state");
    printf("exception state set: %d\n", thread_set_state(t, x86_EXCEPTION_STATE64, s, x86_EXCEPTION_STATE64_COUNT));
#endif

    // Change the register the loop's exit returns and let the thread go.
    n = STATE64_COUNT;
    thread_get_state(t, STATE64, s, &n);
#if defined(__arm64__)
    ts->__x[20] = 0x5a5a;
#else
    ts->__rbx = 0x5a5a;
#endif
    printf("thread state, one word short: %d\n", thread_set_state(t, STATE64, s, STATE64_COUNT - 1));
    printf("set: %d\n", thread_set_state(t, STATE64, s, STATE64_COUNT));
    n = STATE64_COUNT;
    thread_get_state(t, STATE64, s, &n);
#if defined(__arm64__)
    printf("x20 after set: %#llx\n", (unsigned long long)ts->__x[20]);
#else
    printf("rbx after set: %#llx\n", (unsigned long long)ts->__rbx);
#endif
    printf("get on the task port: %d\n", thread_get_state(mach_task_self(), STATE64, s, &n));
    go = 1;
    printf("resume: %d\n", thread_resume(t));
    void *ret;
    pthread_join(th, &ret);
    printf("the thread returned %#lx\n", (unsigned long)ret);
    return 0;
}
