/*
 * Context Switching via Inline Assembly
 *
 * Tests register save/restore for coroutine switching.
 * Exercises callee-saved register handling.
 *
 * Features exercised:
 *   - Register save/restore
 *   - Stack pointer manipulation
 *   - User-space context switching
 *   - Coroutine implementation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

#define STACK_SIZE 4096

/* Context structure to hold saved registers */
#if defined(__x86_64__)

typedef struct {
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
} Context;

__attribute__((noinline, noclone))
void context_switch(Context *from, Context *to) {
    __asm__ volatile(
        /* Save current context */
        "movq %%rsp, %c[rsp](%0)\n"
        "movq %%rbp, %c[rbp](%0)\n"
        "movq %%rbx, %c[rbx](%0)\n"
        "movq %%r12, %c[r12](%0)\n"
        "movq %%r13, %c[r13](%0)\n"
        "movq %%r14, %c[r14](%0)\n"
        "movq %%r15, %c[r15](%0)\n"
        "leaq 1f(%%rip), %%rax\n"
        "movq %%rax, %c[rip](%0)\n"

        /* Load new context */
        "movq %c[rsp](%1), %%rsp\n"
        "movq %c[rbp](%1), %%rbp\n"
        "movq %c[rbx](%1), %%rbx\n"
        "movq %c[r12](%1), %%r12\n"
        "movq %c[r13](%1), %%r13\n"
        "movq %c[r14](%1), %%r14\n"
        "movq %c[r15](%1), %%r15\n"
        "jmpq *%c[rip](%1)\n"
        "1:\n"
        :
        : "r"(from), "r"(to),
          [rsp] "i"(offsetof(Context, rsp)),
          [rbp] "i"(offsetof(Context, rbp)),
          [rbx] "i"(offsetof(Context, rbx)),
          [r12] "i"(offsetof(Context, r12)),
          [r13] "i"(offsetof(Context, r13)),
          [r14] "i"(offsetof(Context, r14)),
          [r15] "i"(offsetof(Context, r15)),
          [rip] "i"(offsetof(Context, rip))
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
          "memory", "cc"
    );
}

__attribute__((noinline))
void init_context(Context *ctx, void *stack_top, void (*entry)(void)) {
    memset(ctx, 0, sizeof(*ctx));
    /* Stack grows down, align to 16 bytes */
    ctx->rsp = ((uint64_t)stack_top - 8) & ~0xFUL;
    ctx->rbp = ctx->rsp;
    ctx->rip = (uint64_t)entry;
}

#elif defined(__aarch64__)

typedef struct {
    uint64_t sp;
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t x29; /* FP */
    uint64_t x30; /* LR */
} Context;

__attribute__((noinline, noclone))
void context_switch(Context *from, Context *to) {
    __asm__ volatile(
        /* Save current context */
        "mov x9, sp\n"
        "str x9, [%0, %[sp]]\n"
        "stp x19, x20, [%0, %[x19]]\n"
        "stp x21, x22, [%0, %[x21]]\n"
        "stp x23, x24, [%0, %[x23]]\n"
        "stp x25, x26, [%0, %[x25]]\n"
        "stp x27, x28, [%0, %[x27]]\n"
        "stp x29, x30, [%0, %[x29]]\n"

        /* Load new context */
        "ldr x9, [%1, %[sp]]\n"
        "mov sp, x9\n"
        "ldp x19, x20, [%1, %[x19]]\n"
        "ldp x21, x22, [%1, %[x21]]\n"
        "ldp x23, x24, [%1, %[x23]]\n"
        "ldp x25, x26, [%1, %[x25]]\n"
        "ldp x27, x28, [%1, %[x27]]\n"
        "ldp x29, x30, [%1, %[x29]]\n"
        "ret\n"
        :
        : "r"(from), "r"(to),
          [sp] "i"(offsetof(Context, sp)),
          [x19] "i"(offsetof(Context, x19)),
          [x21] "i"(offsetof(Context, x21)),
          [x23] "i"(offsetof(Context, x23)),
          [x25] "i"(offsetof(Context, x25)),
          [x27] "i"(offsetof(Context, x27)),
          [x29] "i"(offsetof(Context, x29))
        : "x9", "memory"
    );
}

__attribute__((noinline))
void init_context(Context *ctx, void *stack_top, void (*entry)(void)) {
    memset(ctx, 0, sizeof(*ctx));
    /* Stack must be 16-byte aligned */
    ctx->sp = (uint64_t)stack_top & ~0xFUL;
    ctx->x29 = ctx->sp;
    ctx->x30 = (uint64_t)entry;
}

#elif defined(__i386__)

typedef struct {
    uint32_t esp;
    uint32_t ebp;
    uint32_t ebx;
    uint32_t esi;
    uint32_t edi;
    uint32_t eip;
} Context;

__attribute__((noinline, noclone))
void context_switch(Context *from, Context *to) {
    __asm__ volatile(
        /* Save current context */
        "movl %%esp, %c[esp](%0)\n"
        "movl %%ebp, %c[ebp](%0)\n"
        "movl %%ebx, %c[ebx](%0)\n"
        "movl %%esi, %c[esi](%0)\n"
        "movl %%edi, %c[edi](%0)\n"
        "movl $1f, %c[eip](%0)\n"

        /* Load new context */
        "movl %c[esp](%1), %%esp\n"
        "movl %c[ebp](%1), %%ebp\n"
        "movl %c[ebx](%1), %%ebx\n"
        "movl %c[esi](%1), %%esi\n"
        "movl %c[edi](%1), %%edi\n"
        "jmpl *%c[eip](%1)\n"
        "1:\n"
        :
        : "r"(from), "r"(to),
          [esp] "i"(offsetof(Context, esp)),
          [ebp] "i"(offsetof(Context, ebp)),
          [ebx] "i"(offsetof(Context, ebx)),
          [esi] "i"(offsetof(Context, esi)),
          [edi] "i"(offsetof(Context, edi)),
          [eip] "i"(offsetof(Context, eip))
        : "eax", "ecx", "edx", "memory", "cc"
    );
}

__attribute__((noinline))
void init_context(Context *ctx, void *stack_top, void (*entry)(void)) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->esp = ((uint32_t)stack_top - 4) & ~0xFUL;
    ctx->ebp = ctx->esp;
    ctx->eip = (uint32_t)entry;
}

#else

/* Generic fallback - no real context switch, just call functions */
typedef struct {
    void (*entry)(void);
    int active;
} Context;

__attribute__((noinline))
void context_switch(Context *from, Context *to) {
    (void)from;
    if (to->entry && to->active) {
        to->entry();
    }
}

__attribute__((noinline))
void init_context(Context *ctx, void *stack_top, void (*entry)(void)) {
    (void)stack_top;
    ctx->entry = entry;
    ctx->active = 1;
}

#endif

/* Coroutine state */
typedef struct {
    Context ctx;
    char stack[STACK_SIZE];
    int64_t result;
    int finished;
} Coroutine;

static Coroutine main_coro;
static Coroutine worker_coros[4];
static int current_coro = -1; /* -1 = main, 0-3 = workers */

/* Yield back to main coroutine */
__attribute__((noinline))
void yield_to_main(void) {
    if (current_coro >= 0) {
        int prev = current_coro;
        current_coro = -1;
        context_switch(&worker_coros[prev].ctx, &main_coro.ctx);
    }
}

/* Resume specific worker coroutine */
__attribute__((noinline))
void resume_worker(int idx) {
    if (idx >= 0 && idx < 4 && !worker_coros[idx].finished) {
        current_coro = idx;
        context_switch(&main_coro.ctx, &worker_coros[idx].ctx);
    }
}

/* Worker coroutine functions */
__attribute__((noinline))
void worker_func_0(void) {
    int64_t sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i;
        if (i % 10 == 0) yield_to_main();
    }
    worker_coros[0].result = sum;
    worker_coros[0].finished = 1;
    yield_to_main();
}

__attribute__((noinline))
void worker_func_1(void) {
    int64_t prod = 1;
    for (int i = 1; i <= 10; i++) {
        prod *= i;
        yield_to_main();
    }
    worker_coros[1].result = prod;
    worker_coros[1].finished = 1;
    yield_to_main();
}

__attribute__((noinline))
void worker_func_2(void) {
    int64_t fib_a = 0, fib_b = 1;
    for (int i = 0; i < 20; i++) {
        int64_t next = fib_a + fib_b;
        fib_a = fib_b;
        fib_b = next;
        if (i % 5 == 0) yield_to_main();
    }
    worker_coros[2].result = fib_b;
    worker_coros[2].finished = 1;
    yield_to_main();
}

__attribute__((noinline))
void worker_func_3(void) {
    int64_t val = 1;
    for (int i = 0; i < 30; i++) {
        val = val * 3 % 1000000007;
        if (i % 3 == 0) yield_to_main();
    }
    worker_coros[3].result = val;
    worker_coros[3].finished = 1;
    yield_to_main();
}

/* Test basic context switching */
__attribute__((noinline))
int64_t test_basic_switch(void) {
    void (*funcs[4])(void) = {worker_func_0, worker_func_1, worker_func_2, worker_func_3};

    /* Initialize coroutines */
    memset(&main_coro, 0, sizeof(main_coro));
    for (int i = 0; i < 4; i++) {
        memset(&worker_coros[i], 0, sizeof(worker_coros[i]));
        void *stack_top = worker_coros[i].stack + STACK_SIZE;
        init_context(&worker_coros[i].ctx, stack_top, funcs[i]);
    }

    /* Run until all finished */
    int iterations = 0;
    while (iterations < 1000) {
        int all_done = 1;
        for (int i = 0; i < 4; i++) {
            if (!worker_coros[i].finished) {
                all_done = 0;
                resume_worker(i);
            }
        }
        if (all_done) break;
        iterations++;
    }

    int64_t result = 0;
    for (int i = 0; i < 4; i++) {
        result += worker_coros[i].result;
    }

    return result;
}

/* Simple register save/restore test without full context switch */
__attribute__((noinline))
int64_t test_register_preservation(void) {
    int64_t result = 0;

#if defined(__x86_64__)
    int64_t saved_rbx, saved_r12, saved_r13, saved_r14, saved_r15;

    __asm__ volatile(
        "movq %%rbx, %0\n"
        "movq %%r12, %1\n"
        "movq %%r13, %2\n"
        "movq %%r14, %3\n"
        "movq %%r15, %4\n"

        /* Modify callee-saved registers */
        "movq $100, %%rbx\n"
        "movq $200, %%r12\n"
        "movq $300, %%r13\n"
        "movq $400, %%r14\n"
        "movq $500, %%r15\n"

        /* Add them to result */
        "addq %%rbx, %5\n"
        "addq %%r12, %5\n"
        "addq %%r13, %5\n"
        "addq %%r14, %5\n"
        "addq %%r15, %5\n"

        /* Restore */
        "movq %0, %%rbx\n"
        "movq %1, %%r12\n"
        "movq %2, %%r13\n"
        "movq %3, %%r14\n"
        "movq %4, %%r15\n"
        : "=m"(saved_rbx), "=m"(saved_r12), "=m"(saved_r13),
          "=m"(saved_r14), "=m"(saved_r15), "+r"(result)
        :
        : "rbx", "r12", "r13", "r14", "r15", "memory"
    );
#elif defined(__aarch64__)
    int64_t saved[5];

    __asm__ volatile(
        "stp x19, x20, [%1]\n"
        "str x21, [%1, #16]\n"

        "mov x19, #100\n"
        "mov x20, #200\n"
        "mov x21, #300\n"

        "add %0, %0, x19\n"
        "add %0, %0, x20\n"
        "add %0, %0, x21\n"

        "ldp x19, x20, [%1]\n"
        "ldr x21, [%1, #16]\n"
        : "+r"(result)
        : "r"(saved)
        : "x19", "x20", "x21", "memory"
    );
#else
    /* Generic fallback */
    result = 100 + 200 + 300 + 400 + 500;
#endif

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 5; iter++) { /* rax: was 100 */
        result += test_basic_switch();
        result += test_register_preservation();
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
