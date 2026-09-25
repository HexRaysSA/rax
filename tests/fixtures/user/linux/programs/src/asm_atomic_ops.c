/*
 * Atomic Operations via Inline Assembly
 *
 * Tests lock-free atomic primitives.
 * Exercises architecture-specific atomic instructions.
 *
 * Features exercised:
 *   - Compare-and-swap (CAS)
 *   - Atomic fetch-and-add
 *   - Load-linked/store-conditional
 *   - Atomic exchange
 */

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

#if defined(__x86_64__) || defined(__i386__)

/* x86 atomic operations using LOCK prefix */
__attribute__((noinline))
int32_t atomic_load_32(volatile int32_t *ptr) {
    int32_t val;
    __asm__ volatile("movl %1, %0" : "=r"(val) : "m"(*ptr) : "memory");
    return val;
}

__attribute__((noinline))
void atomic_store_32(volatile int32_t *ptr, int32_t val) {
    __asm__ volatile("movl %1, %0" : "=m"(*ptr) : "r"(val) : "memory");
}

__attribute__((noinline))
int32_t atomic_fetch_add_32(volatile int32_t *ptr, int32_t val) {
    int32_t result;
    __asm__ volatile(
        "lock; xaddl %0, %1"
        : "=r"(result), "+m"(*ptr)
        : "0"(val)
        : "memory"
    );
    return result;
}

__attribute__((noinline))
int32_t atomic_exchange_32(volatile int32_t *ptr, int32_t val) {
    int32_t result;
    __asm__ volatile(
        "xchgl %0, %1"
        : "=r"(result), "+m"(*ptr)
        : "0"(val)
        : "memory"
    );
    return result;
}

__attribute__((noinline))
int atomic_cas_32(volatile int32_t *ptr, int32_t expected, int32_t desired) {
    int32_t prev;
    __asm__ volatile(
        "lock; cmpxchgl %2, %1"
        : "=a"(prev), "+m"(*ptr)
        : "r"(desired), "0"(expected)
        : "memory"
    );
    return prev == expected;
}

#if defined(__x86_64__)
__attribute__((noinline))
int64_t atomic_fetch_add_64(volatile int64_t *ptr, int64_t val) {
    int64_t result;
    __asm__ volatile(
        "lock; xaddq %0, %1"
        : "=r"(result), "+m"(*ptr)
        : "0"(val)
        : "memory"
    );
    return result;
}

__attribute__((noinline))
int atomic_cas_64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    int64_t prev;
    __asm__ volatile(
        "lock; cmpxchgq %2, %1"
        : "=a"(prev), "+m"(*ptr)
        : "r"(desired), "0"(expected)
        : "memory"
    );
    return prev == expected;
}
#else
__attribute__((noinline))
int64_t atomic_fetch_add_64(volatile int64_t *ptr, int64_t val) {
    return __sync_fetch_and_add(ptr, val);
}

__attribute__((noinline))
int atomic_cas_64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    return __sync_bool_compare_and_swap(ptr, expected, desired);
}
#endif

#elif defined(__aarch64__)

/* AArch64 atomic operations using LDXR/STXR */
__attribute__((noinline))
int32_t atomic_load_32(volatile int32_t *ptr) {
    int32_t val;
    __asm__ volatile("ldar %w0, %1" : "=r"(val) : "Q"(*ptr) : "memory");
    return val;
}

__attribute__((noinline))
void atomic_store_32(volatile int32_t *ptr, int32_t val) {
    __asm__ volatile("stlr %w1, %0" : "=Q"(*ptr) : "r"(val) : "memory");
}

__attribute__((noinline))
int32_t atomic_fetch_add_32(volatile int32_t *ptr, int32_t val) {
    int32_t result, tmp;
    __asm__ volatile(
        "1: ldxr %w0, %2\n"
        "   add %w1, %w0, %w3\n"
        "   stxr %w4, %w1, %2\n"
        "   cbnz %w4, 1b"
        : "=&r"(result), "=&r"(tmp), "+Q"(*ptr)
        : "r"(val), "r"(0)
        : "memory"
    );
    return result;
}

__attribute__((noinline))
int32_t atomic_exchange_32(volatile int32_t *ptr, int32_t val) {
    int32_t result, status;
    __asm__ volatile(
        "1: ldxr %w0, %2\n"
        "   stxr %w1, %w3, %2\n"
        "   cbnz %w1, 1b"
        : "=&r"(result), "=&r"(status), "+Q"(*ptr)
        : "r"(val)
        : "memory"
    );
    return result;
}

__attribute__((noinline))
int atomic_cas_32(volatile int32_t *ptr, int32_t expected, int32_t desired) {
    int32_t result;
    int status;
    __asm__ volatile(
        "1: ldxr %w0, %2\n"
        "   cmp %w0, %w3\n"
        "   b.ne 2f\n"
        "   stxr %w1, %w4, %2\n"
        "   cbnz %w1, 1b\n"
        "2:"
        : "=&r"(result), "=&r"(status), "+Q"(*ptr)
        : "r"(expected), "r"(desired)
        : "memory", "cc"
    );
    return result == expected;
}

__attribute__((noinline))
int64_t atomic_fetch_add_64(volatile int64_t *ptr, int64_t val) {
    int64_t result, tmp;
    int status;
    __asm__ volatile(
        "1: ldxr %0, %2\n"
        "   add %1, %0, %3\n"
        "   stxr %w4, %1, %2\n"
        "   cbnz %w4, 1b"
        : "=&r"(result), "=&r"(tmp), "+Q"(*ptr)
        : "r"(val), "r"(0)
        : "memory"
    );
    return result;
}

__attribute__((noinline))
int atomic_cas_64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    int64_t result;
    int status;
    __asm__ volatile(
        "1: ldxr %0, %2\n"
        "   cmp %0, %3\n"
        "   b.ne 2f\n"
        "   stxr %w1, %4, %2\n"
        "   cbnz %w1, 1b\n"
        "2:"
        : "=&r"(result), "=&r"(status), "+Q"(*ptr)
        : "r"(expected), "r"(desired)
        : "memory", "cc"
    );
    return result == expected;
}

#elif defined(__riscv)

/* RISC-V atomic operations using LR/SC or A extension */
__attribute__((noinline))
int32_t atomic_load_32(volatile int32_t *ptr) {
    int32_t val;
    __asm__ volatile("lw %0, 0(%1)" : "=r"(val) : "r"(ptr) : "memory");
    __asm__ volatile("fence r, rw" ::: "memory");
    return val;
}

__attribute__((noinline))
void atomic_store_32(volatile int32_t *ptr, int32_t val) {
    __asm__ volatile("fence rw, w" ::: "memory");
    __asm__ volatile("sw %0, 0(%1)" : : "r"(val), "r"(ptr) : "memory");
}

__attribute__((noinline))
int32_t atomic_fetch_add_32(volatile int32_t *ptr, int32_t val) {
    int32_t result;
    __asm__ volatile("amoadd.w.aqrl %0, %1, (%2)"
        : "=r"(result)
        : "r"(val), "r"(ptr)
        : "memory");
    return result;
}

__attribute__((noinline))
int32_t atomic_exchange_32(volatile int32_t *ptr, int32_t val) {
    int32_t result;
    __asm__ volatile("amoswap.w.aqrl %0, %1, (%2)"
        : "=r"(result)
        : "r"(val), "r"(ptr)
        : "memory");
    return result;
}

__attribute__((noinline))
int atomic_cas_32(volatile int32_t *ptr, int32_t expected, int32_t desired) {
    int32_t result, tmp;
    __asm__ volatile(
        "1: lr.w.aq %0, (%2)\n"
        "   bne %0, %3, 2f\n"
        "   sc.w.rl %1, %4, (%2)\n"
        "   bnez %1, 1b\n"
        "2:"
        : "=&r"(result), "=&r"(tmp)
        : "r"(ptr), "r"(expected), "r"(desired)
        : "memory"
    );
    return result == expected;
}

#if __riscv_xlen == 64
__attribute__((noinline))
int64_t atomic_fetch_add_64(volatile int64_t *ptr, int64_t val) {
    int64_t result;
    __asm__ volatile("amoadd.d.aqrl %0, %1, (%2)"
        : "=r"(result)
        : "r"(val), "r"(ptr)
        : "memory");
    return result;
}

__attribute__((noinline))
int atomic_cas_64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    int64_t result;
    int tmp;
    __asm__ volatile(
        "1: lr.d.aq %0, (%2)\n"
        "   bne %0, %3, 2f\n"
        "   sc.d.rl %1, %4, (%2)\n"
        "   bnez %1, 1b\n"
        "2:"
        : "=&r"(result), "=&r"(tmp)
        : "r"(ptr), "r"(expected), "r"(desired)
        : "memory"
    );
    return result == expected;
}
#else
__attribute__((noinline))
int64_t atomic_fetch_add_64(volatile int64_t *ptr, int64_t val) {
    return __sync_fetch_and_add(ptr, val);
}

__attribute__((noinline))
int atomic_cas_64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    return __sync_bool_compare_and_swap(ptr, expected, desired);
}
#endif

#else

/* Generic fallback using GCC builtins */
__attribute__((noinline))
int32_t atomic_load_32(volatile int32_t *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

__attribute__((noinline))
void atomic_store_32(volatile int32_t *ptr, int32_t val) {
    __atomic_store_n(ptr, val, __ATOMIC_SEQ_CST);
}

__attribute__((noinline))
int32_t atomic_fetch_add_32(volatile int32_t *ptr, int32_t val) {
    return __sync_fetch_and_add(ptr, val);
}

__attribute__((noinline))
int32_t atomic_exchange_32(volatile int32_t *ptr, int32_t val) {
    return __sync_lock_test_and_set(ptr, val);
}

__attribute__((noinline))
int atomic_cas_32(volatile int32_t *ptr, int32_t expected, int32_t desired) {
    return __sync_bool_compare_and_swap(ptr, expected, desired);
}

__attribute__((noinline))
int64_t atomic_fetch_add_64(volatile int64_t *ptr, int64_t val) {
    return __sync_fetch_and_add(ptr, val);
}

__attribute__((noinline))
int atomic_cas_64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    return __sync_bool_compare_and_swap(ptr, expected, desired);
}

#endif

/* Test atomic counter */
__attribute__((noinline))
int64_t test_atomic_counter(void) {
    volatile int32_t counter = 0;
    int64_t result = 0;

    for (int i = 0; i < 1000; i++) {
        int32_t old = atomic_fetch_add_32(&counter, 1);
        result += old;
    }

    result += atomic_load_32(&counter);
    return result;
}

/* Test atomic exchange */
__attribute__((noinline))
int64_t test_atomic_exchange(void) {
    volatile int32_t val = 0;
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        int32_t old = atomic_exchange_32(&val, i);
        result += old;
    }

    return result + atomic_load_32(&val);
}

/* Test compare-and-swap */
__attribute__((noinline))
int64_t test_cas_32(void) {
    volatile int32_t val = 0;
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        int32_t expected = i;
        if (atomic_cas_32(&val, expected, i + 1)) {
            result += 1;
        }
    }

    return result + atomic_load_32(&val);
}

/* Test 64-bit atomics */
__attribute__((noinline))
int64_t test_atomic_64(void) {
    volatile int64_t counter = 0;
    int64_t result = 0;

    for (int i = 0; i < 500; i++) {
        int64_t old = atomic_fetch_add_64(&counter, 1);
        result += old;
    }

    /* Test CAS */
    int64_t expected = 500;
    if (atomic_cas_64(&counter, expected, 1000)) {
        result += 100;
    }

    result += counter;
    return result;
}

/* Simulated lock-free stack push/pop */
typedef struct Node {
    struct Node *next;
    int value;
} Node;

static Node nodes[64];
volatile Node *stack_head;

__attribute__((noinline))
int push_node(int value) {
    static volatile int32_t node_idx = 0;
    int32_t idx = atomic_fetch_add_32(&node_idx, 1) % 64;

    Node *node = &nodes[idx];
    node->value = value;

    Node *old_head;
    do {
        old_head = (Node *)stack_head;
        node->next = old_head;
    } while (!atomic_cas_64((volatile int64_t *)&stack_head,
                           (int64_t)old_head, (int64_t)node));
    return 1;
}

__attribute__((noinline))
int pop_node(int *value) {
    Node *old_head;
    Node *new_head;

    do {
        old_head = (Node *)stack_head;
        if (old_head == NULL) {
            return 0;
        }
        new_head = old_head->next;
    } while (!atomic_cas_64((volatile int64_t *)&stack_head,
                           (int64_t)old_head, (int64_t)new_head));

    *value = old_head->value;
    return 1;
}

__attribute__((noinline))
int64_t test_lock_free_stack(void) {
    int64_t result = 0;
    stack_head = NULL;

    /* Push values */
    for (int i = 0; i < 32; i++) {
        push_node(i);
    }

    /* Pop values */
    int value;
    while (pop_node(&value)) {
        result += value;
    }

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 10; iter++) { /* rax: was 100 */
        result += test_atomic_counter();
        result += test_atomic_exchange();
        result += test_cas_32();
        result += test_atomic_64();
        result += test_lock_free_stack();
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
