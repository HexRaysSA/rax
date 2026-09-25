/*
 * Memory Barriers via Inline Assembly
 *
 * Tests memory ordering instructions.
 * Exercises architecture-specific fence instructions.
 *
 * Features exercised:
 *   - Full memory barriers
 *   - Load/store barriers
 *   - Compiler barriers
 *   - Acquire/release semantics
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;
volatile int shared_data;
volatile int flag;

/* Compiler barrier - prevent reordering by compiler */
#define COMPILER_BARRIER() __asm__ volatile("" ::: "memory")

#if defined(__x86_64__) || defined(__i386__)

/* x86 memory barriers */
__attribute__((noinline))
void full_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

__attribute__((noinline))
void store_barrier(void) {
    __asm__ volatile("sfence" ::: "memory");
}

__attribute__((noinline))
void load_barrier(void) {
    __asm__ volatile("lfence" ::: "memory");
}

/* x86 is strongly ordered, but we can use LOCK prefix */
__attribute__((noinline))
void lock_barrier(void) {
    int dummy = 0;
    __asm__ volatile("lock; addl $0, %0" : "+m"(dummy) :: "memory");
}

#elif defined(__aarch64__)

/* AArch64 memory barriers */
__attribute__((noinline))
void full_barrier(void) {
    __asm__ volatile("dmb ish" ::: "memory");
}

__attribute__((noinline))
void store_barrier(void) {
    __asm__ volatile("dmb ishst" ::: "memory");
}

__attribute__((noinline))
void load_barrier(void) {
    __asm__ volatile("dmb ishld" ::: "memory");
}

__attribute__((noinline))
void instruction_barrier(void) {
    __asm__ volatile("isb" ::: "memory");
}

/* Data synchronization barrier */
__attribute__((noinline))
void dsb_barrier(void) {
    __asm__ volatile("dsb ish" ::: "memory");
}

__attribute__((noinline))
void lock_barrier(void) {
    full_barrier();
}

#elif defined(__arm__)

/* ARMv7 memory barriers */
__attribute__((noinline))
void full_barrier(void) {
    __asm__ volatile("dmb ish" ::: "memory");
}

__attribute__((noinline))
void store_barrier(void) {
    __asm__ volatile("dmb ishst" ::: "memory");
}

__attribute__((noinline))
void load_barrier(void) {
    __asm__ volatile("dmb ish" ::: "memory");
}

__attribute__((noinline))
void lock_barrier(void) {
    full_barrier();
}

#elif defined(__riscv)

/* RISC-V memory barriers */
__attribute__((noinline))
void full_barrier(void) {
    __asm__ volatile("fence rw, rw" ::: "memory");
}

__attribute__((noinline))
void store_barrier(void) {
    __asm__ volatile("fence w, w" ::: "memory");
}

__attribute__((noinline))
void load_barrier(void) {
    __asm__ volatile("fence r, r" ::: "memory");
}

__attribute__((noinline))
void acquire_barrier(void) {
    __asm__ volatile("fence r, rw" ::: "memory");
}

__attribute__((noinline))
void release_barrier(void) {
    __asm__ volatile("fence rw, w" ::: "memory");
}

__attribute__((noinline))
void lock_barrier(void) {
    full_barrier();
}

#elif defined(__powerpc__) || defined(__powerpc64__)

/* PowerPC memory barriers */
__attribute__((noinline))
void full_barrier(void) {
    __asm__ volatile("sync" ::: "memory");
}

__attribute__((noinline))
void store_barrier(void) {
    __asm__ volatile("lwsync" ::: "memory");
}

__attribute__((noinline))
void load_barrier(void) {
    __asm__ volatile("lwsync" ::: "memory");
}

__attribute__((noinline))
void io_barrier(void) {
    __asm__ volatile("eieio" ::: "memory");
}

__attribute__((noinline))
void lock_barrier(void) {
    full_barrier();
}

#elif defined(__mips__)

/* MIPS memory barriers */
__attribute__((noinline))
void full_barrier(void) {
    __asm__ volatile("sync" ::: "memory");
}

__attribute__((noinline))
void store_barrier(void) {
    __asm__ volatile("sync" ::: "memory");
}

__attribute__((noinline))
void load_barrier(void) {
    __asm__ volatile("sync" ::: "memory");
}

__attribute__((noinline))
void lock_barrier(void) {
    full_barrier();
}

#else

/* Generic fallback using GCC builtins */
__attribute__((noinline))
void full_barrier(void) {
    __sync_synchronize();
}

__attribute__((noinline))
void store_barrier(void) {
    __sync_synchronize();
}

__attribute__((noinline))
void load_barrier(void) {
    __sync_synchronize();
}

__attribute__((noinline))
void lock_barrier(void) {
    __sync_synchronize();
}

#endif

/* Test store-load ordering */
__attribute__((noinline))
int64_t test_store_load_ordering(void) {
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        shared_data = i;
        store_barrier();
        flag = 1;

        /* Reader side would be in another thread */
        load_barrier();
        if (flag) {
            result += shared_data;
        }
        flag = 0;
    }

    return result;
}

/* Test acquire-release pattern */
__attribute__((noinline))
int64_t test_acquire_release(void) {
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        /* Release store */
        shared_data = i * 2;
        store_barrier(); /* Release */
        flag = 1;

        /* Acquire load */
        while (!flag) {
            COMPILER_BARRIER();
        }
        load_barrier(); /* Acquire */
        result += shared_data;

        flag = 0;
        full_barrier();
    }

    return result;
}

/* Test multiple barriers in sequence */
__attribute__((noinline))
int64_t test_barrier_sequence(void) {
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        shared_data = i;
        COMPILER_BARRIER();
        store_barrier();
        COMPILER_BARRIER();
        flag = 1;
        full_barrier();

        if (flag) {
            load_barrier();
            result += shared_data;
        }

        COMPILER_BARRIER();
        flag = 0;
        lock_barrier();
    }

    return result;
}

/* Test barrier with volatile access patterns */
__attribute__((noinline))
int64_t test_volatile_barriers(void) {
    volatile int local_a = 0;
    volatile int local_b = 0;
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        local_a = i;
        COMPILER_BARRIER();
        local_b = i + 1;
        store_barrier();

        load_barrier();
        result += local_a;
        COMPILER_BARRIER();
        result += local_b;
    }

    return result;
}

/* Simulated spinlock using barriers */
__attribute__((noinline))
int64_t test_spinlock_pattern(void) {
    volatile int lock = 0;
    int64_t result = 0;

    for (int i = 0; i < 50; i++) {
        /* Acquire lock */
        while (__sync_lock_test_and_set(&lock, 1)) {
            COMPILER_BARRIER();
        }
        load_barrier(); /* Acquire barrier */

        /* Critical section */
        shared_data = i;
        result += shared_data;

        /* Release lock */
        store_barrier(); /* Release barrier */
        __sync_lock_release(&lock);
    }

    return result;
}

/* Test barriers with array operations */
__attribute__((noinline))
int64_t test_array_barriers(void) {
    volatile int arr[16];
    int64_t result = 0;

    for (int round = 0; round < 50; round++) {
        /* Write with barriers */
        for (int i = 0; i < 16; i++) {
            arr[i] = round * 16 + i;
            if (i % 4 == 3) {
                store_barrier();
            }
        }

        full_barrier();

        /* Read with barriers */
        for (int i = 0; i < 16; i++) {
            if (i % 4 == 0) {
                load_barrier();
            }
            result += arr[i];
        }
    }

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 10; iter++) { /* rax: was 100 */
        result += test_store_load_ordering();
        result += test_acquire_release();
        result += test_barrier_sequence();
        result += test_volatile_barriers();
        result += test_spinlock_pattern();
        result += test_array_barriers();
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
