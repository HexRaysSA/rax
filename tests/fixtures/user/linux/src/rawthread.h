/* A thread made by a bare clone(2) with the caller's flags, for fixtures
 * that need clone flags pthread_create does not use (musl's clone()
 * refuses CLONE_THREAD). The new thread shares the caller's TLS, so its
 * function must keep to raw system calls and plain memory: no stdio, no
 * locks. It runs on `stack_top` (16-byte aligned), gets `arg`, and exits
 * the thread with the function's result. Returns the new TID, or the
 * negated errno. With CLONE_CHILD_CLEARTID, `*ctid` is cleared and woken
 * at the thread's exit. */
#ifndef RAX_FIXTURE_RAWTHREAD_H
#define RAX_FIXTURE_RAWTHREAD_H

typedef int (*raw_thread_fn)(void *);

static long raw_thread(unsigned long flags, void *stack_top, raw_thread_fn fn, void *arg,
                       int *ctid) {
#if defined(__x86_64__)
    /* clone(flags, stack, ptid, ctid, tls): the function and its argument
     * travel on the new stack. */
    void **sp = (void **)stack_top;
    *--sp = arg;
    *--sp = (void *)fn;
    register long r10 __asm__("r10") = (long)ctid;
    register long r8 __asm__("r8") = 0;
    long ret;
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "pop %%rax\n\t"
                     "pop %%rdi\n\t"
                     "call *%%rax\n\t"
                     "mov %%eax, %%edi\n\t"
                     "mov $60, %%eax\n\t"
                     "syscall\n\t"
                     "hlt\n"
                     "1:"
                     : "=a"(ret)
                     : "a"(56L), "D"(flags), "S"(sp), "d"(0L), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return ret;
#elif defined(__aarch64__)
    /* clone(flags, stack, ptid, tls, ctid): the child starts with the
     * caller's registers, so x9 and x10 carry the function and argument. */
    register long x8 __asm__("x8") = 220;
    register long x0 __asm__("x0") = (long)flags;
    register long x1 __asm__("x1") = (long)stack_top;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = (long)ctid;
    register long x9 __asm__("x9") = (long)fn;
    register long x10 __asm__("x10") = (long)arg;
    __asm__ volatile("svc #0\n\t"
                     "cbnz x0, 1f\n\t"
                     "mov x0, x10\n\t"
                     "blr x9\n\t"
                     "mov x8, #93\n\t"
                     "svc #0\n"
                     "1:"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x9), "r"(x10)
                     : "memory");
    return x0;
#elif defined(__riscv) && __riscv_xlen == 64
    /* clone(flags, stack, ptid, tls, ctid), as on arm64; t0 and t1 carry
     * the function and argument. */
    register long a7 __asm__("a7") = 220;
    register long a0 __asm__("a0") = (long)flags;
    register long a1 __asm__("a1") = (long)stack_top;
    register long a2 __asm__("a2") = 0;
    register long a3 __asm__("a3") = 0;
    register long a4 __asm__("a4") = (long)ctid;
    register long t0 __asm__("t0") = (long)fn;
    register long t1 __asm__("t1") = (long)arg;
    __asm__ volatile("ecall\n\t"
                     "bnez a0, 1f\n\t"
                     "mv a0, t1\n\t"
                     "jalr t0\n\t"
                     "li a7, 93\n\t"
                     "ecall\n"
                     "1:"
                     : "+r"(a0)
                     : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(t0), "r"(t1)
                     : "memory");
    return a0;
#else
#error "raw_thread: unsupported architecture"
#endif
}

#endif
