/*
 * Raw System Call Invocation via Inline Assembly
 *
 * Bypasses libc to invoke syscalls directly.
 * Tests architecture-specific syscall mechanisms.
 *
 * Features exercised:
 *   - Syscall instruction/trap
 *   - Syscall number passing
 *   - Argument registers
 *   - Return value handling
 */

#include <stdint.h>
#include <stddef.h>

volatile int64_t sink;

#if defined(__x86_64__) && defined(__linux__)

/* x86_64 Linux syscall numbers */
#define SYS_read    0
#define SYS_write   1
#define SYS_getpid  39
#define SYS_getuid  102
#define SYS_getgid  104
#define SYS_gettid  186
#define SYS_time    201

__attribute__((noinline))
long raw_syscall0(long num) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noinline))
long raw_syscall1(long num, long arg1) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noinline))
long raw_syscall2(long num, long arg1, long arg2) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noinline))
long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    long ret;
    register long r10 __asm__("r10") = arg3;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noinline))
int64_t test_getpid(void) {
    return raw_syscall0(SYS_getpid);
}

__attribute__((noinline))
int64_t test_getuid(void) {
    return raw_syscall0(SYS_getuid);
}

__attribute__((noinline))
int64_t test_getgid(void) {
    return raw_syscall0(SYS_getgid);
}

__attribute__((noinline))
int64_t test_gettid(void) {
    return raw_syscall0(SYS_gettid);
}

__attribute__((noinline))
int64_t test_write_stdout(void) {
    const char msg[] = "";
    return raw_syscall3(SYS_write, 1, (long)msg, 0);
}

#elif defined(__aarch64__) && defined(__linux__)

/* AArch64 Linux syscall numbers */
#define SYS_read    63
#define SYS_write   64
#define SYS_getpid  172
#define SYS_getuid  174
#define SYS_getgid  176
#define SYS_gettid  178

__attribute__((noinline))
long raw_syscall0(long num) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0");
    __asm__ volatile(
        "svc #0"
        : "=r"(x0)
        : "r"(x8)
        : "memory"
    );
    return x0;
}

__attribute__((noinline))
long raw_syscall1(long num, long arg1) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = arg1;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory"
    );
    return x0;
}

__attribute__((noinline))
long raw_syscall2(long num, long arg1, long arg2) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1)
        : "memory"
    );
    return x0;
}

__attribute__((noinline))
long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory"
    );
    return x0;
}

__attribute__((noinline))
int64_t test_getpid(void) {
    return raw_syscall0(SYS_getpid);
}

__attribute__((noinline))
int64_t test_getuid(void) {
    return raw_syscall0(SYS_getuid);
}

__attribute__((noinline))
int64_t test_getgid(void) {
    return raw_syscall0(SYS_getgid);
}

__attribute__((noinline))
int64_t test_gettid(void) {
    return raw_syscall0(SYS_gettid);
}

__attribute__((noinline))
int64_t test_write_stdout(void) {
    const char msg[] = "";
    return raw_syscall3(SYS_write, 1, (long)msg, 0);
}

#elif defined(__i386__) && defined(__linux__)

/* i386 Linux syscall numbers (via int 0x80) */
#define SYS_read    3
#define SYS_write   4
#define SYS_getpid  20
#define SYS_getuid  24
#define SYS_getgid  47
#define SYS_gettid  224

__attribute__((noinline))
long raw_syscall0(long num) {
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num)
        : "memory"
    );
    return ret;
}

__attribute__((noinline))
long raw_syscall1(long num, long arg1) {
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1)
        : "memory"
    );
    return ret;
}

__attribute__((noinline))
long raw_syscall2(long num, long arg1, long arg2) {
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1), "c"(arg2)
        : "memory"
    );
    return ret;
}

__attribute__((noinline))
long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1), "c"(arg2), "d"(arg3)
        : "memory"
    );
    return ret;
}

__attribute__((noinline))
int64_t test_getpid(void) {
    return raw_syscall0(SYS_getpid);
}

__attribute__((noinline))
int64_t test_getuid(void) {
    return raw_syscall0(SYS_getuid);
}

__attribute__((noinline))
int64_t test_getgid(void) {
    return raw_syscall0(SYS_getgid);
}

__attribute__((noinline))
int64_t test_gettid(void) {
    return raw_syscall0(SYS_gettid);
}

__attribute__((noinline))
int64_t test_write_stdout(void) {
    const char msg[] = "";
    return raw_syscall3(SYS_write, 1, (long)msg, 0);
}

#elif defined(__riscv) && defined(__linux__)

/* RISC-V Linux syscall numbers */
#define SYS_read    63
#define SYS_write   64
#define SYS_getpid  172
#define SYS_getuid  174
#define SYS_getgid  176
#define SYS_gettid  178

__attribute__((noinline))
long raw_syscall0(long num) {
    register long a7 __asm__("a7") = num;
    register long a0 __asm__("a0");
    __asm__ volatile(
        "ecall"
        : "=r"(a0)
        : "r"(a7)
        : "memory"
    );
    return a0;
}

__attribute__((noinline))
long raw_syscall1(long num, long arg1) {
    register long a7 __asm__("a7") = num;
    register long a0 __asm__("a0") = arg1;
    __asm__ volatile(
        "ecall"
        : "+r"(a0)
        : "r"(a7)
        : "memory"
    );
    return a0;
}

__attribute__((noinline))
long raw_syscall2(long num, long arg1, long arg2) {
    register long a7 __asm__("a7") = num;
    register long a0 __asm__("a0") = arg1;
    register long a1 __asm__("a1") = arg2;
    __asm__ volatile(
        "ecall"
        : "+r"(a0)
        : "r"(a7), "r"(a1)
        : "memory"
    );
    return a0;
}

__attribute__((noinline))
long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    register long a7 __asm__("a7") = num;
    register long a0 __asm__("a0") = arg1;
    register long a1 __asm__("a1") = arg2;
    register long a2 __asm__("a2") = arg3;
    __asm__ volatile(
        "ecall"
        : "+r"(a0)
        : "r"(a7), "r"(a1), "r"(a2)
        : "memory"
    );
    return a0;
}

__attribute__((noinline))
int64_t test_getpid(void) {
    return raw_syscall0(SYS_getpid);
}

__attribute__((noinline))
int64_t test_getuid(void) {
    return raw_syscall0(SYS_getuid);
}

__attribute__((noinline))
int64_t test_getgid(void) {
    return raw_syscall0(SYS_getgid);
}

__attribute__((noinline))
int64_t test_gettid(void) {
    return raw_syscall0(SYS_gettid);
}

__attribute__((noinline))
int64_t test_write_stdout(void) {
    const char msg[] = "";
    return raw_syscall3(SYS_write, 1, (long)msg, 0);
}

#else

/* Non-Linux or unsupported architecture - use libc stubs */
#include <unistd.h>
#include <sys/types.h>

__attribute__((noinline))
long raw_syscall0(long num) {
    (void)num;
    return 0;
}

__attribute__((noinline))
long raw_syscall1(long num, long arg1) {
    (void)num;
    (void)arg1;
    return 0;
}

__attribute__((noinline))
long raw_syscall2(long num, long arg1, long arg2) {
    (void)num;
    (void)arg1;
    (void)arg2;
    return 0;
}

__attribute__((noinline))
long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    (void)num;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    return 0;
}

__attribute__((noinline))
int64_t test_getpid(void) {
#ifdef _POSIX_VERSION
    return getpid();
#else
    return 0;
#endif
}

__attribute__((noinline))
int64_t test_getuid(void) {
#ifdef _POSIX_VERSION
    return getuid();
#else
    return 0;
#endif
}

__attribute__((noinline))
int64_t test_getgid(void) {
#ifdef _POSIX_VERSION
    return getgid();
#else
    return 0;
#endif
}

__attribute__((noinline))
int64_t test_gettid(void) {
    return 0;
}

__attribute__((noinline))
int64_t test_write_stdout(void) {
    return 0;
}

#endif

/* Test repeated syscalls */
__attribute__((noinline))
int64_t test_repeated_syscalls(void) {
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        result += test_getpid();
        result += test_getuid();
        result += test_getgid();
    }

    return result;
}

/* Test syscall timing */
__attribute__((noinline))
int64_t test_syscall_timing(void) {
    int64_t result = 0;

    /* Make many quick syscalls */
    for (int i = 0; i < 1000; i++) {
        result += test_getpid();
    }

    return result;
}

/* Test interleaved syscalls */
__attribute__((noinline))
int64_t test_interleaved(void) {
    int64_t result = 0;
    int64_t pid = test_getpid();
    int64_t uid = test_getuid();
    int64_t gid = test_getgid();

    for (int i = 0; i < 50; i++) {
        result += pid;
        result += uid;
        result += gid;

        if (i % 10 == 0) {
            /* Verify values haven't changed */
            result += (test_getpid() == pid) ? 1 : 0;
            result += (test_getuid() == uid) ? 1 : 0;
            result += (test_getgid() == gid) ? 1 : 0;
        }
    }

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 10; iter++) { /* rax: was 100 */
        result += test_getpid();
        result += test_getuid();
        result += test_getgid();
        result += test_gettid();
        result += test_write_stdout();
        result += test_repeated_syscalls();
        result += test_syscall_timing();
        result += test_interleaved();
    }

    sink = result;
    return 0;
}
