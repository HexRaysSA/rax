/* PT_STEP retires one instruction after the stopping system call. */
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}
int main(void) {
    setbuf(stdout, NULL);
    volatile int *marker = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANON, -1, 0);
    if (marker == MAP_FAILED) return 1;
    *marker = 0;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        pid_t pid = getpid();
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(90);
#if defined(__aarch64__)
        register long x0 __asm__("x0") = pid;
        register long x1 __asm__("x1") = SIGSTOP;
        register long x2 __asm__("x2") = 0;
        register long x16 __asm__("x16") = 37;
        __asm__ volatile("svc #0x80\n\tnop\n\tmov w9, #1\n\tstr w9, [%[p]]"
                         : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16), [p] "r"(marker)
                         : "x9", "cc", "memory");
#elif defined(__x86_64__)
        register long rax __asm__("rax") = 0x2000025;
        register long rdi __asm__("rdi") = pid;
        register long rsi __asm__("rsi") = SIGSTOP;
        register long rdx __asm__("rdx") = 0;
        __asm__ volatile("syscall\n\tnop\n\tmovl $1, (%[p])"
                         : "+a"(rax) : "D"(rdi), "S"(rsi), "d"(rdx), [p] "r"(marker)
                         : "rcx", "r11", "cc", "memory");
#else
#error unsupported architecture
#endif
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    if (got != child || !WIFSTOPPED(status)) goto fail;
    printf("initial=%d marker=%d\n", WSTOPSIG(status), *marker);
#if defined(__aarch64__)
    const int steps = 3;
#else
    const int steps = 2;
#endif
    for (int i = 0; i < steps; ++i) {
        if (ptrace(PT_STEP, child, (caddr_t)1, 0) != 0) goto fail;
        got = waitpid(child, &status, 0);
        if (got != child || !WIFSTOPPED(status)) goto fail;
        printf("step=%d signal=%d marker=%d\n", i + 1, WSTOPSIG(status), *marker);
    }
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) goto fail;
    got = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", got == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return got != child || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    tracee = 0;
    return 1;
}
