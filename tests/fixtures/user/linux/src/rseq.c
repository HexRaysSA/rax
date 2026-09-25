/* Restartable sequences (kernel/rseq.c, include/linux/rseq_entry.h):
 * registration's checks (the flags, the size and alignment, a second
 * registration, the signature), the fields it writes and the IDs the
 * return to user space fills in, unregistering, and what aborts a
 * critical section: a signal delivered while it runs and a preemption
 * by another thread on the same CPU, each resuming at the abort handler;
 * an interrupted IP outside the section only clears rseq_cs; a wrong
 * signature kills the task with SIGSEGV. A new thread has no
 * registration, a forked child keeps it. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#ifndef SYS_rseq
#define SYS_rseq 293
#endif
#define SIG 0x53053053u
#define UNREGISTER 1

struct rseq_area {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t node_id;
    uint32_t mm_cid;
    char pad[4];
} __attribute__((aligned(32)));

static __thread struct rseq_area area;
static struct rseq_area spare __attribute__((aligned(32)));

static long rseq(void *a, uint32_t len, int flags, uint32_t sig) {
    return syscall(SYS_rseq, a, len, flags, sig);
}

/* A critical section that spins until *flag is set: 0 when it ran to
 * its end, 1 when it resumed at its abort handler. `sig` is the word
 * before the handler. */
#if defined(__x86_64__)
#define CS(name, SIGWORD)                                                             \
    static int name(struct rseq_area *rs, volatile int *flag, volatile int *ready) { \
        int aborted;                                                                  \
        __asm__ volatile(".pushsection .data, \"aw\"\n\t"                             \
                         ".balign 32\n\t"                                             \
                         "3: .long 0, 0\n\t"                                          \
                         ".quad 1f, 2f - 1f, 4f\n\t"                                  \
                         ".popsection\n\t"                                            \
                         "leaq 3b(%%rip), %%rax\n\t"                                  \
                         "movq %%rax, 8(%[rs])\n\t"                                   \
                         "movl $1, (%[ready])\n\t"                                    \
                         "1: cmpl $0, (%[flag])\n\t"                                  \
                         "je 1b\n\t"                                                  \
                         "2: movl $0, %[ab]\n\t"                                      \
                         "jmp 5f\n\t"                                                 \
                         ".long " #SIGWORD "\n\t"                                     \
                         "4: movl $1, %[ab]\n\t"                                      \
                         "5:\n\t"                                                     \
                         : [ab] "=&r"(aborted)                                        \
                         : [rs] "r"(rs), [flag] "r"(flag), [ready] "r"(ready)         \
                         : "rax", "memory", "cc");                                    \
        return aborted;                                                               \
    }
#elif defined(__aarch64__)
#define CS(name, SIGWORD)                                                             \
    static int name(struct rseq_area *rs, volatile int *flag, volatile int *ready) { \
        int aborted;                                                                  \
        __asm__ volatile(".pushsection .data, \"aw\"\n\t"                             \
                         ".balign 32\n\t"                                             \
                         "3: .long 0, 0\n\t"                                          \
                         ".quad 1f, 2f - 1f, 4f\n\t"                                  \
                         ".popsection\n\t"                                            \
                         "adrp x9, 3b\n\t"                                            \
                         "add x9, x9, :lo12:3b\n\t"                                   \
                         "str x9, [%[rs], #8]\n\t"                                    \
                         "mov w10, #1\n\t"                                            \
                         "str w10, [%[ready]]\n\t"                                    \
                         "1: ldr w10, [%[flag]]\n\t"                                  \
                         "cbz w10, 1b\n\t"                                            \
                         "2: mov %w[ab], #0\n\t"                                      \
                         "b 5f\n\t"                                                   \
                         ".long " #SIGWORD "\n\t"                                     \
                         "4: mov %w[ab], #1\n\t"                                      \
                         "5:\n\t"                                                     \
                         : [ab] "=&r"(aborted)                                        \
                         : [rs] "r"(rs), [flag] "r"(flag), [ready] "r"(ready)         \
                         : "x9", "x10", "memory", "cc");                              \
        return aborted;                                                               \
    }
#elif defined(__riscv)
#define CS(name, SIGWORD)                                                             \
    static int name(struct rseq_area *rs, volatile int *flag, volatile int *ready) { \
        int aborted;                                                                  \
        __asm__ volatile(".pushsection .data, \"aw\"\n\t"                             \
                         ".balign 32\n\t"                                             \
                         "3: .long 0, 0\n\t"                                          \
                         ".quad 1f, 2f - 1f, 4f\n\t"                                  \
                         ".popsection\n\t"                                            \
                         "la t0, 3b\n\t"                                              \
                         "sd t0, 8(%[rs])\n\t"                                        \
                         "li t1, 1\n\t"                                               \
                         "sw t1, 0(%[ready])\n\t"                                     \
                         "1: lw t1, 0(%[flag])\n\t"                                   \
                         "beqz t1, 1b\n\t"                                            \
                         "2: li %[ab], 0\n\t"                                         \
                         "j 5f\n\t"                                                   \
                         ".balign 4\n\t"                                              \
                         ".long " #SIGWORD "\n\t"                                     \
                         "4: li %[ab], 1\n\t"                                         \
                         "5:\n\t"                                                     \
                         : [ab] "=&r"(aborted)                                        \
                         : [rs] "r"(rs), [flag] "r"(flag), [ready] "r"(ready)         \
                         : "t0", "t1", "memory");                                     \
        return aborted;                                                               \
    }
#endif

CS(cs_good, 0x53053053)
CS(cs_bad_sig, 0x12345678)

static volatile int flag, ready;

static void on_alarm(int s) {
    (void)s;
    flag = 1;
}

static void registration(void) {
    CHECK_ERR("flags", rseq(&area, 32, 0x100, SIG), EINVAL);
    CHECK_ERR("too-small", rseq(&area, 31, 0, SIG), EINVAL);
    CHECK_ERR("misaligned", rseq((char *)&spare + 8, 32, 0, SIG), EINVAL);
    CHECK_ERR("large-misaligned", rseq((char *)&spare + 8, 64, 0, SIG), EINVAL);
    CHECK_ERR("outside", rseq((void *)0xffff800000000000UL, 32, 0, SIG), EFAULT);
    CHECK_ERR("unmapped", rseq((void *)32, 32, 0, SIG), EFAULT);
    CHECK_ERR("unregister-none", rseq(&area, 32, UNREGISTER, SIG), EINVAL);
    memset(&area, 0x77, sizeof area);
    CHECK("register", rseq(&area, 32, 0, SIG) == 0);
    /* The return to user space filled in the IDs. */
    unsigned cpu = 99, node = 99;
    syscall(SYS_getcpu, &cpu, &node, NULL);
    CHECK("ids", area.cpu_id_start == cpu && area.cpu_id == cpu && area.node_id == node &&
                     area.mm_cid == 0 && area.rseq_cs == 0);
    CHECK_ERR("again", rseq(&area, 32, 0, SIG), EBUSY);
    CHECK_ERR("again-other-sig", rseq(&area, 32, 0, SIG + 1), EPERM);
    CHECK_ERR("again-other-area", rseq(&spare, 32, 0, SIG), EINVAL);
    CHECK_ERR("again-other-len", rseq(&area, 64, 0, SIG), EINVAL);
    CHECK_ERR("unregister-flags", rseq(&area, 32, UNREGISTER | 0x100, SIG), EINVAL);
    CHECK_ERR("unregister-other", rseq(&spare, 32, UNREGISTER, SIG), EINVAL);
    CHECK_ERR("unregister-len", rseq(&area, 64, UNREGISTER, SIG), EINVAL);
    CHECK_ERR("unregister-sig", rseq(&area, 32, UNREGISTER, SIG + 1), EPERM);
    CHECK("unregister", rseq(&area, 32, UNREGISTER, SIG) == 0);
    /* cpu_id reads "uninitialized" again (Linux 7.0 also resets
     * cpu_id_start, to 0 rather than 6.19's -1: not compared). */
    CHECK("unregistered-id", area.cpu_id == (uint32_t)-1);
    CHECK("register-again", rseq(&area, 32, 0, SIG) == 0);
}

static void *thread_check(void *arg) {
    (void)arg;
    /* A new thread has no registration of its own. */
    long r = rseq(&area, 32, UNREGISTER, SIG);
    return (void *)(r == -1 && errno == EINVAL ? (void *)1 : (void *)0);
}

static void *preempter(void *arg) {
    (void)arg;
    while (!ready) {}
    flag = 1;
    return NULL;
}

static void aborts(void) {
    /* A signal delivered inside the section: the handler returns to
     * the abort handler. */
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    flag = 0;
    struct itimerval it = {.it_value = {0, 20000}};
    setitimer(ITIMER_REAL, &it, NULL);
    CHECK("signal-aborts", cs_good(&area, &flag, &ready) == 1);
    CHECK("signal-cleared", area.rseq_cs == 0);
    /* A preemption by another thread on the same CPU. */
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    CHECK("pin", sched_setaffinity(0, sizeof one, &one) == 0);
    int aborted = 0;
    for (int i = 0; i < 20 && !aborted; i++) {
        flag = 0;
        ready = 0;
        pthread_t t;
        pthread_create(&t, NULL, preempter, NULL);
        aborted = cs_good(&area, &flag, &ready);
        pthread_join(t, NULL);
    }
    CHECK("preemption-aborts", aborted == 1 && area.rseq_cs == 0);
    /* Outside the section, rseq_cs is only cleared. */
    flag = 1;
    CHECK("completes", cs_good(&area, &flag, &ready) == 0 && area.rseq_cs != 0);
    it.it_value.tv_usec = 10000;
    flag = 0;
    setitimer(ITIMER_REAL, &it, NULL);
    while (!flag) {}
    CHECK("outside-cleared", area.rseq_cs == 0);
    void *r;
    pthread_t t;
    pthread_create(&t, NULL, thread_check, NULL);
    pthread_join(t, &r);
    CHECK("new-thread-unregistered", r == (void *)1);
}

static void children(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) _exit(rseq(&area, 32, 0, SIG) == -1 && errno == EBUSY ? 0 : 1);
    int st = 0;
    waitpid(c, &st, 0);
    CHECK("fork-keeps", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* A wrong signature before the abort handler kills the task. */
    fflush(stdout);
    c = fork();
    if (c == 0) {
        flag = 0;
        struct itimerval it = {.it_value = {0, 20000}};
        setitimer(ITIMER_REAL, &it, NULL);
        cs_bad_sig(&area, &flag, &ready);
        _exit(0);
    }
    waitpid(c, &st, 0);
    CHECK("bad-signature-kills", WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
}

int main(void) {
    registration();
    aborts();
    children();
    FINISH();
}
