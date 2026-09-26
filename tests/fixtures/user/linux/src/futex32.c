/* The 32-bit futex calls of an i386 task (i386 only): the robust list a
 * 32-bit call registers (struct compat_robust_list_head), released when
 * its owner exits and when it executes another program, the list
 * get_robust_list reports, and the timeouts of futex_time32 (struct
 * old_timespec32) and futex_time64 (struct __kernel_timespec, the padding
 * above the nanoseconds ignored for a 32-bit caller). */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "futex32 is an i386 program"
#endif

#define OWNER_DIED 0x40000000u
#define WAITERS 0x80000000u

/* A robust list in shared memory with one held lock and a pending one;
 * the entries sit below their locks (a positive futex_offset) or above
 * them (a negative one, whose 32-bit sum wraps). */
struct robust {
    long head[3];
    long entry[1];
    long pad[5];
    uint32_t lock, pending;
};

static void setup(struct robust *r, uint32_t tid) {
    r->head[0] = (long)r->entry;
    r->head[1] = (long)((char *)&r->lock - (char *)r->entry);
    r->head[2] = (long)((char *)&r->pending - r->head[1]);
    r->entry[0] = (long)r->head;
    r->lock = tid | WAITERS;
    r->pending = tid;
}

/* Forks a child that registers the list and then exits (`exec` 0) or
 * executes this program again (`exec` 1); returns the child's status. */
static int release(struct robust *r, int exec, char *self) {
    pid_t c = fork();
    if (c == 0) {
        setup(r, syscall(SYS_gettid));
        if (syscall(SYS_set_robust_list, r->head, 12)) _exit(8);
        if (exec) {
            execl("/proc/self/exe", self, "exec", (char *)0);
            _exit(9);
        }
        _exit(4);
    }
    int st = 0;
    waitpid(c, &st, 0);
    return WEXITSTATUS(st);
}

static long futex(long nr, volatile uint32_t *word, int op, uint32_t val, const void *ts) {
    return syscall(nr, word, op, val, ts, 0, 0);
}

int main(int argc, char **argv) {
    if (argc > 1) return 5;
    setvbuf(stdout, NULL, _IONBF, 0);
    struct robust *r = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    /* The 32-bit head is 12 bytes, reported as 32-bit words. */
    CHECK_ERR("robust-len", syscall(SYS_set_robust_list, r->head, 24), EINVAL);
    CHECK("robust-set", syscall(SYS_set_robust_list, r->head, 12) == 0);
    uint32_t got[2] = {0xeeeeeeee, 0xeeeeeeee}, len[2] = {0xeeeeeeee, 0xeeeeeeee};
    CHECK("robust-get", syscall(SYS_get_robust_list, 0, got, len) == 0 &&
                            got[0] == (uint32_t)(uintptr_t)r->head && got[1] == 0xeeeeeeee &&
                            len[0] == 12 && len[1] == 0xeeeeeeee);
    syscall(SYS_set_robust_list, 0, 12);

    /* At exit and at execve, the held lock and the pending one go to
     * FUTEX_OWNER_DIED, the waiters bit kept. */
    int st = release(r, 0, argv[0]);
    printf("exit: status %d lock %x pending %x\n", st, r->lock, r->pending);
    CHECK("exit-releases", r->lock == (WAITERS | OWNER_DIED) && r->pending == OWNER_DIED);
    st = release(r, 1, argv[0]);
    printf("exec: status %d lock %x pending %x\n", st, r->lock, r->pending);
    CHECK("exec-releases", r->lock == (WAITERS | OWNER_DIED) && r->pending == OWNER_DIED);

    /* futex_time32 reads struct old_timespec32. */
    volatile uint32_t word = 5;
    int32_t ts32[2] = {0, 1000};
    CHECK_ERR("time32-again", futex(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 6, ts32), EAGAIN);
    CHECK_ERR("time32-timeout", futex(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 5, ts32), ETIMEDOUT);
    ts32[1] = 1000000000;
    CHECK_ERR("time32-invalid", futex(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 5, ts32), EINVAL);
    /* futex_time64 (422): the upper half of tv_nsec is padding. */
    uint32_t ts64[4] = {0, 0, 1000, 0xffffffff};
    CHECK_ERR("time64-padding", futex(422, &word, FUTEX_WAIT_PRIVATE, 5, ts64), ETIMEDOUT);
    ts64[3] = 0;
    ts64[2] = 1000000000;
    CHECK_ERR("time64-invalid", futex(422, &word, FUTEX_WAIT_PRIVATE, 5, ts64), EINVAL);
    FINISH();
}
