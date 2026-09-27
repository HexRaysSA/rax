/* select, pselect6, and ppoll of an i386 task (i386 only): fd sets of
 * 32-bit words (compat_get_bitmap, compat_put_bitmap), struct
 * old_timeval32 in and out, the old select's struct compat_sel_arg_struct,
 * pselect6's struct compat_sigset_argpack, and the *_time32 timeouts
 * beside the *_time64 ones. Structures that must be read at their 32-bit
 * size sit at the end of a page whose successor is not mapped. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "select32 is an i386 program"
#endif

#define NR_OLD_SELECT 82
#define NR_NEWSELECT 142
#define NR_PSELECT6 308
#define NR_PPOLL 309
#define NR_PSELECT6_TIME64 413
#define NR_PPOLL_TIME64 414

int main(void) {
    char *page = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(page + 4096, 4096);
    char *end = page + 4096;
    int p[2];
    CHECK("pipe", pipe(p) == 0 && p[1] < 10 && write(p[1], "x", 1) == 1);

    /* One 32-bit word of each set, read at a page's end and written back
     * alone. */
    uint32_t *in = (uint32_t *)(end - 4);
    *in = 1u << p[0];
    CHECK("newselect-word", syscall(NR_NEWSELECT, 10, in, 0, 0, 0) == 1 && *in == 1u << p[0]);
    uint32_t set[2] = {1u << p[0] | 1u << 20, 0xEEEEEEEE};
    CHECK("newselect-writes-one-word",
          syscall(NR_NEWSELECT, 10, set, 0, 0, 0) == 1 && set[0] == 1u << p[0] &&
              set[1] == 0xEEEEEEEE);
    *in = 1u << p[0];
    CHECK_ERR("newselect-two-words-fault", syscall(NR_NEWSELECT, 33, in, 0, 0, 0), EFAULT);

    /* struct old_timeval32: read and written back at 8 bytes. */
    int32_t *tv = (int32_t *)(end - 8);
    tv[0] = 0;
    tv[1] = 10000;
    uint32_t none = 0;
    CHECK("newselect-timeout", syscall(NR_NEWSELECT, 10, &none, 0, 0, tv) == 0 && tv[0] == 0 &&
                                   tv[1] == 0);
    tv[0] = 0;
    tv[1] = -1;
    CHECK_ERR("newselect-bad-timeval", syscall(NR_NEWSELECT, 10, &none, 0, 0, tv), EINVAL);

    /* The old select: struct compat_sel_arg_struct of five words. */
    uint32_t *args = (uint32_t *)(end - 20);
    *in = 0;
    uint32_t ready = 1u << p[0];
    args[0] = 10;
    args[1] = (uintptr_t)&ready;
    args[2] = args[3] = args[4] = 0;
    CHECK("old-select", syscall(NR_OLD_SELECT, args) == 1 && ready == 1u << p[0]);

    /* pselect6_time32: struct old_timespec32 and struct
     * compat_sigset_argpack. */
    int32_t *ts = (int32_t *)(end - 8);
    ts[0] = 0;
    ts[1] = 10000000;
    uint64_t mask = 0;
    uint32_t pack[2] = {(uintptr_t)&mask, 8};
    none = 0;
    CHECK("pselect6-time32", syscall(NR_PSELECT6, 10, &none, 0, 0, ts, pack) == 0 &&
                                 ts[0] == 0 && ts[1] == 0);
    uint32_t *pack_end = (uint32_t *)(end - 8);
    pack_end[0] = (uintptr_t)&mask;
    pack_end[1] = 8;
    ready = 1u << p[0];
    CHECK("pselect6-argpack-at-page-end",
          syscall(NR_PSELECT6, 10, &ready, 0, 0, 0, pack_end) == 1);
    pack_end[1] = 16;
    CHECK_ERR("pselect6-mask-size", syscall(NR_PSELECT6, 10, &ready, 0, 0, 0, pack_end), EINVAL);
    int32_t ts64[4] = {0, 0, 1000, -1};
    none = 0;
    CHECK("pselect6-time64-padding",
          syscall(NR_PSELECT6_TIME64, 10, &none, 0, 0, ts64, 0) == 0);

    /* ppoll_time32 and ppoll_time64. */
    struct pollfd pfd = {p[0], POLLIN, 0};
    ts[0] = 1;
    ts[1] = 0;
    CHECK("ppoll-time32", syscall(NR_PPOLL, &pfd, 1, ts, 0, 8) == 1 && pfd.revents == POLLIN &&
                              ts[0] >= 0 && ts[0] <= 1 && ts[1] >= 0 && ts[1] < 1000000000);
    ts[0] = 0;
    ts[1] = 1000000000;
    CHECK_ERR("ppoll-time32-invalid", syscall(NR_PPOLL, &pfd, 1, ts, 0, 8), EINVAL);
    int32_t t64[4] = {1, 0, 0, -1};
    CHECK("ppoll-time64-padding", syscall(NR_PPOLL_TIME64, &pfd, 1, t64, 0, 8) == 1 &&
                                      t64[3] == 0);
    FINISH();
}
