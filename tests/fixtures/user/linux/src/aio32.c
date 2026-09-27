/* Asynchronous I/O of an i386 task (i386 only): compat_sys_io_setup's
 * 32-bit context, compat_sys_io_submit's array of 32-bit iocb pointers
 * and int count, io_getevents_time32's __s32 counts and struct
 * old_timespec32, and compat_sys_io_pgetevents' struct
 * __compat_aio_sigset and compat_long_t counts. Structures that must be
 * read at their 32-bit size sit at the end of a page whose successor is
 * not mapped. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "aio32 is an i386 program"
#endif

#define NR_IO_SETUP 245
#define NR_IO_DESTROY 246
#define NR_IO_GETEVENTS 247
#define NR_IO_SUBMIT 248
#define NR_IO_PGETEVENTS 385
#define NR_IO_PGETEVENTS_TIME64 416

struct iocb32 {
    uint64_t data;
    uint32_t key, rw_flags;
    uint16_t opcode;
    int16_t reqprio;
    uint32_t fildes;
    uint64_t buf, nbytes;
    int64_t offset;
    uint64_t reserved2;
    uint32_t flags, resfd;
};

struct event {
    uint64_t data, obj;
    int64_t res, res2;
};

static struct iocb32 pread_of(int fd, void *buf, uint64_t n, int64_t off, uint64_t data) {
    struct iocb32 cb;
    memset(&cb, 0, sizeof cb);
    cb.data = data;
    cb.opcode = 0; /* IOCB_CMD_PREAD */
    cb.fildes = fd;
    cb.buf = (uintptr_t)buf;
    cb.nbytes = n;
    cb.offset = off;
    return cb;
}

int main(void) {
    char *page = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(page + 4096, 4096);
    char *end = page + 4096;

    /* The context: 32 bits read (the word above it is not looked at) and
     * written. */
    uint32_t ctxw[2] = {0, 1};
    CHECK("setup", syscall(NR_IO_SETUP, 4, ctxw) == 0 && ctxw[0] != 0 && ctxw[1] == 1);
    uint32_t ctx = ctxw[0];
    uint32_t *last = (uint32_t *)(end - 4);
    *last = 0;
    CHECK("setup-at-page-end", syscall(NR_IO_SETUP, 1, last) == 0 && *last != 0 &&
                                   syscall(NR_IO_DESTROY, *last) == 0);

    /* Two reads through an array of 32-bit iocb pointers. */
    int fd = memfd_create("a", 0);
    CHECK("file", fd >= 0 && write(fd, "hello", 5) == 5);
    char buf[16] = {0};
    struct iocb32 cb[2] = {pread_of(fd, buf, 5, 0, 7), pread_of(fd, buf + 8, 2, 3, 8)};
    uint32_t list[2] = {(uintptr_t)&cb[0], (uintptr_t)&cb[1]};
    CHECK_ERR("submit-negative", syscall(NR_IO_SUBMIT, ctx, -1, list), EINVAL);
    CHECK("submit", syscall(NR_IO_SUBMIT, ctx, 2, list) == 2);

    /* io_getevents_time32: __s32 counts, an 8-byte timeout. */
    struct event ev[4];
    CHECK_ERR("getevents-negative", syscall(NR_IO_GETEVENTS, ctx, 0, -1, ev, 0), EINVAL);
    int32_t *ts = (int32_t *)(end - 8);
    ts[0] = ts[1] = 0;
    CHECK("getevents", syscall(NR_IO_GETEVENTS, ctx, 2, 2, ev, ts) == 2 && ev[0].data == 7 &&
                           ev[0].obj == (uintptr_t)&cb[0] && ev[0].res == 5 && ev[1].data == 8 &&
                           ev[1].res == 2 && !memcmp(buf, "hello", 5) &&
                           !memcmp(buf + 8, "lo", 2));

    /* io_pgetevents: struct __compat_aio_sigset of 8 bytes, compat_long_t
     * counts. */
    uint64_t mask = 0;
    uint32_t *sig = (uint32_t *)(end - 8);
    sig[0] = (uintptr_t)&mask;
    sig[1] = 8;
    CHECK("pgetevents", syscall(NR_IO_PGETEVENTS, ctx, 0, 1, ev, 0, sig) == 0);
    CHECK("pgetevents-time64", syscall(NR_IO_PGETEVENTS_TIME64, ctx, 0, 1, ev, 0, sig) == 0);
    CHECK_ERR("pgetevents-negative", syscall(NR_IO_PGETEVENTS, ctx, 0, -1, ev, 0, sig), EINVAL);
    sig[1] = 16;
    CHECK_ERR("pgetevents-mask-size", syscall(NR_IO_PGETEVENTS, ctx, 0, 1, ev, 0, sig), EINVAL);
    CHECK("destroy", syscall(NR_IO_DESTROY, ctx) == 0);
    FINISH();
}
