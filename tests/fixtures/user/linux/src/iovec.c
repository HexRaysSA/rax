/* Vector import (lib/iov_iter.c: __import_iovec, import_ubuf,
 * iovec_from_user) as the vectored transfers use it: readv, writev,
 * preadv, pwritev, preadv2, pwritev2, sendmsg, and recvmsg. The count is
 * an unsigned int; each of several vectors must lie in user space at its
 * full length, a single one only after its cap at MAX_RW_COUNT; a
 * negative length is EINVAL as its vector is read; and a failed import
 * transfers nothing and leaves the file position alone. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "check.h"

#define KERNEL ((void *)0xffff800000000000UL)
#define BAD ((void *)16)

static long sys_readv(int fd, const struct iovec *v, unsigned long n) {
    return syscall(SYS_readv, fd, v, n);
}

static long sys_writev(int fd, const struct iovec *v, unsigned long n) {
    return syscall(SYS_writev, fd, v, n);
}

static int pending(int fd) {
    int n = -1;
    ioctl(fd, FIONREAD, &n);
    return n;
}

int main(void) {
    char a[16], b[16];
    int p[2];
    CHECK("pipe", pipe(p) == 0);
    /* Several vectors: each checked at its full length before anything
     * moves. */
    struct iovec bad2[2] = {{a, 5}, {KERNEL, 5}};
    CHECK_ERR("writev-second-kernel", sys_writev(p[1], bad2, 2), EFAULT);
    CHECK("writev-nothing-written", pending(p[0]) == 0);
    struct iovec huge2[2] = {{a, 5}, {b, 1UL << 62}};
    CHECK_ERR("writev-second-huge", sys_writev(p[1], huge2, 2), EFAULT);
    CHECK("writev-huge-nothing-written", pending(p[0]) == 0);
    /* A single vector is capped first. */
    char *low = mmap((void *)0x10000000, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK("low-page", low == (void *)0x10000000);
    memcpy(low, "hello", 5);
    CHECK("pipe-fill", write(p[1], "abcdefgh", 8) == 8);
    struct iovec one = {low, 1UL << 62};
    CHECK("readv-single-capped", sys_readv(p[0], &one, 1) == 8 && memcmp(low, "abcdefgh", 8) == 0);
    /* The count is an unsigned int. */
    CHECK("pipe-fill-2", write(p[1], "xyz", 3) == 3);
    struct iovec two[2] = {{a, 2}, {b, 2}};
    CHECK("readv-count-truncated", sys_readv(p[0], two, (1UL << 32) | 1) == 2 &&
                                        memcmp(a, "xy", 2) == 0);
    CHECK("readv-rest", read(p[0], a, 16) == 1 && a[0] == 'z');
    /* Negative lengths, and faults, in vector order. */
    struct iovec neg[2] = {{a, (size_t)-1}, {KERNEL, 1}};
    CHECK_ERR("negative-first", sys_readv(p[0], neg, 2), EINVAL);
    CHECK_ERR("array-fault", sys_readv(p[0], BAD, 2), EFAULT);
    CHECK_ERR("count-too-big", sys_readv(p[0], two, 1025), EINVAL);
    CHECK("count-zero", sys_readv(p[0], two, 0) == 0);
    /* A file's position stays where it was. */
    char path[] = "/tmp/rax-iovec-XXXXXX";
    int fd = mkstemp(path);
    CHECK("file", fd >= 0 && write(fd, "0123456789", 10) == 10 && lseek(fd, 0, SEEK_SET) == 0);
    struct iovec rbad[2] = {{a, 3}, {KERNEL, 3}};
    CHECK_ERR("readv-file-kernel", sys_readv(fd, rbad, 2), EFAULT);
    CHECK("readv-file-position", lseek(fd, 0, SEEK_CUR) == 0);
    CHECK_ERR("preadv-kernel", preadv(fd, rbad, 2, 2), EFAULT);
    CHECK_ERR("preadv2-kernel", preadv2(fd, rbad, 2, 2, 0), EFAULT);
    CHECK_ERR("pwritev-kernel", pwritev(fd, rbad, 2, 2), EFAULT);
    CHECK_ERR("pwritev2-kernel", pwritev2(fd, rbad, 2, 2, 0), EFAULT);
    CHECK("file-unchanged", pread(fd, b, 10, 0) == 10 && memcmp(b, "0123456789", 10) == 0);
    CHECK("preadv-count-truncated",
          syscall(SYS_preadv, fd, two, (1UL << 32) | 1, 4L, 0L) == 2 && memcmp(a, "45", 2) == 0);
    unlink(path);
    close(fd);
    /* Sockets: EMSGSIZE for too many vectors, then the import. */
    int s[2];
    CHECK("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
    struct msghdr m = {0};
    m.msg_iov = bad2;
    m.msg_iovlen = 2;
    CHECK_ERR("sendmsg-kernel", sendmsg(s[0], &m, MSG_DONTWAIT), EFAULT);
    CHECK("sendmsg-nothing-sent", pending(s[1]) == 0);
    m.msg_iovlen = 1025;
    CHECK_ERR("sendmsg-too-many", sendmsg(s[0], &m, MSG_DONTWAIT), EMSGSIZE);
    /* The kernel's struct user_msghdr: msg_iovlen is a size_t (musl's
     * msghdr pads an int and its wrapper clears the padding). */
    struct {
        void *name;
        uint32_t namelen, pad;
        struct iovec *iov;
        uint64_t iovlen;
        void *control;
        uint64_t controllen;
        uint32_t flags, pad2;
    } raw = {0};
    raw.iov = bad2;
    raw.iovlen = (1UL << 32) | 1;
    CHECK_ERR("sendmsg-count-not-truncated", syscall(SYS_sendmsg, s[0], &raw, MSG_DONTWAIT),
              EMSGSIZE);
    CHECK("send", send(s[0], "pq", 2, 0) == 2);
    m.msg_iov = rbad;
    m.msg_iovlen = 2;
    CHECK_ERR("recvmsg-kernel", recvmsg(s[1], &m, MSG_DONTWAIT), EFAULT);
    CHECK("recvmsg-left-queued", pending(s[1]) == 2);
    FINISH();
}
