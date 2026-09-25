/* splice and vmsplice (fs/splice.c): the checks in order (a zero length
 * before anything, the flags, the descriptors, a pipe's offsets, the
 * offsets read, the access modes, two files, a pipe to itself, O_APPEND,
 * positions where a file has none, rw_verify_area, files that cannot be
 * spliced); transfers from a file to a pipe and back, at an offset or the
 * file's position, from a pipe to a pipe, sockets, and devices, each
 * moving what there is without waiting for more; the end of a pipe's data,
 * SPLICE_F_NONBLOCK and O_NONBLOCK, a transfer sleeping until a child
 * writes or a signal comes, and EPIPE with SIGPIPE; vmsplice into a pipe
 * and out of one, with faults. Byte counts stay below any pipe's capacity
 * (the kernel's pipe buffers and the host's differ). tee is not here: a
 * pipe cannot be copied without consuming it on every host. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define BAD ((void *)16)

static long sp(int in, int64_t *oin, int out, int64_t *oout, size_t len, unsigned flags) {
    return syscall(SYS_splice, in, oin, out, oout, len, flags);
}

static long vms(int fd, const struct iovec *v, unsigned long n, unsigned flags) {
    return syscall(SYS_vmsplice, fd, v, n, flags);
}

static volatile int pipes_signalled;
static void on_pipe(int s) { (void)s; pipes_signalled++; }
static void on_alarm(int s) { (void)s; }

/* What a pipe holds, read without sleeping. */
static int drain(int fd, char *buf, int max) {
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int n = (int)read(fd, buf, max);
    fcntl(fd, F_SETFL, fl);
    if (n < 0) n = 0;
    buf[n] = 0;
    return n;
}

static int temp_file(const char *contents) {
    char path[] = "/tmp/rax-splice-XXXXXX";
    int fd = mkstemp(path);
    unlink(path);
    if (contents) write(fd, contents, strlen(contents));
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static void checks(void) {
    int p[2], f = temp_file("0123456789"), g = temp_file(NULL);
    pipe(p);
    int64_t off = 0;
    CHECK("zero-length", sp(-1, NULL, -1, NULL, 0, 0x100) == 0);
    CHECK_ERR("flags", sp(p[0], NULL, f, NULL, 1, 0x10), EINVAL);
    CHECK_ERR("bad-in", sp(-1, NULL, p[1], NULL, 1, 0), EBADF);
    CHECK_ERR("bad-out", sp(f, NULL, -1, NULL, 1, 0), EBADF);
    int path = open("/", O_PATH);
    CHECK_ERR("path-fd", sp(path, NULL, p[1], NULL, 1, 0), EBADF);
    close(path);
    CHECK_ERR("pipe-off-in", sp(p[0], &off, f, NULL, 1, 0), ESPIPE);
    CHECK_ERR("pipe-off-out", sp(f, NULL, p[1], &off, 1, 0), ESPIPE);
    CHECK_ERR("pipe-off-before-fault", sp(p[0], BAD, f, NULL, 1, 0), ESPIPE);
    /* *off_out is read before *off_in, both before the modes and the
     * kinds of file. */
    CHECK_ERR("off-out-fault", sp(f, &off, g, BAD, 1, 0), EFAULT);
    CHECK_ERR("off-in-fault", sp(f, BAD, g, &off, 1, 0), EFAULT);
    CHECK_ERR("off-fault-before-mode", sp(p[1], NULL, g, BAD, 1, 0), EFAULT);
    CHECK_ERR("mode-in", sp(p[1], NULL, f, NULL, 1, 0), EBADF);
    CHECK_ERR("mode-out", sp(f, NULL, p[0], NULL, 1, 0), EBADF);
    CHECK_ERR("two-files", sp(f, NULL, g, NULL, 1, 0), EINVAL);
    CHECK_ERR("pipe-to-itself", sp(p[0], NULL, p[1], NULL, 1, 0), EINVAL);
    char path2[] = "/tmp/rax-splice-app-XXXXXX";
    int app = mkstemp(path2);
    close(app);
    app = open(path2, O_WRONLY | O_APPEND);
    unlink(path2);
    write(p[1], "x", 1);
    CHECK_ERR("append", sp(p[0], NULL, app, NULL, 1, 0), EINVAL);
    close(app);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK_ERR("socket-off-out", sp(p[0], NULL, sv[0], &off, 1, 0), EINVAL);
    CHECK_ERR("socket-off-in", sp(sv[0], &off, p[1], NULL, 1, 0), EINVAL);
    off = -1;
    CHECK_ERR("negative-offset", sp(f, &off, p[1], NULL, 1, 0), EINVAL);
    off = INT64_MAX - 1;
    CHECK_ERR("offset-overflow", sp(p[0], NULL, g, &off, 2, 0), EINVAL);
    CHECK_ERR("length-negative", sp(f, NULL, p[1], NULL, (size_t)-1, 0), EINVAL);
    int efd = eventfd(0, 0);
    CHECK_ERR("no-splice-read", sp(efd, NULL, p[1], NULL, 1, 0), EINVAL);
    CHECK_ERR("no-splice-write", sp(p[0], NULL, efd, NULL, 1, 0), EINVAL);
    close(efd);
    int dir = open("/", O_RDONLY);
    CHECK_ERR("directory", sp(dir, NULL, p[1], NULL, 1, 0), EINVAL);
    close(dir);
    int null = open("/dev/null", O_RDWR);
    CHECK_ERR("dev-null-in", sp(null, NULL, p[1], NULL, 1, 0), EINVAL);
    char c;
    CHECK("dev-null-out", sp(p[0], NULL, null, NULL, 10, 0) == 1 && drain(p[0], &c, 1) == 0);
    close(null);
    close(sv[0]);
    close(sv[1]);
    close(f);
    close(g);
    close(p[0]);
    close(p[1]);
}

static void transfers(void) {
    char buf[64];
    int p[2], q[2], f = temp_file("0123456789");
    pipe(p);
    pipe(q);
    /* A file to a pipe: at an offset (which moves; the position stays),
     * then at the file's position (which moves). */
    int64_t off = 2;
    CHECK("file-to-pipe-offset", sp(f, &off, p[1], NULL, 100, 0) == 8 && off == 10 &&
                                     lseek(f, 0, SEEK_CUR) == 0 && drain(p[0], buf, 63) == 8 &&
                                     strcmp(buf, "23456789") == 0);
    CHECK("file-to-pipe-position", sp(f, NULL, p[1], NULL, 4, 0) == 4 && lseek(f, 0, SEEK_CUR) == 4 &&
                                       drain(p[0], buf, 63) == 4 && strcmp(buf, "0123") == 0);
    off = 10;
    CHECK("file-to-pipe-end", sp(f, &off, p[1], NULL, 4, 0) == 0 && off == 10);
    /* A pipe to a file: what the pipe holds, without waiting for more. */
    write(p[1], "abc", 3);
    off = 5;
    CHECK("pipe-to-file-offset", sp(p[0], NULL, f, &off, 100, 0) == 3 && off == 8 &&
                                     pread(f, buf, 10, 0) == 10 && memcmp(buf, "01234abc89", 10) == 0 &&
                                     lseek(f, 0, SEEK_CUR) == 4);
    write(p[1], "XYZW", 4);
    CHECK("pipe-to-file-position", sp(p[0], NULL, f, NULL, 2, 0) == 2 && lseek(f, 0, SEEK_CUR) == 6 &&
                                       pread(f, buf, 10, 0) == 10 && memcmp(buf, "0123XYbc89", 10) == 0 &&
                                       drain(p[0], buf, 63) == 2 && strcmp(buf, "ZW") == 0);
    /* A pipe to a pipe. */
    write(p[1], "hello", 5);
    CHECK("pipe-to-pipe", sp(p[0], NULL, q[1], NULL, 3, 0) == 3 && drain(q[0], buf, 63) == 3 &&
                              strcmp(buf, "hel") == 0 && drain(p[0], buf, 63) == 2 && strcmp(buf, "lo") == 0);
    write(p[1], "more", 4);
    CHECK("pipe-to-pipe-all", sp(p[0], NULL, q[1], NULL, 100, 0) == 4 && drain(q[0], buf, 63) == 4 &&
                                  strcmp(buf, "more") == 0);
    /* Empty: SPLICE_F_NONBLOCK, O_NONBLOCK on either end, the end. */
    CHECK_ERR("empty-nonblock", sp(p[0], NULL, q[1], NULL, 1, SPLICE_F_NONBLOCK), EAGAIN);
    fcntl(q[1], F_SETFL, O_NONBLOCK);
    CHECK_ERR("empty-o-nonblock", sp(p[0], NULL, q[1], NULL, 1, 0), EAGAIN);
    fcntl(q[1], F_SETFL, 0);
    CHECK_ERR("empty-to-file-nonblock", sp(p[0], NULL, f, NULL, 1, SPLICE_F_NONBLOCK), EAGAIN);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    CHECK_ERR("empty-to-file-o-nonblock", sp(p[0], NULL, f, NULL, 1, 0), EAGAIN);
    fcntl(p[0], F_SETFL, 0);
    /* A full pipe: SPLICE_F_NONBLOCK. */
    fcntl(q[1], F_SETFL, O_NONBLOCK);
    static char block[4096];
    while (write(q[1], block, sizeof block) > 0) {}
    while (write(q[1], block, 1) > 0) {}
    fcntl(q[1], F_SETFL, 0);
    off = 0;
    CHECK_ERR("full-nonblock", sp(f, &off, q[1], NULL, 1, SPLICE_F_NONBLOCK), EAGAIN);
    close(q[0]);
    close(q[1]);
    pipe(q);
    /* Sleeping until a child writes. */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        usleep(20000);
        write(p[1], "late", 4);
        _exit(0);
    }
    CHECK("sleeps-for-data", sp(p[0], NULL, q[1], NULL, 100, 0) == 4 && drain(q[0], buf, 63) == 4 &&
                                 strcmp(buf, "late") == 0);
    waitpid(pid, NULL, 0);
    /* A signal ends the sleep (no SA_RESTART): EINTR. */
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = {.it_interval = {0, 20000}, .it_value = {0, 20000}};
    setitimer(ITIMER_REAL, &it, NULL);
    long r = sp(p[0], NULL, f, NULL, 1, 0);
    int err = errno;
    struct itimerval stop = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &stop, NULL);
    CHECK("interrupted", r == -1 && err == EINTR);
    /* The end of the input: 0. */
    close(p[1]);
    CHECK("pipe-end", sp(p[0], NULL, q[1], NULL, 1, 0) == 0);
    CHECK("pipe-end-to-file", sp(p[0], NULL, f, NULL, 1, SPLICE_F_NONBLOCK) == 0);
    close(p[0]);
    /* No readers: EPIPE and SIGPIPE, from a pipe or a file. */
    struct sigaction sp_act = {.sa_handler = on_pipe};
    sigaction(SIGPIPE, &sp_act, NULL);
    pipe(p);
    write(p[1], "x", 1);
    close(q[0]);
    CHECK_ERR("epipe-pipe", sp(p[0], NULL, q[1], NULL, 1, 0), EPIPE);
    CHECK("epipe-pipe-signal", pipes_signalled == 1 && drain(p[0], buf, 63) == 1);
    off = 0;
    CHECK_ERR("epipe-file", sp(f, &off, q[1], NULL, 1, 0), EPIPE);
    CHECK("epipe-file-signal", pipes_signalled == 2 && off == 0);
    close(q[1]);
    /* Sockets both ways, and the memory devices. */
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write(p[1], "xyz", 3);
    CHECK("pipe-to-socket", sp(p[0], NULL, sv[0], NULL, 100, 0) == 3 && read(sv[1], buf, 63) == 3 &&
                                memcmp(buf, "xyz", 3) == 0);
    write(sv[1], "sock", 4);
    CHECK("socket-to-pipe", sp(sv[0], NULL, p[1], NULL, 100, 0) == 4 && drain(p[0], buf, 63) == 4 &&
                                strcmp(buf, "sock") == 0);
    CHECK_ERR("socket-empty-nonblock", sp(sv[0], NULL, p[1], NULL, 1, SPLICE_F_NONBLOCK), EAGAIN);
    int zero = open("/dev/zero", O_RDONLY);
    memset(buf, 1, 8);
    CHECK("zero-to-pipe", sp(zero, NULL, p[1], NULL, 5, 0) == 5 && drain(p[0], buf, 63) == 5 &&
                              memcmp(buf, "\0\0\0\0\0", 5) == 0);
    close(zero);
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
    close(f);
}

static void vmsplices(void) {
    char buf[64], a[3] = "ab", b[4] = "cde";
    int p[2];
    pipe(p);
    struct iovec v[2] = {{a, 2}, {b, 3}};
    CHECK_ERR("vm-flags", vms(p[1], v, 2, 0x10), EINVAL);
    CHECK_ERR("vm-bad-fd", vms(-1, v, 2, 0), EBADF);
    int f = temp_file("file");
    CHECK("vm-nothing-on-a-file", vms(f, v, 0, 0) == 0);
    CHECK_ERR("vm-not-a-pipe", vms(f, v, 2, 0), EBADF);
    CHECK_ERR("vm-vector-fault", vms(p[1], BAD, 2, 0), EFAULT);
    CHECK("vm-to-pipe", vms(p[1], v, 2, 0) == 5 && drain(p[0], buf, 63) == 5 && strcmp(buf, "abcde") == 0);
    struct iovec bad[2] = {{BAD, 4}, {a, 2}};
    CHECK_ERR("vm-memory-fault", vms(p[1], bad, 2, 0), EFAULT);
    struct iovec part[2] = {{a, 2}, {BAD, 4}};
    CHECK("vm-memory-fault-after", vms(p[1], part, 2, 0) == 2 && drain(p[0], buf, 63) == 2);
    /* Out of the pipe: what it holds, to the first byte that cannot be
     * written. */
    write(p[1], "hello", 5);
    char x[3] = {0}, y[10] = {0};
    struct iovec out[2] = {{x, 2}, {y, 10}};
    CHECK("vm-to-user", vms(p[0], out, 2, 0) == 5 && memcmp(x, "he", 2) == 0 && memcmp(y, "llo", 3) == 0);
    write(p[1], "kept", 4);
    struct iovec unwritable[1] = {{BAD, 4}};
    CHECK_ERR("vm-to-user-fault", vms(p[0], unwritable, 1, 0), EFAULT);
    CHECK("vm-to-user-fault-kept", drain(p[0], buf, 63) == 4 && strcmp(buf, "kept") == 0);
    CHECK_ERR("vm-to-user-nonblock", vms(p[0], out, 2, SPLICE_F_NONBLOCK), EAGAIN);
    /* O_NONBLOCK is not SPLICE_F_NONBLOCK: a writer's close ends it. */
    close(p[1]);
    CHECK("vm-to-user-end", vms(p[0], out, 2, 0) == 0);
    close(p[0]);
    /* No readers: EPIPE and SIGPIPE. */
    pipe(p);
    close(p[0]);
    int before = pipes_signalled;
    CHECK_ERR("vm-epipe", vms(p[1], v, 2, 0), EPIPE);
    CHECK("vm-epipe-signal", pipes_signalled == before + 1);
    close(p[1]);
    close(f);
}

int main(void) {
    struct sigaction sa = {.sa_handler = on_pipe};
    sigaction(SIGPIPE, &sa, NULL);
    checks();
    transfers();
    vmsplices();
    FINISH();
}
