/* Linux AIO (fs/aio.c): io_setup's checks and the ring it maps (its
 * header, the context ID as its address, /proc/self/maps, never locked),
 * io_submit's checks in order and requests failing where the kernel fails
 * them (the count submitted before a failure, a buffer that faults only in
 * the transfer), reads and writes (positioned, vectored, into a pipe
 * without data both with O_NONBLOCK and with a signal arriving), fsync,
 * the aio_key written back, IOCB_FLAG_RESFD, IOCB_CMD_POLL (at once,
 * waiting, cancelled), io_getevents and io_pgetevents (checks, timeouts, a
 * signal mask), the ring's capacity and reaping from user space, a
 * clobbered ring ID, mremap moving the context, a forked child, and
 * io_destroy. The ring's size depends on the machine's CPUs and is not
 * printed. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#define BAD ((void *)16)
#ifndef RWF_NOAPPEND
#define RWF_NOAPPEND 0x20
#endif
#ifndef RWF_ATOMIC
#define RWF_ATOMIC 0x40
#endif
#ifndef RWF_NOSIGNAL
#define RWF_NOSIGNAL 0x100
#endif

struct iocb {
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

struct io_event {
    uint64_t data, obj;
    int64_t res, res2;
};

struct aio_ring {
    uint32_t id, nr, head, tail, magic, compat, incompat, header_length;
    struct io_event events[];
};

enum { PREAD = 0, PWRITE = 1, FSYNC = 2, FDSYNC = 3, POLL = 5, PREADV = 7, PWRITEV = 8 };
#define RESFD 1

static long setup(unsigned n, uint64_t *ctx) { return syscall(SYS_io_setup, n, ctx); }
static long destroy(uint64_t ctx) { return syscall(SYS_io_destroy, ctx); }
static long submit(uint64_t ctx, long n, struct iocb **v) { return syscall(SYS_io_submit, ctx, n, v); }
static long cancel(uint64_t ctx, struct iocb *c, struct io_event *r) {
    return syscall(SYS_io_cancel, ctx, c, r);
}
static long getevents(uint64_t ctx, long min, long max, struct io_event *e, struct timespec *t) {
    return syscall(SYS_io_getevents, ctx, min, max, e, t);
}

static struct iocb cb(uint16_t op, int fd, void *buf, uint64_t n, int64_t off, uint64_t data) {
    struct iocb c;
    memset(&c, 0, sizeof c);
    c.opcode = op;
    c.fildes = fd;
    c.buf = (uint64_t)(uintptr_t)buf;
    c.nbytes = n;
    c.offset = off;
    c.data = data;
    return c;
}

static long submit1(uint64_t ctx, struct iocb *c) {
    struct iocb *v[1] = {c};
    return submit(ctx, 1, v);
}

/* One event, waiting for it. */
static int one(uint64_t ctx, struct io_event *e) {
    return getevents(ctx, 1, 1, e, NULL) == 1;
}

static int in_maps(const char *what, uint64_t at) {
    static char b[1 << 16];
    int fd = open("/proc/self/maps", O_RDONLY);
    size_t n = 0;
    long k;
    while (fd >= 0 && n < sizeof b - 1 && (k = read(fd, b + n, sizeof b - 1 - n)) > 0) n += k;
    if (fd >= 0) close(fd);
    b[n] = 0;
    char key[32];
    snprintf(key, sizeof key, "%lx-", (unsigned long)at);
    char *l = strstr(b, key);
    if (!l) return 0;
    char *e = strchr(l, '\n');
    if (e) *e = 0;
    return strstr(l, what) != NULL;
}

/* A number from a /proc file (without allocating). */
static long proc_long(const char *path) {
    char b[64];
    int fd = open(path, O_RDONLY);
    long n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    return strtol(b, NULL, 10);
}

/* VmLck from /proc/self/status, in kB (without allocating). */
static long vmlck(void) {
    static char b[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    long n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    char *l = strstr(b, "VmLck:");
    return l ? strtol(l + 6, NULL, 10) : -1;
}

static void on_alarm(int s) { (void)s; }

static volatile int sigpipes;
static void on_pipe(int s) { (void)s; sigpipes++; }

static void setup_checks(void) {
    uint64_t ctx = 1;
    CHECK_ERR("setup-ctx-nonzero", setup(1, &ctx), EINVAL);
    ctx = 0;
    CHECK_ERR("setup-zero", setup(0, &ctx), EINVAL);
    CHECK_ERR("setup-fault", setup(1, BAD), EFAULT);
    CHECK_ERR("setup-overflow", setup(0x10000001, &ctx), EINVAL);
    /* Twice the events must stay below 0x10000000 / 32 for the limit to be
     * what refuses them. */
    long max = proc_long("/proc/sys/fs/aio-max-nr");
    CHECK("aio-max-nr", max > 0 && max < 0x400000);
    CHECK_ERR("setup-over-max", setup(max + 1, &ctx), EAGAIN);
    CHECK_ERR("setup-wraps", setup(0x80000000u, &ctx), EAGAIN);
    CHECK("setup-left-zero", ctx == 0);
}

static void basics(uint64_t ctx) {
    struct aio_ring *r = (struct aio_ring *)(uintptr_t)ctx;
    CHECK("ring-header", r->magic == 0xa10a10a1 && r->compat == 1 && r->incompat == 0 &&
                             r->header_length == 32 && r->head == 0 && r->tail == 0 && r->nr >= 8);
    CHECK("ring-mapped", in_maps("/[aio] (deleted)", ctx));
    char path[] = "/tmp/rax-aio-XXXXXX";
    int fd = mkstemp(path);
    unlink(path);
    struct io_event e;
    char out[16] = "hello, aio!";
    struct iocb w = cb(PWRITE, fd, out, 11, 4, 77);
    w.key = 0x12345678;
    CHECK("pwrite", submit1(ctx, &w) == 1 && w.key == 0);
    CHECK("pwrite-event", one(ctx, &e) && e.data == 77 && e.obj == (uintptr_t)&w && e.res == 11 &&
                              e.res2 == 0);
    char in[32] = {0};
    struct iocb rd = cb(PREAD, fd, in, 20, 4, 78);
    CHECK("pread", submit1(ctx, &rd) == 1 && one(ctx, &e) && e.res == 11 &&
                       memcmp(in, "hello, aio!", 11) == 0);
    CHECK("position-unchanged", lseek(fd, 0, SEEK_CUR) == 0);
    char a[3] = "ab", b[5] = "cdef";
    struct iovec wv[2] = {{a, 2}, {b, 4}};
    struct iocb wvc = cb(PWRITEV, fd, wv, 2, 0, 0);
    CHECK("pwritev", submit1(ctx, &wvc) == 1 && one(ctx, &e) && e.res == 6);
    char x[3] = {0}, y[4] = {0};
    struct iovec rv[2] = {{x, 2}, {y, 3}};
    struct iocb rvc = cb(PREADV, fd, rv, 2, 1, 0);
    CHECK("preadv", submit1(ctx, &rvc) == 1 && one(ctx, &e) && e.res == 5 && memcmp(x, "bc", 2) == 0 &&
                        memcmp(y, "def", 3) == 0);
    struct iocb s = cb(FSYNC, fd, 0, 0, 0, 0), ds = cb(FDSYNC, fd, 0, 0, 0, 0);
    CHECK("fsync", submit1(ctx, &s) == 1 && one(ctx, &e) && e.res == 0);
    CHECK("fdsync", submit1(ctx, &ds) == 1 && one(ctx, &e) && e.res == 0);
    s.nbytes = 1;
    CHECK_ERR("fsync-fields", submit1(ctx, &s), EINVAL);
    int p[2];
    pipe(p);
    struct iocb ps = cb(FSYNC, p[0], 0, 0, 0, 0);
    CHECK_ERR("fsync-pipe", submit1(ctx, &ps), EINVAL);
    /* The checks before a request is queued. */
    struct iocb bad = cb(PREAD, 999, in, 1, 0, 0);
    CHECK_ERR("bad-fd", submit1(ctx, &bad), EBADF);
    bad = cb(PREAD, fd, in, 1, 0, 0);
    bad.reserved2 = 1;
    CHECK_ERR("reserved", submit1(ctx, &bad), EINVAL);
    bad = cb(PREAD, fd, in, (uint64_t)-1, 0, 0);
    CHECK_ERR("negative-length", submit1(ctx, &bad), EINVAL);
    bad = cb(6, fd, in, 1, 0, 0);
    CHECK_ERR("bad-opcode", submit1(ctx, &bad), EINVAL);
    bad = cb(PREAD, fd, in, 1, -1, 0);
    CHECK_ERR("negative-offset", submit1(ctx, &bad), EINVAL);
    bad = cb(PREAD, fd, in, 1, 0, 0);
    bad.rw_flags = 0x200;
    CHECK_ERR("rw-flags", submit1(ctx, &bad), EOPNOTSUPP);
    bad.rw_flags = RWF_APPEND | RWF_NOAPPEND;
    CHECK_ERR("rw-flags-append", submit1(ctx, &bad), EINVAL);
    bad.rw_flags = RWF_ATOMIC;
    CHECK_ERR("rw-flags-atomic-read", submit1(ctx, &bad), EOPNOTSUPP);
    bad = cb(PREAD, p[1], in, 1, 0, 0);
    CHECK_ERR("not-readable", submit1(ctx, &bad), EBADF);
    bad = cb(PREAD, fd, in, 1, 0, 0);
    bad.flags = RESFD;
    bad.resfd = fd;
    CHECK_ERR("resfd-not-eventfd", submit1(ctx, &bad), EINVAL);
    bad.resfd = 999;
    CHECK_ERR("resfd-bad", submit1(ctx, &bad), EBADF);
    int opath = open("/", O_PATH);
    bad.resfd = opath;
    CHECK_ERR("resfd-path", submit1(ctx, &bad), EBADF);
    bad = cb(PREAD, opath, in, 1, 0, 0);
    CHECK_ERR("path-fd", submit1(ctx, &bad), EBADF);
    close(opath);
    int dir = open("/", O_RDONLY | O_DIRECTORY);
    bad = cb(PREAD, dir, in, 1, 0, 0);
    CHECK_ERR("directory", submit1(ctx, &bad), EINVAL);
    close(dir);
    int ep = epoll_create1(0);
    bad = cb(PREAD, ep, in, 1, 0, 0);
    CHECK_ERR("epoll", submit1(ctx, &bad), EINVAL);
    close(ep);
    /* access_ok only: an unmapped buffer faults in the transfer. */
    bad = cb(PREAD, fd, (void *)-4096ul, 1, 0, 0);
    CHECK_ERR("buffer-kernel", submit1(ctx, &bad), EFAULT);
    bad = cb(PREADV, fd, BAD, 1, 0, 0);
    CHECK_ERR("vector-fault", submit1(ctx, &bad), EFAULT);
    bad = cb(PREAD, fd, BAD, 4, 0, 9);
    CHECK("buffer-unmapped", submit1(ctx, &bad) == 1 && one(ctx, &e) && e.res == -EFAULT && e.data == 9);
    struct iocb *pv[1] = {BAD};
    CHECK_ERR("bad-iocb", submit(ctx, 1, pv), EFAULT);
    CHECK_ERR("bad-array", submit(ctx, 1, BAD), EFAULT);
    CHECK_ERR("negative-count", submit(ctx, -1, pv), EINVAL);
    CHECK("zero-count", submit(ctx, 0, pv) == 0);
    CHECK_ERR("bad-context", submit(ctx + 4096, 1, pv), EINVAL);
    /* A failure after the first request: the count before it. */
    struct iocb ok = cb(PWRITE, fd, out, 1, 0, 0), fails = cb(PREAD, 999, in, 1, 0, 0);
    struct iocb *two[2] = {&ok, &fails};
    CHECK("count-before-failure", submit(ctx, 2, two) == 1 && one(ctx, &e));
    /* The eventfd hears of each completion. */
    int efd = eventfd(0, 0);
    struct iocb n1 = cb(PWRITE, fd, out, 1, 0, 0), n2 = cb(PWRITE, fd, out, 1, 1, 0);
    n1.flags = n2.flags = RESFD;
    n1.resfd = n2.resfd = efd;
    struct iocb *nv[2] = {&n1, &n2};
    uint64_t count = 0;
    CHECK("resfd", submit(ctx, 2, nv) == 2 && getevents(ctx, 2, 2, (struct io_event[2]){0}, NULL) == 2 &&
                       read(efd, &count, 8) == 8 && count == 2);
    close(efd);
    /* Pipes: without data, O_NONBLOCK gives -EAGAIN; with a signal the
     * sleep inside io_submit ends in -EINTR. */
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    struct iocb pr = cb(PREAD, p[0], in, 8, 0, 0);
    CHECK("pipe-nonblock", submit1(ctx, &pr) == 1 && one(ctx, &e) && e.res == -EAGAIN);
    fcntl(p[0], F_SETFL, 0);
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    /* Periodic, so a signal that comes before the read sleeps is followed
     * by one that ends the sleep. */
    struct itimerval it = {.it_interval = {0, 20000}, .it_value = {0, 20000}};
    setitimer(ITIMER_REAL, &it, NULL);
    long interrupted = submit1(ctx, &pr);
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, NULL);
    CHECK("pipe-interrupted", interrupted == 1 && one(ctx, &e) && e.res == -EINTR);
    write(p[1], "xyz", 3);
    CHECK("pipe-data", submit1(ctx, &pr) == 1 && one(ctx, &e) && e.res == 3);
    /* A pipe without readers: -EPIPE, with SIGPIPE unless RWF_NOSIGNAL. */
    int q[2];
    pipe(q);
    close(q[0]);
    struct sigaction sp = {.sa_handler = on_pipe};
    sigaction(SIGPIPE, &sp, NULL);
    struct iocb pw = cb(PWRITE, q[1], out, 1, 0, 0);
    pw.rw_flags = RWF_NOSIGNAL;
    CHECK("epipe-nosignal", submit1(ctx, &pw) == 1 && one(ctx, &e) && e.res == -EPIPE && sigpipes == 0);
    pw.rw_flags = 0;
    CHECK("epipe-sigpipe", submit1(ctx, &pw) == 1 && one(ctx, &e) && e.res == -EPIPE && sigpipes == 1);
    close(q[1]);
    /* IOCB_CMD_POLL. */
    struct iocb pl = cb(POLL, p[0], (void *)(uintptr_t)POLLIN, 0, 0, 5);
    struct timespec zero = {0, 0};
    CHECK("poll-waits", submit1(ctx, &pl) == 1 && getevents(ctx, 1, 1, &e, &zero) == 0);
    /* A wake-up completes the request with its key, whole. */
    write(p[1], "q", 1);
    CHECK("poll-completes", one(ctx, &e) && e.data == 5 && e.res == (POLLIN | POLLRDNORM));
    CHECK("poll-at-once", submit1(ctx, &pl) == 1 && one(ctx, &e) && e.res == POLLIN);
    read(p[0], in, 1);
    CHECK("poll-cancel", submit1(ctx, &pl) == 1 && cancel(ctx, &pl, &e) == -1 && errno == EINPROGRESS &&
                             one(ctx, &e) && e.res == 0 && e.obj == (uintptr_t)&pl);
    CHECK_ERR("cancel-again", cancel(ctx, &pl, &e), EINVAL);
    CHECK_ERR("cancel-completed", cancel(ctx, &w, &e), EINVAL);
    w.key = 5;
    CHECK_ERR("cancel-key", cancel(ctx, &w, &e), EINVAL);
    CHECK_ERR("cancel-fault", cancel(ctx, BAD, &e), EFAULT);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct iocb sk = cb(POLL, sv[0], (void *)(uintptr_t)POLLIN, 0, 0, 6);
    CHECK("poll-socket-waits", submit1(ctx, &sk) == 1 && getevents(ctx, 1, 1, &e, &zero) == 0);
    write(sv[1], "s", 1);
    CHECK("poll-socket-key", one(ctx, &e) && e.data == 6 &&
                                 e.res == (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND));
    close(sv[0]);
    close(sv[1]);
    /* A hang-up wakes without a key: the file is polled again. */
    int h[2];
    pipe(h);
    struct iocb hp = cb(POLL, h[0], (void *)(uintptr_t)POLLIN, 0, 0, 7);
    CHECK("poll-hangup-waits", submit1(ctx, &hp) == 1 && getevents(ctx, 1, 1, &e, &zero) == 0);
    close(h[1]);
    CHECK("poll-hangup", one(ctx, &e) && e.data == 7 && e.res == POLLHUP);
    close(h[0]);
    struct iocb big = cb(POLL, p[0], (void *)0x10000, 0, 0, 0);
    CHECK_ERR("poll-events", submit1(ctx, &big), EINVAL);
    big = cb(POLL, p[0], (void *)(uintptr_t)POLLIN, 1, 0, 0);
    CHECK_ERR("poll-fields", submit1(ctx, &big), EINVAL);
    struct iocb reg = cb(POLL, fd, (void *)(uintptr_t)POLLPRI, 0, 0, 0);
    CHECK_ERR("poll-file-cannot-wait", submit1(ctx, &reg), EINVAL);
    reg.buf = POLLIN;
    CHECK("poll-file-ready", submit1(ctx, &reg) == 1 && one(ctx, &e) && e.res == POLLIN);
    /* io_getevents. */
    CHECK_ERR("getevents-min-over-max", getevents(ctx, 2, 1, &e, NULL), EINVAL);
    CHECK_ERR("getevents-negative-min", getevents(ctx, -1, 1, &e, NULL), EINVAL);
    CHECK_ERR("getevents-context", getevents(ctx + 4096, 0, 1, &e, NULL), EINVAL);
    CHECK_ERR("getevents-timeout-fault", getevents(ctx, 0, 1, &e, BAD), EFAULT);
    /* A fault copying events out leaves them in the ring. */
    struct iocb f1 = cb(FSYNC, fd, 0, 0, 0, 1);
    submit1(ctx, &f1);
    CHECK_ERR("events-fault", getevents(ctx, 1, 1, BAD, NULL), EFAULT);
    CHECK("events-kept", getevents(ctx, 1, 1, &e, &zero) == 1 && e.data == 1);
    struct timespec t10 = {0, 10000000}, t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long got = getevents(ctx, 1, 1, &e, &t10);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    CHECK("getevents-timeout", got == 0 && ms >= 10);
    struct { const sigset_t *mask; size_t size; } us = {NULL, 8};
    CHECK_ERR("pgetevents-sigset-fault", syscall(SYS_io_pgetevents, ctx, 0, 1, &e, &zero, BAD), EFAULT);
    sigset_t m;
    sigemptyset(&m);
    us.mask = &m;
    us.size = 4;
    CHECK_ERR("pgetevents-sigset-size", syscall(SYS_io_pgetevents, ctx, 0, 1, &e, &zero, &us), EINVAL);
    us.size = 8;
    CHECK("pgetevents", syscall(SYS_io_pgetevents, ctx, 0, 1, &e, &zero, &us) == 0);
    close(p[0]);
    close(p[1]);
    close(fd);
}

static void rings(void) {
    uint64_t ctx = 0;
    CHECK("ring-not-locked", setup(1, &ctx) == 0 && mlock((void *)(uintptr_t)ctx, 4096) == 0 &&
                                 vmlck() == 0);
    CHECK("destroy-unlocked", destroy(ctx) == 0);
    ctx = 0;
    mlockall(MCL_FUTURE);
    long r = setup(1, &ctx);
    long locked = vmlck();
    munlockall();
    CHECK("ring-not-locked-future", r == 0 && locked == 0 && destroy(ctx) == 0);
    /* mremap: a special mapping neither grows nor is duplicated nor kept;
     * moving it moves the context. */
    ctx = 0;
    setup(1, &ctx);
    void *ring = (void *)(uintptr_t)ctx;
    CHECK_ERR("mremap-grow", mremap(ring, 4096, 8192, MREMAP_MAYMOVE), EFAULT);
    CHECK_ERR("mremap-duplicate", mremap(ring, 0, 4096, MREMAP_MAYMOVE), EFAULT);
    CHECK_ERR("mremap-dontunmap", mremap(ring, 4096, 4096, MREMAP_MAYMOVE | MREMAP_DONTUNMAP), EINVAL);
    void *spot = mmap(NULL, 3 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *to = (char *)spot + 4096;
    int fd = open("/dev/null", O_WRONLY);
    char c = 'x';
    struct iocb w = cb(PWRITE, fd, &c, 1, 0, 0);
    CHECK("mremap-moves", mremap(ring, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, to) == to);
    uint64_t moved = (uint64_t)(uintptr_t)to;
    struct io_event e;
    CHECK("moved-context", submit1(moved, &w) == 1 && getevents(moved, 1, 1, &e, NULL) == 1);
    CHECK_ERR("old-address", submit1(ctx, &w), EINVAL);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) _exit(mremap(to, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, spot) == MAP_FAILED &&
                                errno == EINVAL ? 0 : 1);
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK("child-cannot-move", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    unsigned char v;
    CHECK("destroy-moved", destroy(moved) == 0 && mincore(to, 4096, &v) == -1 && errno == ENOMEM);
    munmap(spot, 3 * 4096);
    close(fd);
}

static void capacity(void) {
    uint64_t ctx = 0;
    CHECK("setup-small", setup(1, &ctx) == 0);
    int fd = open("/dev/null", O_WRONLY);
    char c = 'x';
    struct iocb w = cb(PWRITE, fd, &c, 1, 0, 0);
    long n = 0;
    while (n < 100000 && submit1(ctx, &w) == 1) n++;
    CHECK("ring-full", n > 0 && errno == EAGAIN);
    struct aio_ring *r = (struct aio_ring *)(uintptr_t)ctx;
    CHECK("ring-holds-them", (r->tail + r->nr - r->head) % r->nr == (unsigned)n);
    /* Reaped from user space, as libaio does: the slots come back. */
    r->head = r->tail;
    CHECK("reaped-by-user", submit1(ctx, &w) == 1 && getevents(ctx, 1, 1, &(struct io_event){0}, NULL) == 1);
    /* The ring's ID names the context. */
    uint32_t id = r->id;
    r->id = 999;
    CHECK_ERR("ring-id-clobbered", submit1(ctx, &w), EINVAL);
    r->id = id;
    CHECK("ring-id-restored", submit1(ctx, &w) == 1 && getevents(ctx, 1, 1, &(struct io_event){0}, NULL) == 1);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) _exit(submit1(ctx, &w) == -1 && errno == EINVAL && r->magic == 0xa10a10a1 ? 0 : 1);
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK("child-no-context", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK("destroy", destroy(ctx) == 0);
    unsigned char v;
    CHECK("destroy-unmaps", mincore((void *)(uintptr_t)ctx, 4096, &v) == -1 && errno == ENOMEM);
    CHECK_ERR("destroy-again", destroy(ctx), EINVAL);
    CHECK_ERR("submit-destroyed", submit1(ctx, &w), EINVAL);
    close(fd);
}

int main(void) {
    setup_checks();
    uint64_t ctx = 0;
    long nr = proc_long("/proc/sys/fs/aio-nr");
    CHECK("setup", setup(4, &ctx) == 0 && ctx != 0);
    CHECK("aio-nr-counts", proc_long("/proc/sys/fs/aio-nr") == nr + 4);
    basics(ctx);
    CHECK("destroy-first", destroy(ctx) == 0);
    CHECK("aio-nr-returns", proc_long("/proc/sys/fs/aio-nr") == nr);
    rings();
    capacity();
    FINISH();
}
