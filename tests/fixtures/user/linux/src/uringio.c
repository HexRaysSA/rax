/* io_uring requests that do I/O (io_uring/rw.c, sync.c, advise.c,
 * truncate.c, poll.c, openclose.c, fs.c, statx.c): reads and writes on a
 * file and on pipes (at an offset and the file position, vectored and
 * registered-buffer ones, the checks of the request and the file,
 * requests waiting for their files), the sync, allocation, advice, and
 * truncation operations, opens (into descriptors and registered slots),
 * closes, installs, pipes, and path operations. Every request an async
 * worker could complete out of order is waited for alone. */
#include "uring.h"

static void transfers(void) {
    struct ring r = make(8, 0, 0);
    int fd = file_with("aaaaaaaaaa");
    char *buf = anon(2 * PAGE, PROT_READ | PROT_WRITE);
    char want[64];
    CHECK("rw-file", fd >= 0 && buf != MAP_FAILED);
    memcpy(buf, "xyz", 3);
    ONE("rw-write", &r, xfer(OP_WRITE, fd, buf, 3, 2, 1), 1, "1:3");
    ONE("rw-read", &r, xfer(OP_READ, fd, buf + 256, 10, 0, 2), 1, "2:10");
    CHECK("rw-read-data", memcmp(buf + 256, "aaxyzaaaaa", 10) == 0);
    /* Offset -1: the file position, which the transfer moves. */
    lseek(fd, 4, SEEK_SET);
    ONE("rw-position", &r, xfer(OP_READ, fd, buf + 512, 3, -1, 3), 1, "3:3");
    CHECK("rw-position-moved", memcmp(buf + 512, "zaa", 3) == 0 && lseek(fd, 0, SEEK_CUR) == 7);
    /* Fewer bytes than asked fail the request, and so its link. */
    struct sqe s = xfer(OP_READ, fd, buf, 5, 8, 4);
    s.flags = LINK;
    push(&r, s);
    ONE("rw-short", &r, nop(5), 2, "4:2 5:-125");
    s = xfer(OP_READ, fd, buf, 0, 10, 6);
    s.flags = LINK;
    push(&r, s);
    ONE("rw-nothing", &r, nop(7), 2, "6:0 7:0");
    s = xfer(OP_READ, fd, buf, 4, 10, 8);
    s.flags = LINK;
    push(&r, s);
    ONE("rw-at-end", &r, nop(9), 2, "8:0 9:-125");
    lseek(fd, 0, SEEK_SET);
    ONE("rw-write-position", &r, xfer(OP_WRITE, fd, buf, 3, -1, 10), 1, "10:3");
    CHECK("rw-write-position-moved", lseek(fd, 0, SEEK_CUR) == 3);

    /* Vectored: one transfer gathered and scattered. */
    ftruncate(fd, 0);
    memcpy(buf, "ABCDEFGH00000000", 16);
    struct iovec iov[2] = {{buf, 3}, {buf + 5, 3}};
    ONE("rw-writev", &r, xfer(OP_WRITEV, fd, iov, 2, 0, 11), 1, "11:6");
    struct iovec in[2] = {{buf + 256, 4}, {buf + 512, 4}};
    ONE("rw-readv", &r, xfer(OP_READV, fd, in, 2, 0, 12), 1, "12:6");
    CHECK("rw-readv-data", memcmp(buf + 256, "ABCF", 4) == 0 && memcmp(buf + 512, "GH", 2) == 0);

    /* A registered buffer: none is EFAULT; then within it only. */
    s = xfer(OP_READ_FIXED, fd, buf, 4, 0, 13);
    ONE("rw-fixed-none", &r, s, 1, "13:-14");
    struct iovec reg_iov = {buf, PAGE};
    CHECK("rw-fixed-register", reg(r.fd, REGISTER_BUFFERS, &reg_iov, 1) == 0);
    s = xfer(OP_READ_FIXED, fd, buf + 10, 4, 0, 14);
    ONE("rw-fixed", &r, s, 1, "14:4");
    CHECK("rw-fixed-data", memcmp(buf + 10, "ABCF", 4) == 0);
    s = xfer(OP_READ_FIXED, fd, buf - 1, 4, 0, 15);
    ONE("rw-fixed-below", &r, s, 1, "15:-14");
    s = xfer(OP_READ_FIXED, fd, buf + PAGE - 2, 4, 0, 16);
    ONE("rw-fixed-past", &r, s, 1, "16:-14");
    s = xfer(OP_WRITE_FIXED, fd, buf, 4, 0, 17);
    s.buf_index = 1;
    ONE("rw-fixed-index", &r, s, 1, "17:-14");
    ONE("rw-write-fixed", &r, xfer(OP_WRITE_FIXED, fd, buf + 10, 2, 0, 18), 1, "18:2");
    struct iovec vf[2] = {{buf + 0x300, 2}, {buf + 0x310, 2}};
    ONE("rw-readv-fixed", &r, xfer(OP_READV_FIXED, fd, vf, 2, 0, 19), 1, "19:4");
    CHECK("rw-readv-fixed-data", memcmp(buf + 0x300, "AB", 2) == 0 && memcmp(buf + 0x310, "CF", 2) == 0);
    ONE("rw-writev-fixed", &r, xfer(OP_WRITEV_FIXED, fd, vf, 2, 0, 20), 1, "20:4");
    struct iovec bad_vf[3] = {{buf, 0}, {buf + PAGE - 1, 2}, {buf, 0}};
    bad_vf[2].iov_len = sizeof(size_t) == 8 ? (size_t)1 << 62 : 0x7fffffff;
    ONE("rw-readv-fixed-empty", &r, xfer(OP_READV_FIXED, fd, &bad_vf[0], 1, 0, 21), 1, "21:-14");
    ONE("rw-readv-fixed-past", &r, xfer(OP_READV_FIXED, fd, &bad_vf[1], 1, 0, 22), 1, "22:-14");
    /* Too long to count in pages (EOVERFLOW), or, for a 32-bit length,
     * more pages than an array kmalloc can give holds (ENOMEM). */
    snprintf(want, sizeof want, "23:%d", sizeof(size_t) == 8 ? -EOVERFLOW : -ENOMEM);
    ONE("rw-readv-fixed-long", &r, xfer(OP_READV_FIXED, fd, &bad_vf[2], 1, 0, 23), 1, want);
    close(fd);
    drop(&r);
}

static void transfer_checks(void) {
    struct ring r = make(8, 0, 0);
    int fd = file_with("xxxxxxxx");
    char name[] = "/tmp/uring-ro-XXXXXX";
    int tmp = mkstemp(name);
    int wo = open(name, O_WRONLY);
    int ro = open(name, O_RDONLY);
    unlink(name);
    close(tmp);
    int path = open("/", O_PATH);
    int dir = open("/", O_RDONLY | O_DIRECTORY);
    char *buf = anon(PAGE, PROT_READ | PROT_WRITE);
    /* Freed after the last mapping, so it stays a hole. */
    char *hole = anon(PAGE, PROT_READ | PROT_WRITE);
    munmap(hole, PAGE);
    /* Protection information: rsvd zero, its buffer in user space. */
    struct {
        uint16_t flags, app_tag;
        uint32_t len;
        uint64_t addr, seed, rsvd;
    } pi = {0, 0, 16, PTR(buf + 0x900), 0, 0};
    struct {
        const char *name;
        struct sqe s;
        int err;
    } bad[] = {
        {"rw-bad-fd", xfer(OP_READ, 999, buf, 4, 0, 1), EBADF},
        {"rw-o-path", xfer(OP_READ, path, buf, 4, 0, 2), EBADF},
        {"rw-read-write-only", xfer(OP_READ, wo, buf, 4, 0, 3), EBADF},
        {"rw-write-read-only", xfer(OP_WRITE, ro, buf, 4, 0, 4), EBADF},
        {"rw-hipri", xfer(OP_READ, fd, buf, 4, 0, 5), EINVAL},
        {"rw-unknown-flag", xfer(OP_READ, fd, buf, 4, 0, 6), EOPNOTSUPP},
        {"rw-append-noappend", xfer(OP_READ, fd, buf, 4, 0, 7), EINVAL},
        {"rw-atomic-read", xfer(OP_READ, fd, buf, 4, 0, 8), EOPNOTSUPP},
        {"rw-negative-offset", xfer(OP_READ, fd, buf, 4, -2, 9), EINVAL},
        {"rw-offset-wraps", xfer(OP_READ, fd, buf, 4, INT64_MAX - 2, 10), EINVAL},
        {"rw-directory", xfer(OP_READ, dir, buf, 4, 0, 11), EISDIR},
        {"rw-unmapped", xfer(OP_READ, fd, hole, 4, 0, 12), EFAULT},
        {"rw-buffer-select", xfer(OP_READ, fd, NULL, 4, 0, 13), ENOBUFS},
        {"rw-pi", xfer(OP_READ, fd, buf, 4, 0, 14), EINVAL},
    };
    bad[4].s.op_flags = RWF_HIPRI_;
    bad[5].s.op_flags = 0x1000;
    bad[6].s.op_flags = RWF_APPEND_ | RWF_NOAPPEND_;
    bad[7].s.op_flags = RWF_ATOMIC_;
    bad[12].s.flags = BUFFER_SELECT;
    bad[13].s.pad2 = 1;
    bad[13].s.addr3 = PTR(&pi);
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char want[32];
        snprintf(want, sizeof want, "%llu:%d", (unsigned long long)bad[i].s.user_data, -bad[i].err);
        ONE(bad[i].name, &r, bad[i].s, 1, want);
    }
    /* Preparation's refusals end the submission. */
    struct {
        const char *name;
        struct sqe s;
        int err;
    } prep[] = {
        {"rw-ioprio", xfer(OP_READ, fd, buf, 4, 0, 21), EINVAL},
        {"rw-attr", xfer(OP_READ, fd, buf, 4, 0, 22), EINVAL},
        {"rw-readv-select", xfer(OP_READV, fd, buf, 2, 0, 24), EINVAL},
        {"rw-fixed-select", xfer(OP_READ_FIXED, fd, buf, 4, 0, 25), EOPNOTSUPP},
    };
    prep[0].s.ioprio = 7 << 13;
    prep[1].s.pad2 = 2;
    prep[2].s.flags = BUFFER_SELECT;
    prep[3].s.flags = BUFFER_SELECT;
    for (unsigned i = 0; i < sizeof prep / sizeof prep[0]; i++) {
        char want[32];
        snprintf(want, sizeof want, "%llu:%d", (unsigned long long)prep[i].s.user_data,
                 -prep[i].err);
        push(&r, prep[i].s);
        push(&r, nop(99));
        CHECK(prep[i].name, enter(r.fd, 2, 0, 0, NULL, 0) == 1);
        REAPS(prep[i].name, &r, want);
        CHECK(prep[i].name, enter(r.fd, 1, 0, 0, NULL, 0) == 1);
        REAPS(prep[i].name, &r, "99:0");
    }
    /* A buffer past user space: import_ubuf refuses it at preparation; a
     * 32-bit task's never is (access_ok's limit is the kernel's 64-bit
     * one), and its copy faults at issue. */
    ONE("rw-far-buffer", &r, xfer(OP_READ, fd, (void *)(uintptr_t)-PAGE, 4, 0, 23), 1, "23:-14");
    close(fd);
    close(wo);
    close(ro);
    close(path);
    close(dir);
    drop(&r);
}

static int sigpipes;
static void on_sigpipe(int s) { (void)s; sigpipes++; }

static void waiting(void) {
    struct ring r = make(8, 0, 0);
    char *buf = anon(PAGE, PROT_READ | PROT_WRITE);
    int p[2];
    /* O_NONBLOCK does not stop the wait: pipes support FMODE_NOWAIT. */
    CHECK("wait-pipe", pipe2(p, O_NONBLOCK) == 0);
    push(&r, xfer(OP_READ, p[0], buf, 8, -1, 1));
    CHECK("wait-submit", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("wait-parked", &r, "");
    /* The write's wake-up retries the read as the write returns. */
    CHECK("wait-write", write(p[1], "abc", 3) == 3);
    REAPS("wait-done", &r, "1:3");
    CHECK("wait-data", memcmp(buf, "abc", 3) == 0);
    struct sqe s = xfer(OP_READ, p[0], buf, 8, -1, 2);
    s.op_flags = RWF_NOWAIT_;
    push(&r, s);
    CHECK("wait-nowait", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("wait-nowait-cqe", &r, "2:-11");
    /* A link waits with its head; an offset does not matter to a pipe,
     * unless negative. */
    s = xfer(OP_READ, p[0], buf, 4, 0, 3);
    s.flags = LINK;
    push(&r, s);
    push(&r, nop(4));
    CHECK("wait-link", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("wait-link-parked", &r, "");
    CHECK("wait-link-write", write(p[1], "wxyz", 4) == 4);
    REAPS("wait-link-done", &r, "3:4 4:0");
    ONE("wait-negative-offset", &r, xfer(OP_READ, p[0], buf, 4, -5, 5), 1, "5:-22");
    /* A write waits for room. */
    memset(buf, 'f', PAGE);
    while (write(p[1], buf, PAGE) > 0) {
    }
    push(&r, xfer(OP_WRITE, p[1], buf, 10, -1, 6));
    CHECK("wait-room", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("wait-room-parked", &r, "");
    CHECK("wait-room-read", read(p[0], buf, PAGE) == PAGE);
    REAPS("wait-room-done", &r, "6:10");
    close(p[0]);
    close(p[1]);
    /* A deferring ring retries only in its waits. */
    struct ring d = make(4, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    CHECK("wait-defer-pipe", pipe(p) == 0);
    push(&d, xfer(OP_READ, p[0], buf, 8, -1, 7));
    CHECK("wait-defer", enter(d.fd, 1, 0, 0, NULL, 0) == 1);
    CHECK("wait-defer-write", write(p[1], "12", 2) == 2);
    REAPS("wait-defer-kept", &d, "");
    CHECK("wait-defer-wait", enter(d.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    REAPS("wait-defer-done", &d, "7:2");
    drop(&d);
    /* A write without readers: its error through task work, after the
     * inline NOP; SIGPIPE unless RWF_NOSIGNAL. */
    struct sigaction sa = {.sa_handler = on_sigpipe};
    sigaction(SIGPIPE, &sa, NULL);
    close(p[0]);
    s = xfer(OP_WRITE, p[1], buf, 1, -1, 8);
    s.op_flags = RWF_NOSIGNAL_;
    push(&r, s);
    push(&r, nop(9));
    CHECK("epipe-submit", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("epipe-order", &r, "9:0 8:-32");
    CHECK("epipe-nosignal", sigpipes == 0);
    push(&r, xfer(OP_WRITE, p[1], buf, 1, -1, 10));
    CHECK("epipe-signal-submit", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("epipe-signal-cqe", &r, "10:-32");
    CHECK("epipe-signal", sigpipes == 1);
    signal(SIGPIPE, SIG_DFL);
    close(p[1]);

    /* A registered file: a parked request holds its node, so emptying the
     * slot posts the tag once the request is done. */
    int f = file_with("qqqqqqqq");
    CHECK("wait-fixed-pipe", pipe(p) == 0);
    int fds[2] = {f, p[0]}, empty = -1;
    uint64_t tags[2] = {0, 77};
    CHECK("wait-fixed-register", rsrc2(r.fd, REGISTER_FILES2, 2, 0, fds, tags) == 0);
    s = xfer(OP_READ, 0, buf, 4, 0, 11);
    s.flags = FIXED_FILE;
    ONE("wait-fixed-read", &r, s, 1, "11:4");
    s.fd = 2;
    s.user_data = 12;
    ONE("wait-fixed-missing", &r, s, 1, "12:-9");
    s.fd = 1;
    s.user_data = 13;
    push(&r, s);
    CHECK("wait-fixed-submit", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    CHECK("wait-fixed-update", update2(r.fd, REGISTER_FILES_UPDATE2, 1, &empty, NULL, 1) == 1);
    REAPS("wait-fixed-held", &r, "");
    CHECK("wait-fixed-write", write(p[1], "12345", 5) == 5);
    REAPS("wait-fixed-done", &r, "13:4 77:0");
    close(f);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static off_t size_of(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 ? st.st_size : -1;
}

static void sync_ops(void) {
    struct ring r = make(8, 0, 0);
    int fd = file_with("ssssssss");
    char name[] = "/tmp/uring-sro-XXXXXX";
    int w = mkstemp(name);
    int ro = open(name, O_RDONLY);
    unlink(name);
    int p[2];
    CHECK("ops-pipe", pipe(p) == 0);
    struct sqe s = xfer(OP_FSYNC, fd, NULL, 0, 0, 1);
    ONE("ops-fsync", &r, s, 1, "1:0");
    /* io_fsync keeps its link going even when it fails. */
    s = xfer(OP_FSYNC, p[0], NULL, 0, 0, 2);
    s.flags = LINK;
    push(&r, s);
    ONE("ops-fsync-link", &r, nop(3), 2, "2:-22 3:0");
    struct {
        const char *name;
        struct sqe s;
    } prep[] = {
        {"ops-fsync-flags", xfer(OP_FSYNC, fd, NULL, 0, 0, 4)},
        {"ops-fsync-addr", xfer(OP_FSYNC, fd, (void *)1, 0, 0, 5)},
        {"ops-sfr-buf-index", xfer(OP_SYNC_FILE_RANGE, fd, NULL, 0, 0, 6)},
        {"ops-fallocate-flags", xfer(OP_FALLOCATE, fd, NULL, 0, 0, 7)},
        {"ops-ftruncate-len", xfer(OP_FTRUNCATE, fd, NULL, 1, 0, 8)},
        {"ops-madvise-file-index", xfer(OP_MADVISE, 0, NULL, 0, 0, 9)},
    };
    prep[0].s.op_flags = 2;
    prep[2].s.buf_index = 1;
    prep[3].s.op_flags = 1;
    prep[5].s.file_index = 1;
    for (unsigned i = 0; i < sizeof prep / sizeof prep[0]; i++) {
        char want[32];
        snprintf(want, sizeof want, "%llu:-22", (unsigned long long)prep[i].s.user_data);
        ONE(prep[i].name, &r, prep[i].s, 1, want);
    }
    /* vfs_fallocate: the length in addr, the mode in len. */
    ONE("ops-fallocate", &r, xfer(OP_FALLOCATE, fd, (void *)100, 0, 0, 10), 1, "10:0");
    CHECK("ops-fallocate-size", size_of(fd) == 100);
    ONE("ops-ftruncate", &r, xfer(OP_FTRUNCATE, fd, NULL, 0, 10, 11), 1, "11:0");
    CHECK("ops-ftruncate-size", size_of(fd) == 10);
    ONE("ops-ftruncate-read-only", &r, xfer(OP_FTRUNCATE, ro, NULL, 0, 1, 12), 1, "12:-22");
    ONE("ops-sfr", &r, xfer(OP_SYNC_FILE_RANGE, fd, NULL, 0, 0, 13), 1, "13:0");
    ONE("ops-sfr-pipe", &r, xfer(OP_SYNC_FILE_RANGE, p[0], NULL, 0, 0, 14), 1, "14:-29");
    s = xfer(OP_SYNC_FILE_RANGE, fd, NULL, 0, 0, 15);
    s.op_flags = 8;
    ONE("ops-sfr-flags", &r, s, 1, "15:-22");
    /* io_fadvise: its failure fails its link. */
    ONE("ops-fadvise", &r, xfer(OP_FADVISE, fd, NULL, 0, 0, 16), 1, "16:0");
    s = xfer(OP_FADVISE, fd, NULL, 0, 0, 17);
    s.op_flags = 9;
    s.flags = LINK;
    push(&r, s);
    ONE("ops-fadvise-bad", &r, nop(18), 2, "17:-22 18:-125");
    ONE("ops-fadvise-pipe", &r, xfer(OP_FADVISE, p[0], NULL, 0, 0, 19), 1, "19:-29");
    /* do_madvise: the length in off (or len). */
    char *page = anon(PAGE, PROT_READ | PROT_WRITE);
    memcpy(page, "data", 4);
    s = xfer(OP_MADVISE, 0, page, 0, PAGE, 20);
    s.op_flags = MADV_DONTNEED;
    ONE("ops-madvise", &r, s, 1, "20:0");
    CHECK("ops-madvise-dropped", page[0] == 0);
    s = xfer(OP_MADVISE, 0, page, PAGE, 0, 21);
    s.op_flags = 1000;
    ONE("ops-madvise-bad", &r, s, 1, "21:-22");
    close(fd);
    close(w);
    close(ro);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void opens(void) {
    struct ring r = make(8, 0, 0);
    char a[] = "/tmp/uring-open-a", b[] = "/tmp/uring-open-b", fifo[] = "/tmp/uring-open-fifo";
    int fd = open(a, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    CHECK("open-setup", fd >= 0 && write(fd, "A", 1) == 1);
    close(fd);
    fd = open(b, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    CHECK("open-setup-b", fd >= 0 && write(fd, "B", 1) == 1);
    close(fd);
    /* The lowest free descriptor, O_LARGEFILE added, O_NONBLOCK not kept. */
    int want_fd = lowest_free();
    char *got = one(&r, path_op(OP_OPENAT, AT_FDCWD, a, NULL, 0, 0, 1), 1);
    fd = cqe_res(got);
    CHECK("open", fd == want_fd);
    int fl = fcntl(fd, F_GETFL);
    CHECK("open-flags", (fl & RAW_LARGEFILE) && !(fl & O_NONBLOCK) &&
                            fcntl(fd, F_GETFD) == 0);
    close(fd);
    fd = cqe_res(one(&r, path_op(OP_OPENAT, AT_FDCWD, a, NULL, 0, O_CLOEXEC, 2), 1));
    CHECK("open-cloexec", fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    close(fd);
    struct sqe s = path_op(OP_OPENAT, AT_FDCWD, "/tmp/uring-open-missing", NULL, 0, 0, 3);
    s.flags = LINK;
    push(&r, s);
    ONE("open-missing", &r, nop(4), 2, "3:-2 4:-125");
    fd = cqe_res(one(&r, path_op(OP_OPENAT, AT_FDCWD, "/tmp/uring-open-created", NULL, 0600,
                                 O_CREAT | O_WRONLY, 5), 1));
    struct stat st;
    CHECK("open-create", fd >= 0 && stat("/tmp/uring-open-created", &st) == 0);
    close(fd);
    unlink("/tmp/uring-open-created");
    /* RLIMIT_NOFILE (as preparation reads it): the descriptor is taken
     * before the lookup, so EMFILE rather than ENOENT. */
    struct rlimit rl, low;
    getrlimit(RLIMIT_NOFILE, &rl);
    low = rl;
    low.rlim_cur = lowest_free();
    push(&r, path_op(OP_OPENAT, AT_FDCWD, "/tmp/uring-open-missing", NULL, 0, 0, 6));
    setrlimit(RLIMIT_NOFILE, &low);
    long submitted = enter(r.fd, 1, 1, GETEVENTS, NULL, 0);
    setrlimit(RLIMIT_NOFILE, &rl);
    CHECK("open-limit-submit", submitted == 1);
    REAPS("open-limit", &r, "6:-24");
    /* Tried with O_NONBLOCK: a FIFO without a reader is ENXIO. */
    unlink(fifo);
    CHECK("open-fifo-make", mkfifo(fifo, 0600) == 0);
    ONE("open-fifo", &r, path_op(OP_OPENAT, AT_FDCWD, fifo, NULL, 0, O_WRONLY, 7), 1, "7:-6");
    unlink(fifo);
    /* Preparation. */
    PREP("open-empty", &r, path_op(OP_OPENAT, AT_FDCWD, "", NULL, 0, 0, 8), "8:-2");
    PREP("open-fault", &r, path_op(OP_OPENAT, AT_FDCWD, (char *)16, NULL, 0, 0, 9), "9:-14");
    s = path_op(OP_OPENAT, AT_FDCWD, a, NULL, 0, 0, 10);
    s.buf_index = 1;
    PREP("open-buf-index", &r, s, "10:-22");
    s = path_op(OP_OPENAT, AT_FDCWD, a, NULL, 0, 0, 11);
    s.flags = FIXED_FILE;
    PREP("open-fixed-file", &r, s, "11:-9");
    s = path_op(OP_OPENAT, AT_FDCWD, a, NULL, 0, O_CLOEXEC, 12);
    s.file_index = 1;
    PREP("open-direct-cloexec", &r, s, "12:-22");
    /* The name is the one at preparation: a read linked ahead rewrites
     * it before the open runs. */
    char name[32];
    strcpy(name, a);
    int src = file_with(b);
    s = xfer(OP_READ, src, name, sizeof b - 1, 0, 13);
    s.flags = LINK;
    push(&r, s);
    got = one(&r, path_op(OP_OPENAT, AT_FDCWD, name, NULL, 0, 0, 14), 2);
    char *second = strchr(got, ' ');
    fd = second ? cqe_res(second) : -1;
    char c = 0;
    CHECK("open-name-stable", strcmp(name, b) == 0 && fd >= 0 && read(fd, &c, 1) == 1 && c == 'A');
    close(fd);
    close(src);

    /* IORING_OP_OPENAT2: copy_struct_from_user, then build_open_flags. */
    uint64_t how[4] = {0, 0, 0, 0};
    PREP("openat2-short", &r, path_op(OP_OPENAT2, AT_FDCWD, a, how, 16, 0, 15), "15:-22");
    how[3] = 1;
    PREP("openat2-tail", &r, path_op(OP_OPENAT2, AT_FDCWD, a, how, 32, 0, 16), "16:-7");
    how[3] = 0;
    fd = cqe_res(one(&r, path_op(OP_OPENAT2, AT_FDCWD, a, how, 32, 0, 17), 1));
    CHECK("openat2", fd >= 0);
    close(fd);
    how[0] = 1ULL << 40;
    ONE("openat2-flag", &r, path_op(OP_OPENAT2, AT_FDCWD, a, how, 24, 0, 18), 1, "18:-22");
    how[0] = 0;
    how[1] = 0600;
    ONE("openat2-mode", &r, path_op(OP_OPENAT2, AT_FDCWD, a, how, 24, 0, 19), 1, "19:-22");
    unlink(a);
    unlink(b);
    drop(&r);
}

static void directs(void) {
    struct ring r = make(8, 0, 0);
    char a[] = "/tmp/uring-direct";
    int fd = open(a, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    CHECK("direct-setup", fd >= 0 && write(fd, "direct", 6) == 6);
    close(fd);
    struct sqe s = path_op(OP_OPENAT, AT_FDCWD, a, NULL, 0, 0, 1);
    s.file_index = 1;
    ONE("direct-no-table", &r, s, 1, "1:-6");
    CHECK("direct-table", rsrc2(r.fd, REGISTER_FILES2, 4, RSRC_SPARSE, NULL, NULL) == 0);
    s.file_index = 2;
    s.user_data = 2;
    ONE("direct-named", &r, s, 1, "2:0");
    s.file_index = FILE_INDEX_ALLOC;
    s.user_data = 3;
    ONE("direct-alloc", &r, s, 1, "3:2");
    s.file_index = 5;
    s.user_data = 4;
    ONE("direct-past", &r, s, 1, "4:-22");
    char buf[8] = {0};
    s = xfer(OP_READ, 1, buf, 6, 0, 5);
    s.flags = FIXED_FILE;
    ONE("direct-read", &r, s, 1, "5:6");
    CHECK("direct-read-data", memcmp(buf, "direct", 6) == 0);
    /* io_install_fixed_fd. */
    struct sqe in = nop(6);
    in.opcode = OP_FIXED_FD_INSTALL;
    in.flags = FIXED_FILE;
    in.fd = 1;
    fd = cqe_res(one(&r, in, 1));
    CHECK("install", fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    close(fd);
    in.op_flags = 1;
    in.user_data = 7;
    fd = cqe_res(one(&r, in, 1));
    CHECK("install-no-cloexec", fd >= 0 && fcntl(fd, F_GETFD) == 0);
    close(fd);
    struct sqe bad = in;
    bad.flags = 0;
    bad.user_data = 8;
    PREP("install-not-fixed", &r, bad, "8:-9");
    bad = in;
    bad.op_flags = 2;
    bad.user_data = 9;
    PREP("install-flags", &r, bad, "9:-22");
    bad = in;
    bad.addr = 1;
    bad.user_data = 10;
    PREP("install-addr", &r, bad, "10:-22");
    int pers = reg(r.fd, REGISTER_PERSONALITY, NULL, 0);
    bad = in;
    bad.personality = pers;
    bad.user_data = 11;
    PREP("install-creds", &r, bad, "11:-1");
    /* io_close of slots. */
    struct sqe cl = nop(12);
    cl.opcode = OP_CLOSE;
    cl.file_index = 2;
    ONE("close-slot", &r, cl, 1, "12:0");
    cl.user_data = 13;
    ONE("close-slot-empty", &r, cl, 1, "13:-9");
    unlink(a);
    drop(&r);
}

static void closes(void) {
    struct ring r = make(8, 0, 0);
    int fd = dup(1);
    struct sqe cl = nop(1);
    cl.opcode = OP_CLOSE;
    cl.fd = fd;
    ONE("close", &r, cl, 1, "1:0");
    CHECK("close-closed", fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    cl.user_data = 2;
    ONE("close-again", &r, cl, 1, "2:-9");
    cl.fd = r.fd;
    cl.user_data = 3;
    ONE("close-ring", &r, cl, 1, "3:-9");
    struct sqe bad = cl;
    bad.file_index = 1;
    bad.user_data = 4;
    PREP("close-both", &r, bad, "4:-22");
    bad = cl;
    bad.addr = 1;
    bad.user_data = 5;
    PREP("close-addr", &r, bad, "5:-22");
    bad = cl;
    bad.flags = FIXED_FILE;
    bad.user_data = 6;
    PREP("close-fixed-file", &r, bad, "6:-9");
    drop(&r);
}

static void pipes(void) {
    struct ring r = make(8, 0, 0);
    int fds[2] = {-1, -1};
    struct sqe s = nop(1);
    s.opcode = OP_PIPE;
    s.addr = PTR(fds);
    s.op_flags = O_CLOEXEC;
    ONE("pipe", &r, s, 1, "1:0");
    char c = 0;
    CHECK("pipe-works", fcntl(fds[0], F_GETFD) == FD_CLOEXEC && write(fds[1], "p", 1) == 1 &&
                            read(fds[0], &c, 1) == 1 && c == 'p');
    close(fds[0]);
    close(fds[1]);
    s.op_flags = O_WRONLY;
    s.user_data = 2;
    PREP("pipe-flags", &r, s, "2:-22");
    s.op_flags = O_EXCL;
    s.user_data = 3;
    ONE("pipe-notification", &r, s, 1, "3:-65");
    int before = lowest_free();
    s.op_flags = 0;
    s.addr = 16;
    s.user_data = 4;
    ONE("pipe-fault", &r, s, 1, "4:-14");
    CHECK("pipe-fault-no-fds", lowest_free() == before);
    CHECK("pipe-table", rsrc2(r.fd, REGISTER_FILES2, 4, RSRC_SPARSE, NULL, NULL) == 0);
    s.addr = PTR(fds);
    s.file_index = FILE_INDEX_ALLOC;
    s.user_data = 5;
    ONE("pipe-alloc", &r, s, 1, "5:0");
    CHECK("pipe-alloc-slots", fds[0] == 0 && fds[1] == 1);
    s.file_index = 3;
    s.user_data = 6;
    ONE("pipe-named", &r, s, 1, "6:0");
    CHECK("pipe-named-slots", fds[0] == 0 && fds[1] == 0);
    s.op_flags = O_CLOEXEC;
    s.user_data = 7;
    ONE("pipe-direct-cloexec", &r, s, 1, "7:-22");
    drop(&r);
}

static void paths(void) {
    struct ring r = make(8, 0, 0);
    char dir[] = "/tmp/uring-dir", f[] = "/tmp/uring-f", g[] = "/tmp/uring-g",
         linked[] = "/tmp/uring-linked", sym[] = "/tmp/uring-sym";
    unlink(f);
    unlink(g);
    unlink(linked);
    unlink(sym);
    rmdir(dir);
    ONE("mkdirat", &r, path_op(OP_MKDIRAT, AT_FDCWD, dir, NULL, 0700, 0, 1), 1, "1:0");
    struct stat st;
    CHECK("mkdirat-made", stat(dir, &st) == 0 && S_ISDIR(st.st_mode));
    int fd = open(f, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    CHECK("paths-setup", fd >= 0 && write(fd, "12345", 5) == 5);
    close(fd);
    ONE("renameat", &r, path_op(OP_RENAMEAT, AT_FDCWD, f, g, AT_FDCWD, 0, 2), 1, "2:0");
    CHECK("renameat-moved", stat(g, &st) == 0 && stat(f, &st) == -1);
    ONE("linkat", &r, path_op(OP_LINKAT, AT_FDCWD, g, linked, AT_FDCWD, 0, 3), 1, "3:0");
    ONE("symlinkat", &r, path_op(OP_SYMLINKAT, AT_FDCWD, g, sym, 0, 0, 4), 1, "4:0");
    char target[64] = {0};
    CHECK("symlinkat-target", readlink(sym, target, sizeof target - 1) > 0 && strcmp(target, g) == 0);
    unsigned char stx[256];
    memset(stx, 0, sizeof stx);
    ONE("statx", &r, path_op(OP_STATX, AT_FDCWD, g, stx, 0x7ff, 0, 5), 1, "5:0");
    uint64_t size;
    memcpy(&size, stx + 40, 8);
    CHECK("statx-size", size == 5);
    /* A failure keeps the link going. */
    struct sqe s = path_op(OP_UNLINKAT, AT_FDCWD, "/tmp/uring-gone", NULL, 0, 0, 6);
    s.flags = LINK;
    push(&r, s);
    ONE("unlinkat-missing", &r, nop(7), 2, "6:-2 7:0");
    ONE("unlinkat", &r, path_op(OP_UNLINKAT, AT_FDCWD, linked, NULL, 0, 0, 8), 1, "8:0");
    ONE("unlinkat-dir", &r, path_op(OP_UNLINKAT, AT_FDCWD, dir, NULL, 0, 0x200, 9), 1, "9:0");
    CHECK("unlinkat-dir-gone", stat(dir, &st) == -1);
    /* Preparation. */
    PREP("unlinkat-flags", &r, path_op(OP_UNLINKAT, AT_FDCWD, g, NULL, 0, 0x100, 10), "10:-22");
    PREP("unlinkat-len", &r, path_op(OP_UNLINKAT, AT_FDCWD, g, NULL, 1, 0, 11), "11:-22");
    PREP("mkdirat-off", &r, path_op(OP_MKDIRAT, AT_FDCWD, dir, (void *)1, 0, 0, 12), "12:-22");
    PREP("symlinkat-len", &r, path_op(OP_SYMLINKAT, AT_FDCWD, g, sym, 1, 0, 13), "13:-22");
    s = path_op(OP_RENAMEAT, AT_FDCWD, g, f, 0, 0, 14);
    s.flags = FIXED_FILE;
    PREP("renameat-fixed-file", &r, s, "14:-9");
    PREP("unlinkat-empty", &r, path_op(OP_UNLINKAT, AT_FDCWD, "", NULL, 0, 0, 15), "15:-2");
    PREP("statx-empty", &r, path_op(OP_STATX, AT_FDCWD, "", stx, 0x7ff, 0, 16), "16:-2");
    fd = open(g, O_RDONLY);
    ONE("statx-fd", &r, path_op(OP_STATX, fd, "", stx, 0x7ff, AT_EMPTY_PATH, 17), 1, "17:0");
    memcpy(&size, stx + 40, 8);
    CHECK("statx-fd-size", size == 5);
    close(fd);
    unlink(g);
    unlink(sym);
    drop(&r);
}
int main(void) {
    transfers();
    transfer_checks();
    waiting();
    sync_ops();
    opens();
    directs();
    closes();
    pipes();
    paths();
    FINISH();
}
