/* io_uring's timeouts and cancellation (io_uring/timeout.c, cancel.c, Linux
 * 6.19): IORING_OP_TIMEOUT expiring and counting completions, multishot
 * timeouts, IORING_OP_TIMEOUT_REMOVE's removals and updates,
 * IORING_OP_LINK_TIMEOUT against the request before it, IORING_OP_ASYNC_CANCEL
 * by user data, file, operation, all, and any, IORING_REGISTER_SYNC_CANCEL,
 * and a timer expiring while the process sleeps in another call. Every
 * expiry is waited for; no check depends on a timer racing a return. */
#include "uring.h"

enum { T_ABS = 1, T_UPDATE = 1 << 1, T_BOOTTIME = 1 << 2, T_REALTIME = 1 << 3,
       T_LINK_UPDATE = 1 << 4, T_ETIME_SUCCESS = 1 << 5, T_MULTISHOT = 1 << 6 };
enum { C_ALL = 1, C_FD = 1 << 1, C_ANY = 1 << 2, C_FD_FIXED = 1 << 3, C_OP = 1 << 5 };

/* struct __kernel_timespec, 64-bit fields on every architecture. */
struct kts {
    int64_t sec, nsec;
};

static struct kts short_ts = {0, 5000000}, mid_ts = {0, 50000000}, long_ts = {10, 0},
                  epoch = {0, 0}, neg_sec = {-1, 0}, neg_nsec = {0, -1};

static struct sqe timeout_sqe(struct kts *ts, uint64_t off, uint32_t flags, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_TIMEOUT;
    s.addr = PTR(ts);
    s.len = 1;
    s.off = off;
    s.op_flags = flags;
    return s;
}

static struct sqe ltimeout_sqe(struct kts *ts, uint64_t data) {
    struct sqe s = timeout_sqe(ts, 0, 0, data);
    s.opcode = OP_LINK_TIMEOUT;
    return s;
}

static struct sqe tremove_sqe(uint64_t target, uint32_t flags, struct kts *ts, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_TIMEOUT_REMOVE;
    s.addr = target;
    s.off = PTR(ts);
    s.op_flags = flags;
    return s;
}

static struct sqe cancel_sqe(uint64_t target, uint32_t flags, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_ASYNC_CANCEL;
    s.addr = target;
    s.op_flags = flags;
    return s;
}

static struct sqe poll_in(int fd, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_POLL_ADD;
    s.fd = fd;
    s.op_flags = POLLIN;
    return s;
}

static struct sqe linked(struct sqe s) {
    s.flags |= LINK;
    return s;
}

/* Submits every queued SQE, with IORING_ENTER_GETEVENTS waits for n
 * completions, and reaps with the flags. */
static char *enter_reap(struct ring *r, unsigned n, unsigned flags) {
    uint32_t queued = *sq_u32(r, r->p.sq_off.tail) - *sq_u32(r, r->p.sq_off.head);
    long got = enter(r->fd, queued, n, flags, NULL, 0);
    if (got != (long)queued)
        printf("  enter returned %ld errno %d\n", got, errno);
    return reapf(r);
}

#define ENTER(name, r, n, flags, want)                                        \
    do {                                                                      \
        char *got_ = enter_reap(r, n, flags);                                 \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

#define WAIT(name, r, n, want) ENTER(name, r, n, GETEVENTS, want)

/* Submits without waiting: an ordinary ring's task work runs as the call
 * returns, a deferring ring's waits. */
#define SUB(name, r, want) ENTER(name, r, 0, 0, want)

/* Waits until n CQEs came, however many waits that takes (an expiry ends
 * a wait: io_should_wake), and reaps them with the flags. */
static char *collect(struct ring *r, unsigned n) {
    static char all[1024];
    unsigned got = 0;
    all[0] = 0;
    while (got < n) {
        if (enter(r->fd, 0, 1, GETEVENTS, NULL, 0) < 0) {
            printf("  enter failed errno %d\n", errno);
            break;
        }
        for (char *part = reapf(r); *part; got++) {
            char *end = strchr(part, ' ');
            size_t len = end ? (size_t)(end - part) : strlen(part);
            if (*all)
                strcat(all, " ");
            strncat(all, part, len);
            part += len + (end != NULL);
        }
    }
    return all;
}

static void put_byte(int fd) {
    if (write(fd, "x", 1) != 1)
        printf("  write failed errno %d\n", errno);
}

static void expiry(void) {
    struct ring r = make(8, 0, 0);
    push(&r, timeout_sqe(&short_ts, 0, 0, 1));
    WAIT("expiry-etime", &r, 1, "1:-62");
    /* An expiry ends a wait for more (io_should_wake: nr_timeouts). */
    push(&r, timeout_sqe(&short_ts, 0, 0, 30));
    WAIT("expiry-ends-wait", &r, 2, "30:-62");
    /* Counting: complete with 0 once that many other CQEs posted. */
    push(&r, timeout_sqe(&long_ts, 2, 0, 2));
    push(&r, nop(3));
    push(&r, nop(4));
    SUB("expiry-count", &r, "3:0 4:0 2:0");
    push(&r, timeout_sqe(&long_ts, 1, 0, 5));
    SUB("expiry-count-waits", &r, "");
    push(&r, nop(6));
    SUB("expiry-count-later", &r, "6:0 5:0");
    /* A timeout's own CQE is not counted. */
    push(&r, timeout_sqe(&long_ts, 1, 0, 7));
    SUB("expiry-uncounted-waits", &r, "");
    push(&r, timeout_sqe(&short_ts, 0, 0, 8));
    WAIT("expiry-uncounted-expiry", &r, 1, "8:-62");
    push(&r, nop(9));
    SUB("expiry-uncounted", &r, "9:0 7:0");
    drop(&r);
    /* In order of the sequence each waits for. */
    r = make(8, 0, 0);
    push(&r, timeout_sqe(&long_ts, 3, 0, 20));
    push(&r, timeout_sqe(&long_ts, 1, 0, 21));
    SUB("expiry-sorted-wait", &r, "");
    push(&r, nop(22));
    SUB("expiry-sorted-first", &r, "22:0 21:0");
    push(&r, nop(23));
    push(&r, nop(24));
    SUB("expiry-sorted-second", &r, "23:0 24:0 20:0");
    drop(&r);
}

static void links(void) {
    struct ring r = make(8, 0, 0);
    push(&r, linked(timeout_sqe(&short_ts, 0, 0, 1)));
    push(&r, nop(2));
    WAIT("links-etime-fails", &r, 2, "1:-62 2:-125");
    push(&r, linked(timeout_sqe(&short_ts, 0, T_ETIME_SUCCESS, 3)));
    push(&r, nop(4));
    WAIT("links-etime-success", &r, 2, "3:-62 4:0");
    push(&r, linked(timeout_sqe(&long_ts, 1, 0, 5)));
    push(&r, nop(6));
    SUB("links-count-waits", &r, "");
    push(&r, nop(7));
    SUB("links-count-follows", &r, "7:0 5:0 6:0");
    drop(&r);
}

static void multishot(void) {
    struct ring r = make(8, 0, 0);
    /* Each expiry ends a wait; the last reports without MORE. */
    push(&r, timeout_sqe(&mid_ts, 3, T_MULTISHOT, 1));
    WAIT("multishot-first", &r, 3, "1:-62/2");
    TEXT("multishot-rest", collect(&r, 2), "1:-62/2 1:-62");
    push(&r, timeout_sqe(&long_ts, 0, T_MULTISHOT, 2));
    SUB("multishot-waits", &r, "");
    push(&r, tremove_sqe(2, 0, NULL, 3));
    SUB("multishot-removed", &r, "3:0 2:-125");
    drop(&r);
}

static void prep(void) {
    struct ring r = make(8, 0, 0);
    struct sqe s = timeout_sqe(&long_ts, 0, 0, 1);
    s.len = 2;
    PREP("prep-count", &r, s, "1:-22");
    s = timeout_sqe(&long_ts, 0, 0, 2);
    s.buf_index = 1;
    PREP("prep-buf-index", &r, s, "2:-22");
    s = timeout_sqe(&long_ts, 0, 0, 3);
    s.file_index = 1;
    PREP("prep-file-index", &r, s, "3:-22");
    PREP("prep-flags", &r, timeout_sqe(&long_ts, 0, 1 << 7, 4), "4:-22");
    PREP("prep-clocks", &r, timeout_sqe(&long_ts, 0, T_BOOTTIME | T_REALTIME, 5), "5:-22");
    PREP("prep-abs-multishot", &r, timeout_sqe(&long_ts, 0, T_MULTISHOT | T_ABS, 6), "6:-22");
    PREP("prep-fault", &r, timeout_sqe((struct kts *)16, 0, 0, 7), "7:-14");
    PREP("prep-negative-sec", &r, timeout_sqe(&neg_sec, 0, 0, 8), "8:-22");
#if UINTPTR_MAX == 0xffffffff
    /* A 32-bit caller's tv_nsec is its low word (get_timespec64): -1 is
     * 4294967295 ns, a timeout to remove. */
    push(&r, timeout_sqe(&neg_nsec, 0, 0, 9));
    SUB("prep-nsec-low-word", &r, "");
    push(&r, tremove_sqe(9, 0, NULL, 90));
    SUB("prep-nsec-low-word-removed", &r, "90:0 9:-125");
#else
    PREP("prep-negative-nsec", &r, timeout_sqe(&neg_nsec, 0, 0, 9), "9:-22");
#endif
    s = timeout_sqe(&long_ts, 0, 0, 10);
    s.flags = BUFFER_SELECT;
    PREP("prep-buffer-select", &r, s, "10:-95");
    s = ltimeout_sqe(&long_ts, 11);
    s.off = 1;
    PREP("prep-link-count", &r, s, "11:-22");
    PREP("prep-link-alone", &r, ltimeout_sqe(&long_ts, 12), "12:-22");
    s = tremove_sqe(1, 0, NULL, 13);
    s.len = 1;
    PREP("prep-remove-len", &r, s, "13:-22");
    s = tremove_sqe(1, 0, NULL, 14);
    s.flags = FIXED_FILE;
    PREP("prep-remove-fixed", &r, s, "14:-22");
    PREP("prep-remove-flags", &r, tremove_sqe(1, T_ABS, NULL, 15), "15:-22");
    PREP("prep-update-clock", &r, tremove_sqe(1, T_UPDATE | T_REALTIME, &long_ts, 16), "16:-22");
    PREP("prep-update-fault", &r, tremove_sqe(1, T_UPDATE, NULL, 17), "17:-14");
    PREP("prep-update-negative", &r, tremove_sqe(1, T_UPDATE, &neg_sec, 18), "18:-22");
    s = cancel_sqe(1, 0, 19);
    s.off = 1;
    PREP("prep-cancel-off", &r, s, "19:-22");
    s = cancel_sqe(1, 0, 20);
    s.file_index = 1;
    PREP("prep-cancel-file-index", &r, s, "20:-22");
    PREP("prep-cancel-flags", &r, cancel_sqe(1, 1 << 6, 21), "21:-22");
    PREP("prep-cancel-any-fd", &r, cancel_sqe(1, C_ANY | C_FD, 22), "22:-22");
    PREP("prep-cancel-any-op", &r, cancel_sqe(1, C_ANY | C_OP, 23), "23:-22");
    /* A linked timeout after another fails, and its link with it. */
    push(&r, linked(nop(30)));
    push(&r, linked(ltimeout_sqe(&long_ts, 31)));
    push(&r, ltimeout_sqe(&long_ts, 32));
    SUB("prep-link-after-link", &r, "30:-125 31:-125 32:-22");
    drop(&r);
}

static void removal(void) {
    struct ring r = make(8, 0, 0);
    push(&r, timeout_sqe(&long_ts, 0, 0, 1));
    SUB("removal-waits", &r, "");
    push(&r, tremove_sqe(1, 0, NULL, 2));
    SUB("removal-removed", &r, "2:0 1:-125");
    push(&r, tremove_sqe(1, 0, NULL, 3));
    SUB("removal-none", &r, "3:-2");
    /* Updated: the new time. */
    push(&r, timeout_sqe(&long_ts, 0, 0, 4));
    SUB("removal-update-waits", &r, "");
    push(&r, tremove_sqe(4, T_UPDATE, &short_ts, 5));
    SUB("removal-updated", &r, "5:0");
    WAIT("removal-update-expires", &r, 1, "4:-62");
    /* An updated timeout counts no more completions. */
    push(&r, timeout_sqe(&long_ts, 1, 0, 6));
    SUB("removal-count-waits", &r, "");
    push(&r, tremove_sqe(6, T_UPDATE, &long_ts, 7));
    SUB("removal-count-updated", &r, "7:0");
    push(&r, nop(8));
    SUB("removal-count-gone", &r, "8:0");
    push(&r, tremove_sqe(6, 0, NULL, 9));
    SUB("removal-count-removed", &r, "9:0 6:-125");
    /* An absolute time already past. */
    push(&r, timeout_sqe(&long_ts, 0, 0, 10));
    SUB("removal-abs-waits", &r, "");
    push(&r, tremove_sqe(10, T_UPDATE | T_ABS, &epoch, 11));
    WAIT("removal-abs-past", &r, 2, "11:0 10:-62");
    /* IORING_LINK_TIMEOUT_UPDATE without IORING_TIMEOUT_UPDATE removes. */
    push(&r, timeout_sqe(&long_ts, 0, 0, 12));
    SUB("removal-link-flag-waits", &r, "");
    push(&r, tremove_sqe(12, T_LINK_UPDATE, &long_ts, 13));
    SUB("removal-link-flag-removes", &r, "13:0 12:-125");
    drop(&r);
}

static void linkto(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    char b;
    CHECK("linkto-pipe", pipe(p) == 0);
    /* Expiring first, it cancels the poll and reports -ETIME. */
    push(&r, linked(poll_in(p[0], 1)));
    push(&r, ltimeout_sqe(&short_ts, 2));
    WAIT("linkto-expires", &r, 2, "2:-62 1:-125");
    /* The poll completing first cancels it. */
    push(&r, linked(poll_in(p[0], 3)));
    push(&r, ltimeout_sqe(&long_ts, 4));
    SUB("linkto-waits", &r, "");
    put_byte(p[1]);
    REAPF("linkto-request-first", &r, "3:1 4:-125");
    if (read(p[0], &b, 1) != 1)
        printf("  read failed\n");
    /* Out of the link, the rest follows its request. */
    push(&r, linked(nop(5)));
    push(&r, linked(ltimeout_sqe(&long_ts, 6)));
    push(&r, nop(7));
    SUB("linkto-rest-follows", &r, "5:0 6:-125 7:0");
    push(&r, linked(poll_in(p[0], 8)));
    push(&r, linked(ltimeout_sqe(&short_ts, 9)));
    push(&r, nop(10));
    WAIT("linkto-rest-fails", &r, 3, "9:-62 8:-125 10:-125");
    /* A timeout it bounds. */
    push(&r, linked(timeout_sqe(&long_ts, 0, 0, 15)));
    push(&r, ltimeout_sqe(&short_ts, 16));
    WAIT("linkto-timeout", &r, 2, "16:-62 15:-125");
    /* IORING_LINK_TIMEOUT_UPDATE restarts it. */
    push(&r, linked(poll_in(p[0], 11)));
    push(&r, ltimeout_sqe(&long_ts, 12));
    SUB("linkto-update-waits", &r, "");
    push(&r, tremove_sqe(12, T_UPDATE | T_LINK_UPDATE, &short_ts, 13));
    SUB("linkto-updated", &r, "13:0");
    WAIT("linkto-update-expires", &r, 2, "12:-62 11:-125");
    push(&r, tremove_sqe(12, T_UPDATE | T_LINK_UPDATE, &short_ts, 14));
    SUB("linkto-update-none", &r, "14:-2");
    close(p[0]);
    close(p[1]);
    drop(&r);
    /* A deferring ring: the request's completion waits as task work, the
     * timeout expires, and its cancellation finds nothing (-ENOENT). */
    r = make(8, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    struct sqe s = linked(nop(17));
    s.op_flags = NOP_TW;
    push(&r, s);
    push(&r, ltimeout_sqe(&short_ts, 18));
    SUB("linkto-deferred-waits", &r, "");
    usleep(30000);
    WAIT("linkto-deferred", &r, 2, "17:0 18:-2");
    drop(&r);
}

static void cancel(void) {
    struct ring r = make(8, 0, 0);
    int p[2], q[2];
    char buf[8];
    CHECK("cancel-pipes", pipe(p) == 0 && pipe(q) == 0);
    push(&r, cancel_sqe(99, 0, 1));
    SUB("cancel-none", &r, "1:-2");
    /* By user data: a poll, a request waiting for its file, a timeout. */
    push(&r, poll_in(p[0], 2));
    SUB("cancel-poll-waits", &r, "");
    push(&r, cancel_sqe(2, 0, 3));
    SUB("cancel-poll", &r, "3:0 2:-125");
    push(&r, xfer(OP_READ, p[0], buf, 4, -1, 4));
    SUB("cancel-read-waits", &r, "");
    push(&r, cancel_sqe(4, 0, 5));
    SUB("cancel-read", &r, "5:0 4:-125");
    push(&r, timeout_sqe(&long_ts, 0, 0, 6));
    SUB("cancel-timeout-waits", &r, "");
    push(&r, cancel_sqe(6, 0, 7));
    SUB("cancel-timeout", &r, "7:0 6:-125");
    /* _ALL: each one, counted. */
    push(&r, poll_in(p[0], 8));
    push(&r, poll_in(q[0], 8));
    SUB("cancel-all-waits", &r, "");
    push(&r, cancel_sqe(8, C_ALL, 9));
    SUB("cancel-all", &r, "9:2 8:-125 8:-125");
    /* _ANY: the poll table in its order (user data 14 in bucket 0; 12,
     * then 10, in bucket 1), then the timeouts. */
    push(&r, poll_in(p[0], 10));
    push(&r, timeout_sqe(&long_ts, 0, 0, 11));
    push(&r, xfer(OP_READ, p[0], buf, 4, -1, 12));
    push(&r, poll_in(q[0], 14));
    SUB("cancel-any-waits", &r, "");
    push(&r, cancel_sqe(0, C_ANY, 13));
    SUB("cancel-any", &r, "13:4 14:-125 12:-125 10:-125 11:-125");
    /* By file, by operation. */
    push(&r, poll_in(p[0], 15));
    push(&r, poll_in(q[0], 16));
    SUB("cancel-fd-waits", &r, "");
    struct sqe s = cancel_sqe(0, C_FD, 17);
    s.fd = q[0];
    push(&r, s);
    SUB("cancel-fd", &r, "17:0 16:-125");
    push(&r, xfer(OP_READ, p[0], buf, 4, -1, 18));
    SUB("cancel-op-waits", &r, "");
    s = cancel_sqe(0, C_OP, 19);
    s.len = OP_READ;
    push(&r, s);
    SUB("cancel-op", &r, "19:0 18:-125");
    push(&r, cancel_sqe(0, C_ANY, 20));
    SUB("cancel-any-rest", &r, "20:1 15:-125");
    /* A registered file. */
    int files[1] = {p[0]};
    CHECK("cancel-register", reg(r.fd, REGISTER_FILES, files, 1) == 0);
    push(&r, poll_in(p[0], 40));
    SUB("cancel-fixed-waits", &r, "");
    s = cancel_sqe(0, C_FD | C_FD_FIXED, 41);
    s.fd = 0;
    push(&r, s);
    SUB("cancel-fixed", &r, "41:0 40:-125");
    s = cancel_sqe(0, C_FD, 42);
    s.fd = 999;
    push(&r, s);
    SUB("cancel-no-file", &r, "42:-9");
    s = cancel_sqe(0, C_FD | C_FD_FIXED, 43);
    s.fd = 5;
    push(&r, s);
    SUB("cancel-no-slot", &r, "43:-9");
    close(p[0]);
    close(p[1]);
    close(q[0]);
    close(q[1]);
    drop(&r);
}

struct sync_cancel_reg {
    uint64_t addr;
    int32_t fd;
    uint32_t flags;
    struct kts timeout;
    uint8_t opcode, pad[7];
    uint64_t pad2[3];
};

static void sync_cancel(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    CHECK("sync-pipe", pipe(p) == 0);
    struct sync_cancel_reg sc;
    memset(&sc, 0, sizeof sc);
    sc.addr = 1;
    sc.timeout.sec = -1;
    sc.timeout.nsec = -1;
    push(&r, poll_in(p[0], 1));
    SUB("sync-waits", &r, "");
    CHECK("sync-cancel", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1) == 0);
    /* The poll's task work runs as the call returns. */
    REAPF("sync-completes", &r, "1:-125");
    CHECK_ERR("sync-none", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1), ENOENT);
    CHECK_ERR("sync-nr-args", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 2), EINVAL);
    CHECK_ERR("sync-fault", reg(r.fd, REGISTER_SYNC_CANCEL, (void *)16, 1), EFAULT);
    sc.flags = 1 << 6;
    CHECK_ERR("sync-flags", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1), EINVAL);
    sc.flags = 0;
    sc.pad[0] = 1;
    CHECK_ERR("sync-pad", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1), EINVAL);
    sc.pad[0] = 0;
    sc.pad2[2] = 1;
    CHECK_ERR("sync-pad2", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1), EINVAL);
    sc.pad2[2] = 0;
    /* By file. */
    push(&r, poll_in(p[0], 2));
    SUB("sync-fd-waits", &r, "");
    sc.flags = C_FD;
    sc.fd = p[0];
    CHECK("sync-fd", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1) == 0);
    REAPF("sync-fd-completes", &r, "2:-125");
    sc.fd = 999;
    CHECK_ERR("sync-no-file", reg(r.fd, REGISTER_SYNC_CANCEL, &sc, 1), EBADF);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void sleeping(void) {
    int p[2];
    CHECK("sleeping-pipe", pipe(p) == 0);
    struct pollfd pfd = {.fd = p[0], .events = POLLIN};
    /* An ordinary ring's timeout completes while the process sleeps in
     * another call. */
    struct ring r = make(8, 0, 0);
    push(&r, timeout_sqe(&short_ts, 0, 0, 1));
    SUB("sleeping-waits", &r, "");
    CHECK("sleeping-poll", poll(&pfd, 1, 60) == 0);
    REAPF("sleeping-expired", &r, "1:-62");
    drop(&r);
    /* A deferring ring's waits for the ring's own wait. */
    r = make(8, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    push(&r, timeout_sqe(&short_ts, 0, 0, 2));
    SUB("sleeping-deferred-waits", &r, "");
    CHECK("sleeping-deferred-poll", poll(&pfd, 1, 60) == 0);
    REAPF("sleeping-deferred-held", &r, "");
    WAIT("sleeping-deferred-runs", &r, 1, "2:-62");
    drop(&r);
    close(p[0]);
    close(p[1]);
}

int main(void) {
    expiry();
    links();
    multishot();
    prep();
    removal();
    linkto();
    cancel();
    sync_cancel();
    sleeping();
    FINISH();
}
