/* io_uring's poll requests (io_uring/poll.c, Linux 6.19): one-shot and
 * multishot IORING_OP_POLL_ADD, IORING_OP_POLL_REMOVE and its updates, the
 * order in which one wake-up reaches several requests, the poll table as
 * fdinfo lists it, and the wake-ups of io_uring's own (EPOLL_URING_WAKE). */
#include "uring.h"

enum { ADD_MULTI = 1, UPDATE_EVENTS = 1 << 1, UPDATE_USER_DATA = 1 << 2, ADD_LEVEL = 1 << 3 };

static struct sqe poll_sqe(int fd, uint32_t events, uint32_t flags, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_POLL_ADD;
    s.fd = fd;
    s.op_flags = events;
    s.len = flags;
    return s;
}

static struct sqe remove_sqe(uint64_t old, uint32_t flags, uint64_t new_data, uint32_t events,
                             uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_POLL_REMOVE;
    s.addr = old;
    s.off = new_data;
    s.len = flags;
    s.op_flags = events;
    return s;
}

/* Submits every queued SQE without waiting, and reaps with the flags. */
static char *sub(struct ring *r) {
    uint32_t queued = *sq_u32(r, r->p.sq_off.tail) - *sq_u32(r, r->p.sq_off.head);
    long got = enter(r->fd, queued, 0, 0, NULL, 0);
    if (got != (long)queued)
        printf("  enter returned %ld errno %d\n", got, errno);
    return reapf(r);
}

#define SUB(name, r, want)                                                    \
    do {                                                                      \
        char *got_ = sub(r);                                                  \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

static void put_byte(int fd, const char *c) {
    if (write(fd, c, 1) != 1)
        printf("  write failed errno %d\n", errno);
}

static void put_one(int ev) {
    uint64_t one = 1;
    if (write(ev, &one, 8) != 8)
        printf("  eventfd write failed errno %d\n", errno);
}

static void oneshot(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    CHECK("oneshot-pipe", pipe(p) == 0);
    /* Not ready: the request waits in the poll table. */
    push(&r, poll_sqe(p[0], POLLIN, 0, 1));
    SUB("oneshot-waits", &r, "");
    TEXT("oneshot-listed", poll_list(r.fd), "  op=6, task_works=0\n");
    /* The write's wake-up completes it as the write returns. */
    if (write(p[1], "ab", 2) != 2)
        printf("  write failed\n");
    REAPF("oneshot-woken", &r, "1:1");
    TEXT("oneshot-unlisted", poll_list(r.fd), "");
    /* Ready: at once, with the events asked for... */
    push(&r, poll_sqe(p[0], POLLIN | POLLRDNORM, 0, 2));
    SUB("oneshot-ready", &r, "2:65");
    push(&r, poll_sqe(p[1], POLLOUT, 0, 3));
    SUB("oneshot-writable", &r, "3:4");
    /* ...and those of IO_POLL_UNMASK, asked for or not. */
    char b[2];
    if (read(p[0], b, 2) != 2)
        printf("  read failed\n");
    close(p[1]);
    push(&r, poll_sqe(p[0], POLLIN, 0, 4));
    SUB("oneshot-hangup", &r, "4:16");
    /* A request that skips its successful CQE posts none. */
    struct sqe s = poll_sqe(p[0], POLLIN, 0, 5);
    s.flags = SKIP;
    push(&r, s);
    SUB("oneshot-skip", &r, "");
    close(p[0]);
    drop(&r);
}

static void nowaitq(void) {
    struct ring r = make(8, 0, 0);
    int dir = open("/tmp", O_RDONLY | O_DIRECTORY), file = file_with("x");
    CHECK("nowaitq-files", dir >= 0 && file >= 0);
    /* No ->poll: vfs_poll's DEFAULT_POLLMASK, at once, even multishot. */
    push(&r, poll_sqe(dir, POLLIN | POLLOUT, 0, 1));
    SUB("nowaitq-directory", &r, "1:5");
    push(&r, poll_sqe(file, POLLIN, ADD_MULTI, 2));
    SUB("nowaitq-multishot-once", &r, "2:1");
    /* Nothing it reports: no wait-queue entry either, so EINVAL. */
    push(&r, poll_sqe(file, POLLPRI, 0, 3));
    SUB("nowaitq-never", &r, "3:-22");
    push(&r, poll_sqe(999, POLLIN, 0, 4));
    SUB("nowaitq-no-file", &r, "4:-9");
    close(dir);
    close(file);
    drop(&r);
}

static void prep(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    CHECK("prep-pipe", pipe(p) == 0);
    struct sqe s = poll_sqe(p[0], POLLIN, 0, 1);
    s.addr = 1;
    PREP("prep-add-addr", &r, s, "1:-22");
    s = poll_sqe(p[0], POLLIN, 0, 2);
    s.off = 1;
    PREP("prep-add-off", &r, s, "2:-22");
    s = poll_sqe(p[0], POLLIN, 0, 3);
    s.buf_index = 1;
    PREP("prep-add-buf-index", &r, s, "3:-22");
    PREP("prep-add-level", &r, poll_sqe(p[0], POLLIN, ADD_LEVEL, 4), "4:-22");
    PREP("prep-add-update", &r, poll_sqe(p[0], POLLIN, UPDATE_EVENTS, 5), "5:-22");
    s = poll_sqe(p[0], POLLIN, ADD_MULTI, 6);
    s.flags = SKIP;
    PREP("prep-add-multi-skip", &r, s, "6:-22");
    s = poll_sqe(p[0], POLLIN, 0, 7);
    s.flags = BUFFER_SELECT;
    PREP("prep-add-buffer-select", &r, s, "7:-95");
    PREP("prep-remove-multi-alone", &r, remove_sqe(1, ADD_MULTI, 0, 0, 8), "8:-22");
    PREP("prep-remove-flag", &r, remove_sqe(1, 1 << 4, 0, 0, 9), "9:-22");
    PREP("prep-remove-new-data", &r, remove_sqe(1, 0, 5, 0, 10), "10:-22");
    PREP("prep-remove-events", &r, remove_sqe(1, 0, 0, POLLIN, 11), "11:-22");
    s = remove_sqe(1, 0, 0, 0, 12);
    s.buf_index = 1;
    PREP("prep-remove-buf-index", &r, s, "12:-22");
    s = remove_sqe(1, 0, 0, 0, 13);
    s.file_index = 1;
    PREP("prep-remove-file-index", &r, s, "13:-22");
    TEXT("prep-nothing-listed", poll_list(r.fd), "");
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void multishot(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    char b[4];
    CHECK("multishot-pipe", pipe(p) == 0);
    push(&r, poll_sqe(p[0], POLLIN, ADD_MULTI, 1));
    SUB("multishot-waits", &r, "");
    /* Each write wakes it: a polled pipe's writer wakes its readers
     * whether it was empty or not. */
    put_byte(p[1], "a");
    REAPF("multishot-first", &r, "1:1/2");
    put_byte(p[1], "b");
    REAPF("multishot-second", &r, "1:1/2");
    /* A read that did not sleep wakes no reader. */
    if (read(p[0], b, 1) != 1 || read(p[0], b, 1) != 1)
        printf("  read failed\n");
    REAPF("multishot-reads", &r, "");
    put_byte(p[1], "c");
    REAPF("multishot-refilled", &r, "1:1/2");
    /* Removed: the removal's CQE, then the poll's, through task work. */
    push(&r, remove_sqe(1, 0, 0, 0, 2));
    SUB("multishot-removed", &r, "2:0 1:-125");
    /* Ready as it is armed: the first report comes at once. */
    push(&r, poll_sqe(p[0], POLLIN, ADD_MULTI, 3));
    SUB("multishot-ready", &r, "3:1/2");
    put_byte(p[1], "d");
    REAPF("multishot-again", &r, "3:1/2");
    close(p[1]);
    REAPF("multishot-hangup", &r, "3:17/2");
    push(&r, remove_sqe(3, 0, 0, 0, 4));
    SUB("multishot-hangup-removed", &r, "4:0 3:-125");
    close(p[0]);
    drop(&r);
}

static void removal(void) {
    struct ring r = make(8, 0, 0);
    int ev = eventfd(0, EFD_NONBLOCK), p[2], q[2];
    char buf[8];
    CHECK("removal-files", ev >= 0 && pipe(p) == 0 && pipe(q) == 0);
    push(&r, remove_sqe(9, 0, 0, 0, 1));
    SUB("removal-none", &r, "1:-2");
    /* A request waiting for its file is not a poll request. */
    push(&r, xfer(OP_READ, p[0], buf, 4, -1, 9));
    SUB("removal-read-waits", &r, "");
    push(&r, remove_sqe(9, 0, 0, 0, 2));
    SUB("removal-not-a-poll", &r, "2:-2");
    /* New events arm it again, and ready now it completes (task work). */
    push(&r, poll_sqe(ev, POLLIN, 0, 3));
    SUB("removal-poll-waits", &r, "");
    push(&r, remove_sqe(3, UPDATE_EVENTS, 0, POLLOUT, 4));
    SUB("removal-update-events", &r, "4:0 3:4");
    /* New user data: it completes under that. */
    push(&r, poll_sqe(ev, POLLIN, 0, 5));
    SUB("removal-poll-waits-2", &r, "");
    push(&r, remove_sqe(5, UPDATE_USER_DATA, 6, 0, 7));
    SUB("removal-update-data", &r, "7:0");
    push(&r, remove_sqe(5, 0, 0, 0, 8));
    SUB("removal-old-data-gone", &r, "8:-2");
    put_one(ev);
    REAPF("removal-new-data", &r, "6:1");
    /* Both: new events and user data. */
    push(&r, poll_sqe(q[0], POLLIN, 0, 20));
    SUB("removal-poll-waits-3", &r, "");
    push(&r, remove_sqe(20, UPDATE_EVENTS | UPDATE_USER_DATA, 21, POLLOUT, 22));
    SUB("removal-update-both", &r, "22:0");
    close(q[1]);
    REAPF("removal-update-both-hangup", &r, "21:16");
    close(q[0]);
    /* Of two with the same user data the newest goes; each of two
     * requests one wake-up reaches completes, the newest first. */
    CHECK("removal-pipe", pipe(q) == 0);
    push(&r, poll_sqe(p[0], POLLIN, 0, 10));
    push(&r, poll_sqe(q[0], POLLIN, 0, 10));
    SUB("removal-two-wait", &r, "");
    push(&r, remove_sqe(10, 0, 0, 0, 11));
    SUB("removal-newest", &r, "11:0 10:-125");
    put_byte(q[1], "x");
    REAPF("removal-newest-gone", &r, "");
    put_byte(p[1], "y");
    REAPF("removal-wake-order", &r, "10:1 9:1");
    close(ev);
    close(p[0]);
    close(p[1]);
    close(q[0]);
    close(q[1]);
    drop(&r);
}

static void deferred(void) {
    struct ring r = make(8, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    int p[2];
    CHECK("deferred-ring", r.fd >= 0 && pipe(p) == 0);
    push(&r, poll_sqe(p[0], POLLIN, 0, 1));
    SUB("deferred-waits", &r, "");
    /* Woken, its task work waits for a wait: io_poll_disarm's EALREADY. */
    put_byte(p[1], "x");
    REAPF("deferred-woken", &r, "");
    push(&r, remove_sqe(1, 0, 0, 0, 2));
    SUB("deferred-already", &r, "2:-114");
    long got = enter(r.fd, 0, 1, GETEVENTS, NULL, 0);
    CHECK("deferred-wait", got == 0);
    REAPF("deferred-runs", &r, "1:1");
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void links(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    CHECK("links-pipe", pipe(p) == 0);
    struct sqe s = poll_sqe(p[0], POLLIN, 0, 1);
    s.flags = LINK;
    push(&r, s);
    push(&r, nop(2));
    SUB("links-wait", &r, "");
    put_byte(p[1], "x");
    REAPF("links-follow", &r, "1:1 2:0");
    s = poll_sqe(999, POLLIN, 0, 3);
    s.flags = LINK;
    push(&r, s);
    push(&r, nop(4));
    SUB("links-fail", &r, "3:-9 4:-125");
    /* Forced to the workers, it waits the same way (a worker arms it
     * while the process goes on, so the hang-up may come first). */
    s = poll_sqe(p[0], POLLOUT, 0, 5);
    s.flags = ASYNC;
    push(&r, s);
    SUB("links-async-waits", &r, "");
    close(p[1]);
    CHECK("links-async-wait", enter(r.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    REAPF("links-async-hangup", &r, "5:16");
    close(p[0]);
    drop(&r);
}

static void table(void) {
    /* 16 CQ entries: one hash bit (ilog2(16) - 5, at least 1); hash_64
     * puts user data 1, 3, and 6 in bucket 0, and 2 and 4 in bucket 1. */
    struct ring r = make(8, 0, 0);
    int p[2];
    char b2[4], b6[4];
    CHECK("table-pipe", pipe(p) == 0);
    push(&r, poll_sqe(p[0], POLLIN, 0, 1));
    push(&r, xfer(OP_READ, p[0], b2, 4, -1, 2));
    push(&r, poll_sqe(p[0], POLLIN, 0, 3));
    push(&r, poll_sqe(p[0], POLLIN, 0, 4));
    push(&r, xfer(OP_READ, p[0], b6, 4, -1, 6));
    SUB("table-wait", &r, "");
    /* Bucket by bucket, each newest first: 6, 3, 1; 4, 2. */
    TEXT("table-order", poll_list(r.fd),
         "  op=22, task_works=0\n  op=6, task_works=0\n  op=6, task_works=0\n"
         "  op=6, task_works=0\n  op=22, task_works=0\n");
    /* The hang-up reaches them newest first. */
    close(p[1]);
    REAPF("table-hangup", &r, "6:0 4:16 3:16 2:0 1:16");
    close(p[0]);
    drop(&r);
    /* 128: two bits; user data 1 in bucket 1, 2 in 3, 3 in 0, 4 in 2. */
    r = make(64, 0, 0);
    CHECK("table-pipe-2", pipe(p) == 0);
    push(&r, poll_sqe(p[0], POLLIN, 0, 1));
    push(&r, poll_sqe(p[0], POLLIN, 0, 2));
    push(&r, xfer(OP_READ, p[0], b2, 4, -1, 3));
    push(&r, poll_sqe(p[0], POLLIN, 0, 4));
    SUB("table-wait-2", &r, "");
    TEXT("table-order-2", poll_list(r.fd),
         "  op=22, task_works=0\n  op=6, task_works=0\n  op=6, task_works=0\n"
         "  op=6, task_works=0\n");
    close(p[1]);
    REAPF("table-hangup-2", &r, "4:16 3:0 2:16 1:16");
    close(p[0]);
    drop(&r);
}

static void uring_wake(void) {
    struct ring r = make(8, 0, 0);
    int ev = eventfd(0, EFD_NONBLOCK), p[2];
    uint64_t got;
    CHECK("uring-wake-files", ev >= 0 && pipe(p) == 0);
    /* Written by the process, the eventfd wakes a multishot poll each time. */
    push(&r, poll_sqe(ev, POLLIN, ADD_MULTI, 1));
    SUB("uring-wake-waits", &r, "");
    put_one(ev);
    REAPF("uring-wake-write", &r, "1:1/2");
    put_one(ev);
    REAPF("uring-wake-write-2", &r, "1:1/2");
    /* Registered, it counts the ring's completions with EPOLL_URING_WAKE:
     * the poll reports that once more and leaves the wait queue. */
    CHECK("uring-wake-register", reg(r.fd, REGISTER_EVENTFD, &ev, 1) == 0);
    CHECK("uring-wake-drain", read(ev, &got, 8) == 8 && got == 2);
    push(&r, poll_sqe(p[0], POLLIN, ADD_MULTI, 2));
    SUB("uring-wake-pipe-waits", &r, "");
    push(&r, nop(3));
    SUB("uring-wake-completion", &r, "3:0 1:1/2");
    push(&r, nop(4));
    SUB("uring-wake-off-queue", &r, "4:0");
    put_one(ev);
    REAPF("uring-wake-no-more", &r, "");
    /* Still in the table: a removal cancels it. */
    push(&r, remove_sqe(1, 0, 0, 0, 5));
    SUB("uring-wake-removed", &r, "5:0 1:-125");
    push(&r, remove_sqe(2, 0, 0, 0, 6));
    SUB("uring-wake-pipe-removed", &r, "6:0 2:-125");
    close(ev);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

int main(void) {
    oneshot();
    nowaitq();
    prep();
    multishot();
    removal();
    deferred();
    links();
    table();
    uring_wake();
    FINISH();
}
