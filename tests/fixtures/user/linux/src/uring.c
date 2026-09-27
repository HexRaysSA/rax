/* io_uring through its system calls (io_uring/, include/uapi/linux/io_uring.h):
 * setup and its parameters, the ring mappings, NOP submission and its
 * flags, links, request checks, dropped SQ indices, CQ overflow, deferred
 * task work, drains, waits, polling the ring, registration, and fdinfo.
 * Only NOP requests are used, and only what does not depend on how fast an
 * async worker runs is checked. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#endif

struct sqring_off {
    uint32_t head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
    uint64_t user_addr;
};
struct cqring_off {
    uint32_t head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
    uint64_t user_addr;
};
struct params {
    uint32_t sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle, features, wq_fd;
    uint32_t resv[3];
    struct sqring_off sq_off;
    struct cqring_off cq_off;
};
struct sqe {
    uint8_t opcode, flags;
    uint16_t ioprio;
    int32_t fd;
    uint64_t off, addr;
    uint32_t len, op_flags;
    uint64_t user_data;
    uint16_t buf_index, personality;
    uint32_t file_index;
    uint64_t addr3, pad2;
};
struct cqe {
    uint64_t user_data;
    int32_t res;
    uint32_t flags;
};
struct getevents_arg {
    uint64_t sigmask;
    uint32_t sigmask_sz, min_wait_usec;
    uint64_t ts;
};
struct rsrc_update {
    uint32_t offset, resv;
    uint64_t data;
};

enum {
    CQSIZE = 1 << 3, CLAMP = 1 << 4, ATTACH_WQ = 1 << 5, R_DISABLED = 1 << 6,
    SUBMIT_ALL = 1 << 7, COOP_TASKRUN = 1 << 8, TASKRUN_FLAG = 1 << 9, CQE32 = 1 << 11,
    SINGLE_ISSUER = 1 << 12, DEFER_TASKRUN = 1 << 13, NO_SQARRAY = 1 << 16,
    SQ_AFF = 1 << 2
};
enum { GETEVENTS = 1, EXT_ARG = 1 << 3, REGISTERED_RING = 1 << 4, ABS_TIMER = 1 << 5 };
enum { DRAIN = 1 << 1, LINK = 1 << 2, HARDLINK = 1 << 3, ASYNC = 1 << 4,
       BUFFER_SELECT = 1 << 5, SKIP = 1 << 6 };
enum { INJECT = 1, NOP_FILE = 1 << 1, NOP_FIXED_FILE = 1 << 2, NOP_FIXED_BUFFER = 1 << 3,
       NOP_TW = 1 << 4, NOP_CQE32 = 1 << 5 };
enum { REGISTER_EVENTFD = 4, UNREGISTER_EVENTFD = 5, REGISTER_EVENTFD_ASYNC = 7,
       REGISTER_PROBE = 8, REGISTER_PERSONALITY = 9, UNREGISTER_PERSONALITY = 10,
       REGISTER_ENABLE_RINGS = 12, REGISTER_RING_FDS = 20, UNREGISTER_RING_FDS = 21 };
#define USE_REGISTERED_RING (1u << 31)
#define OFF_SQ_RING 0ULL
#define OFF_CQ_RING 0x8000000ULL
#define OFF_SQES 0x10000000ULL
#define SQ_CQ_OVERFLOW 2u

static long setup_raw(unsigned n, struct params *p) { return syscall(SYS_io_uring_setup, n, p); }
static long enter(int fd, unsigned submit, unsigned min, unsigned flags, void *arg, size_t sz) {
    return syscall(SYS_io_uring_enter, fd, submit, min, flags, arg, sz);
}
static long reg(int fd, unsigned op, void *arg, unsigned n) {
    return syscall(SYS_io_uring_register, fd, op, arg, n);
}

struct ring {
    int fd;
    struct params p;
    char *rings;
    struct sqe *sqes;
    unsigned cqe_size;
};

static volatile uint32_t *sq_u32(struct ring *r, uint32_t off) { return (void *)(r->rings + off); }

/* A ring of n entries with flags, mapped as liburing maps it; fd -errno on
 * failure. */
static struct ring make(unsigned n, unsigned flags, unsigned cq) {
    struct ring r = {.fd = -1};
    memset(&r.p, 0, sizeof r.p);
    r.p.flags = flags;
    r.p.cq_entries = cq;
    r.fd = setup_raw(n, &r.p);
    if (r.fd < 0) {
        r.fd = -errno;
        return r;
    }
    r.cqe_size = flags & CQE32 ? 32 : 16;
    size_t len = flags & NO_SQARRAY ? r.p.cq_off.cqes + r.cqe_size * r.p.cq_entries
                                     : r.p.sq_off.array + 4 * r.p.sq_entries;
    r.rings = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r.fd, OFF_SQ_RING);
    r.sqes = mmap(NULL, 64 * r.p.sq_entries, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                  r.fd, OFF_SQES);
    return r;
}

static void drop(struct ring *r) {
    if (r->fd >= 0)
        close(r->fd);
}

static struct sqe nop(uint64_t data) {
    struct sqe s;
    memset(&s, 0, sizeof s);
    s.user_data = data;
    return s;
}
static struct sqe nopf(uint64_t data, uint8_t flags) {
    struct sqe s = nop(data);
    s.flags = flags;
    return s;
}
static struct sqe inject(uint64_t data, int res, uint8_t flags) {
    struct sqe s = nopf(data, flags);
    s.op_flags = INJECT;
    s.len = (uint32_t)res;
    return s;
}

static void push(struct ring *r, struct sqe s) {
    uint32_t tail = *sq_u32(r, r->p.sq_off.tail);
    uint32_t slot = tail & (r->p.sq_entries - 1);
    r->sqes[slot] = s;
    if (!(r->p.flags & NO_SQARRAY))
        sq_u32(r, r->p.sq_off.array)[slot] = slot;
    __atomic_store_n(sq_u32(r, r->p.sq_off.tail), tail + 1, __ATOMIC_RELEASE);
}

/* Reaps every CQE as "data:res" pairs into buf. */
static char *reap(struct ring *r) {
    static char buf[1024];
    char *p = buf;
    *p = 0;
    uint32_t head = *sq_u32(r, r->p.cq_off.head);
    uint32_t tail = __atomic_load_n(sq_u32(r, r->p.cq_off.tail), __ATOMIC_ACQUIRE);
    while (head != tail) {
        struct cqe *c = (void *)(r->rings + r->p.cq_off.cqes +
                                 r->cqe_size * (head & (r->p.cq_entries - 1)));
        p += sprintf(p, "%s%llu:%d", p == buf ? "" : " ", (unsigned long long)c->user_data, c->res);
        head++;
    }
    __atomic_store_n(sq_u32(r, r->p.cq_off.head), head, __ATOMIC_RELEASE);
    return buf;
}

#define REAPS(name, r, want)                                                  \
    do {                                                                      \
        char *got_ = reap(r);                                                 \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

static int cmpu(const void *a, const void *b) {
    long x = *(const long *)a, y = *(const long *)b;
    return (x > y) - (x < y);
}

static void setup_params(void) {
    struct params p;
    memset(&p, 0, sizeof p);
    int fd = setup_raw(3, &p);
    CHECK("setup", fd >= 0);
    CHECK("setup-entries", p.sq_entries == 4 && p.cq_entries == 8 && p.flags == 0);
    CHECK("setup-sq-off", p.sq_off.head == 0 && p.sq_off.tail == 4 && p.sq_off.ring_mask == 16 &&
                              p.sq_off.ring_entries == 24 && p.sq_off.flags == 36 &&
                              p.sq_off.dropped == 32 && p.sq_off.array == 192 &&
                              p.sq_off.resv1 == 0 && p.sq_off.user_addr == 0);
    CHECK("setup-cq-off", p.cq_off.head == 8 && p.cq_off.tail == 12 && p.cq_off.ring_mask == 20 &&
                              p.cq_off.ring_entries == 28 && p.cq_off.overflow == 44 &&
                              p.cq_off.cqes == 64 && p.cq_off.flags == 40 && p.cq_off.resv1 == 0);
    CHECK("setup-features", (p.features & 0x3ffff) == 0x3ffff);
    CHECK("setup-cloexec", fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK("setup-rdwr", (fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR);
    char path[64], link[64] = {0};
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    CHECK("setup-name", readlink(path, link, sizeof link - 1) > 0 &&
                            strcmp(link, "anon_inode:[io_uring]") == 0);
    struct stat a, b;
    int fd2 = setup_raw(3, &p);
    CHECK("setup-inodes", fstat(fd, &a) == 0 && fstat(fd2, &b) == 0 && a.st_ino != b.st_ino &&
                              (a.st_mode & 07777) == 0600 && a.st_dev == b.st_dev);
    close(fd2);
    memset(&p, 0, sizeof p);
    p.flags = CQSIZE;
    p.cq_entries = 5;
    CHECK("setup-cqsize", setup_raw(4, &p) >= 0 && p.sq_entries == 4 && p.cq_entries == 8);
    memset(&p, 0, sizeof p);
    p.flags = CLAMP;
    CHECK("setup-clamp", setup_raw(40000, &p) >= 0 && p.sq_entries == 32768 &&
                             p.cq_entries == 65536);
    memset(&p, 0, sizeof p);
    p.flags = NO_SQARRAY;
    CHECK("setup-no-sqarray", setup_raw(4, &p) >= 0 && p.sq_off.array == 0);
    memset(&p, 0, sizeof p);
    p.flags = CQE32;
    CHECK("setup-cqe32", setup_raw(4, &p) >= 0 && p.sq_off.array == 2 * (64 + 16 * 8));

    struct {
        const char *name;
        unsigned n, flags, cq;
        int err;
    } bad[] = {
        {"setup-zero", 0, 0, 0, EINVAL},
        {"setup-too-many", 32769, 0, 0, EINVAL},
        {"setup-cqsize-zero", 4, CQSIZE, 0, EINVAL},
        {"setup-cqsize-small", 8, CQSIZE, 4, EINVAL},
        {"setup-cqsize-many", 4, CQSIZE, 65537, EINVAL},
        {"setup-unknown-flag", 4, 1u << 31, 0, EINVAL},
        {"setup-defer-alone", 4, DEFER_TASKRUN, 0, EINVAL},
        {"setup-taskrun-flag-alone", 4, TASKRUN_FLAG, 0, EINVAL},
        {"setup-sq-aff-alone", 4, SQ_AFF, 0, EINVAL},
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        memset(&p, 0, sizeof p);
        p.flags = bad[i].flags;
        p.cq_entries = bad[i].cq;
        CHECK_ERR(bad[i].name, setup_raw(bad[i].n, &p), bad[i].err);
    }
    memset(&p, 0, sizeof p);
    p.flags = ATTACH_WQ;
    p.wq_fd = 999;
    CHECK_ERR("setup-attach-bad-fd", setup_raw(4, &p), ENXIO);
    memset(&p, 0, sizeof p);
    p.flags = ATTACH_WQ;
    p.wq_fd = 1;
    CHECK_ERR("setup-attach-not-ring", setup_raw(4, &p), EINVAL);
    memset(&p, 0, sizeof p);
    p.flags = ATTACH_WQ;
    p.wq_fd = fd;
    int attached = setup_raw(4, &p);
    CHECK("setup-attach", attached >= 0);
    close(attached);
    memset(&p, 0, sizeof p);
    p.resv[1] = 1;
    CHECK_ERR("setup-resv", setup_raw(4, &p), EINVAL);
    CHECK_ERR("setup-fault", setup_raw(4, (void *)16), EFAULT);
    close(fd);
}

static void mappings(void) {
    struct ring r = make(4, 0, 0);
    CHECK("map", r.fd >= 0 && r.rings != MAP_FAILED && r.sqes != MAP_FAILED);
    CHECK("map-masks", *sq_u32(&r, r.p.sq_off.ring_mask) == 3 &&
                           *sq_u32(&r, r.p.sq_off.ring_entries) == 4 &&
                           *sq_u32(&r, r.p.cq_off.ring_mask) == 7 &&
                           *sq_u32(&r, r.p.cq_off.ring_entries) == 8);
    char *cq = mmap(NULL, 4096, PROT_READ, MAP_SHARED, r.fd, OFF_CQ_RING);
    CHECK("map-cq-offset", cq != MAP_FAILED && *(uint32_t *)(cq + 20) == 7);
    errno = 0;
    CHECK("map-hint", mmap((void *)0x70000000, 4096, PROT_READ, MAP_SHARED, r.fd, 0) == MAP_FAILED &&
                          errno == EINVAL);
    errno = 0;
    CHECK("map-fixed", mmap((void *)0x70000000, 4096, PROT_READ, MAP_SHARED | MAP_FIXED, r.fd, 0) ==
                           MAP_FAILED && errno == EINVAL);
    errno = 0;
    CHECK("map-no-region", mmap(NULL, 4096, PROT_READ, MAP_SHARED, r.fd, 0x20000000) ==
                               MAP_FAILED && errno == ENOMEM);
    struct ring big = make(128, 0, 0);
    errno = 0;
    CHECK("map-short-sqes", mmap(NULL, 4096, PROT_READ, MAP_SHARED, big.fd, OFF_SQES) ==
                                MAP_FAILED && errno == EFAULT);
    drop(&big);
    char c;
    CHECK_ERR("ring-read", read(r.fd, &c, 1), EINVAL);
    CHECK_ERR("ring-write", write(r.fd, &c, 1), EINVAL);
    CHECK_ERR("ring-lseek", lseek(r.fd, 0, SEEK_SET), ESPIPE);
    drop(&r);
}

static void nops(void) {
    struct ring r = make(4, 0, 0);
    for (int i = 1; i <= 3; i++)
        push(&r, nop(i));
    CHECK("nop-submit", enter(r.fd, 3, 0, 0, NULL, 0) == 3);
    CHECK("nop-sq-head", *sq_u32(&r, r.p.sq_off.head) == 3);
    REAPS("nop-order", &r, "1:0 2:0 3:0");
    CHECK("nop-nothing", enter(r.fd, 4, 0, 0, NULL, 0) == 0);
    push(&r, nop(4));
    CHECK("nop-short", enter(r.fd, 4, 0, 0, NULL, 0) == 1);
    REAPS("nop-short-cqe", &r, "4:0");
    drop(&r);

    r = make(8, 0, 0);
    push(&r, inject(1, 7, 0));
    push(&r, inject(2, -5, 0));
    struct sqe s = nopf(3, LINK);
    s.op_flags = NOP_FILE;
    s.fd = 999;
    push(&r, s);
    push(&r, nop(4));
    s = nopf(5, LINK);
    s.op_flags = NOP_FILE | NOP_FIXED_FILE;
    push(&r, s);
    push(&r, nop(6));
    s = nop(7);
    s.op_flags = NOP_FIXED_BUFFER;
    push(&r, s);
    s = nop(8);
    s.op_flags = NOP_CQE32;
    push(&r, s);
    CHECK("nop-flags", enter(r.fd, 8, 0, 0, NULL, 0) == 8);
    REAPS("nop-flags-cqes", &r, "1:7 2:-5 3:0 5:0 7:0 8:-22 4:-125 6:-125");
    s = nop(9);
    s.op_flags = 1u << 6;
    push(&r, s);
    CHECK("nop-unknown-flag", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("nop-unknown-flag-cqe", &r, "9:-22");
    drop(&r);

    r = make(4, CQE32, 0);
    s = nop(1);
    s.op_flags = NOP_CQE32;
    s.off = 11;
    s.addr = 22;
    push(&r, s);
    CHECK("nop-cqe32", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    uint64_t *c = (void *)(r.rings + r.p.cq_off.cqes);
    CHECK("nop-cqe32-extra", c[0] == 1 && c[2] == 11 && c[3] == 22);
    drop(&r);
}

static void links(void) {
    struct ring r = make(16, 0, 0);
    push(&r, nopf(1, LINK));
    push(&r, nopf(2, LINK));
    push(&r, nop(3));
    CHECK("link-submit", enter(r.fd, 3, 0, 0, NULL, 0) == 3);
    REAPS("link-chain", &r, "1:0 2:0 3:0");
    push(&r, nopf(4, LINK));
    push(&r, inject(5, -9, LINK));
    push(&r, nopf(6, LINK));
    push(&r, nop(7));
    CHECK("link-fail-submit", enter(r.fd, 4, 0, 0, NULL, 0) == 4);
    REAPS("link-fail", &r, "4:0 5:-9 6:-125 7:-125");
    push(&r, inject(8, -9, HARDLINK));
    push(&r, nop(9));
    CHECK("hardlink-submit", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("hardlink", &r, "8:-9 9:0");
    push(&r, nopf(10, LINK | SKIP));
    push(&r, nopf(11, LINK));
    push(&r, inject(12, -1, LINK | SKIP));
    push(&r, nopf(13, LINK));
    push(&r, nop(14));
    CHECK("skip-submit", enter(r.fd, 5, 0, 0, NULL, 0) == 5);
    REAPS("skip", &r, "11:0 12:-1");
    /* An unfinished link goes to an async worker: wait for it. */
    push(&r, nopf(15, LINK));
    CHECK("link-unfinished", enter(r.fd, 1, 1, GETEVENTS, NULL, 0) == 1);
    REAPS("link-unfinished-cqe", &r, "15:0");
    drop(&r);
}

static void checks(void) {
    struct ring r = make(8, 0, 0);
    struct sqe bad[6];
    const char *names[] = {"check-opcode", "check-sqe-flag", "check-ioprio", "check-buffer-select",
                           "check-personality"};
    const char *want[] = {"1:-22", "2:-22", "3:-22", "4:-95", "5:-22"};
    bad[0] = nop(1);
    bad[0].opcode = 200;
    bad[1] = nopf(2, 1u << 7);
    bad[2] = nop(3);
    bad[2].ioprio = 1;
    bad[3] = nopf(4, BUFFER_SELECT);
    bad[4] = nop(5);
    bad[4].personality = 7;
    for (int i = 0; i < 5; i++) {
        push(&r, bad[i]);
        push(&r, nop(99));
        CHECK(names[i], enter(r.fd, 2, 0, 0, NULL, 0) == 1);
        REAPS(names[i], &r, want[i]);
        CHECK(names[i], enter(r.fd, 1, 0, 0, NULL, 0) == 1);
        REAPS(names[i], &r, "99:0");
    }
    push(&r, nopf(10, LINK));
    struct sqe s = nopf(11, LINK);
    s.ioprio = 1;
    push(&r, s);
    push(&r, nop(12));
    CHECK("check-in-link", enter(r.fd, 3, 0, 0, NULL, 0) == 3);
    REAPS("check-in-link-cqes", &r, "10:-125 11:-22 12:-125");
    drop(&r);
    r = make(4, SUBMIT_ALL, 0);
    s = nop(1);
    s.opcode = 201;
    push(&r, s);
    push(&r, nop(2));
    CHECK("submit-all", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("submit-all-cqes", &r, "1:-22 2:0");
    drop(&r);

    r = make(4, 0, 0);
    push(&r, nop(1));
    push(&r, nop(2));
    sq_u32(&r, r.p.sq_off.array)[1] = 9;
    push(&r, nop(3));
    CHECK("dropped", enter(r.fd, 3, 0, 0, NULL, 0) == 1 && *sq_u32(&r, r.p.sq_off.dropped) == 1 &&
                         *sq_u32(&r, r.p.sq_off.head) == 2);
    REAPS("dropped-cqe", &r, "1:0");
    CHECK("dropped-next", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("dropped-next-cqe", &r, "3:0");
    drop(&r);
}

static void overflow(void) {
    struct ring r = make(2, CQSIZE, 2);
    for (int i = 0; i < 2; i++) {
        push(&r, nop(2 * i + 1));
        push(&r, nop(2 * i + 2));
        CHECK("overflow-submit", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    }
    CHECK("overflow-flag", (*sq_u32(&r, r.p.sq_off.flags) & SQ_CQ_OVERFLOW) &&
                               *sq_u32(&r, r.p.cq_off.overflow) == 0);
    REAPS("overflow-first", &r, "1:0 2:0");
    push(&r, nop(5));
    CHECK("overflow-behind", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("overflow-behind-none", &r, "");
    CHECK("overflow-flush", enter(r.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    REAPS("overflow-flushed", &r, "3:0 4:0");
    CHECK("overflow-still", *sq_u32(&r, r.p.sq_off.flags) & SQ_CQ_OVERFLOW);
    CHECK("overflow-flush-last", enter(r.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    REAPS("overflow-last", &r, "5:0");
    CHECK("overflow-cleared", !(*sq_u32(&r, r.p.sq_off.flags) & SQ_CQ_OVERFLOW));
    drop(&r);
}

static void task_work(void) {
    struct ring r = make(4, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    push(&r, nopf(1, LINK));
    push(&r, nop(2));
    struct sqe s = nop(3);
    s.op_flags = NOP_TW;
    push(&r, s);
    CHECK("defer-submit", enter(r.fd, 3, 0, 0, NULL, 0) == 3);
    REAPS("defer-inline-only", &r, "1:0");
    CHECK("defer-wait", enter(r.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    REAPS("defer-local-work", &r, "3:0 2:0");
    drop(&r);
    r = make(4, 0, 0);
    push(&r, nopf(1, LINK));
    push(&r, nop(2));
    CHECK("tw-submit", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("tw-at-return", &r, "1:0 2:0");
    drop(&r);

    r = make(8, 0, 0);
    push(&r, nopf(1, LINK));
    push(&r, nop(2));
    push(&r, nopf(3, DRAIN));
    push(&r, nop(4));
    CHECK("drain-submit", enter(r.fd, 4, 4, GETEVENTS, NULL, 0) == 4);
    struct timespec pause = {0, 50000000};
    nanosleep(&pause, NULL);
    CHECK("drain-wait", enter(r.fd, 0, 4, GETEVENTS, NULL, 0) == 0);
    REAPS("drain-order", &r, "1:0 2:0 3:0 4:0");
    push(&r, nopf(5, ASYNC));
    push(&r, nop(6));
    CHECK("async-submit", enter(r.fd, 2, 2, GETEVENTS, NULL, 0) == 2);
    nanosleep(&pause, NULL);
    long got[2] = {0, 0};
    uint32_t head = *sq_u32(&r, r.p.cq_off.head), tail = *sq_u32(&r, r.p.cq_off.tail);
    for (int i = 0; head != tail && i < 2; head++, i++) {
        struct cqe *c = (void *)(r.rings + r.p.cq_off.cqes + 16 * (head & 7));
        got[i] = (long)c->user_data * 1000 + c->res;
    }
    *sq_u32(&r, r.p.cq_off.head) = head;
    qsort(got, 2, sizeof got[0], cmpu);
    CHECK("async-both", got[0] == 5000 && got[1] == 6000);
    push(&r, nopf(7, SKIP));
    push(&r, nopf(8, DRAIN));
    CHECK("drain-after-skip", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("drain-after-skip-cqe", &r, "8:-95");
    drop(&r);
}

static void on_alarm(int s) { (void)s; }

static void waits(void) {
    struct ring r = make(4, 0, 0);
    push(&r, nop(1));
    CHECK("wait-enough", enter(r.fd, 1, 1, GETEVENTS, NULL, 0) == 1 &&
                             enter(r.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    reap(&r);
    struct timespec ts = {0, 20000000}, t0, t1;
    struct getevents_arg arg = {.ts = (uintptr_t)&ts};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK_ERR("wait-timeout", enter(r.fd, 0, 1, GETEVENTS | EXT_ARG, &arg, sizeof arg), ETIME);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK("wait-timeout-long", (t1.tv_sec - t0.tv_sec) * 1000000000L + t1.tv_nsec - t0.tv_nsec >=
                                   20000000L);
    ts.tv_nsec = 1;
    CHECK_ERR("wait-abs-past", enter(r.fd, 0, 1, GETEVENTS | EXT_ARG | ABS_TIMER, &arg, sizeof arg),
              ETIME);
    CHECK_ERR("wait-arg-size", enter(r.fd, 0, 1, GETEVENTS | EXT_ARG, &arg, 16), EINVAL);
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = {{0, 0}, {0, 20000}};
    setitimer(ITIMER_REAL, &it, NULL);
    CHECK_ERR("wait-signal", enter(r.fd, 0, 1, GETEVENTS, NULL, 0), EINTR);
    push(&r, nop(9));
    CHECK("wait-count-first", enter(r.fd, 1, 2, GETEVENTS | EXT_ARG, NULL, 0) == 1);
    REAPS("wait-count-cqe", &r, "9:0");
    drop(&r);

    r = make(2, 0, 0);
    struct pollfd pfd = {.fd = r.fd, .events = POLLIN | POLLOUT};
    CHECK("poll-empty", poll(&pfd, 1, 0) == 1 && pfd.revents == POLLOUT);
    push(&r, nop(1));
    push(&r, nop(2));
    CHECK("poll-sq-full", poll(&pfd, 1, 0) == 0);
    CHECK("poll-submit", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    CHECK("poll-cqes", poll(&pfd, 1, 0) == 1 && pfd.revents == (POLLIN | POLLOUT));
    drop(&r);
}

static void registration(void) {
    struct ring r = make(4, 0, 0);
    static unsigned char probe[16 + 8 * 300];
    memset(probe, 0, sizeof probe);
    /* 60 operations: fewer than any kernel with these calls has. */
    CHECK("probe", reg(r.fd, REGISTER_PROBE, probe, 60) == 0 && probe[0] >= 64 && probe[1] == 60 &&
                       probe[16] == 0 && probe[18] == 1 && probe[24] == 1);
    CHECK_ERR("probe-not-zero", reg(r.fd, REGISTER_PROBE, probe, 4), EINVAL);
    CHECK_ERR("probe-too-many", reg(r.fd, REGISTER_PROBE, probe, 257), EINVAL);
    CHECK_ERR("register-unknown", reg(r.fd, 200, NULL, 0), EINVAL);
    CHECK_ERR("register-not-ring", reg(1, REGISTER_PERSONALITY, NULL, 0), EOPNOTSUPP);
    CHECK_ERR("register-bad-fd", reg(999, REGISTER_PERSONALITY, NULL, 0), EBADF);
    CHECK("personality", reg(r.fd, REGISTER_PERSONALITY, NULL, 0) == 1 &&
                             reg(r.fd, REGISTER_PERSONALITY, NULL, 0) == 2 &&
                             reg(r.fd, UNREGISTER_PERSONALITY, NULL, 1) == 0);
    CHECK_ERR("personality-gone", reg(r.fd, UNREGISTER_PERSONALITY, NULL, 1), EINVAL);
    struct sqe s = nop(1);
    s.personality = 2;
    push(&r, s);
    CHECK("personality-use", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("personality-cqe", &r, "1:0");

    int efd = eventfd(0, EFD_NONBLOCK);
    CHECK("eventfd", reg(r.fd, REGISTER_EVENTFD, &efd, 1) == 0);
    CHECK_ERR("eventfd-busy", reg(r.fd, REGISTER_EVENTFD, &efd, 1), EBUSY);
    push(&r, nop(2));
    push(&r, nop(3));
    uint64_t n = 0;
    CHECK("eventfd-count", enter(r.fd, 2, 0, 0, NULL, 0) == 2 && read(efd, &n, 8) == 8 && n == 1);
    reap(&r);
    CHECK("eventfd-unregister", reg(r.fd, UNREGISTER_EVENTFD, NULL, 0) == 0);
    CHECK_ERR("eventfd-unregister-none", reg(r.fd, UNREGISTER_EVENTFD, NULL, 0), ENXIO);
    CHECK_ERR("eventfd-not-eventfd", reg(r.fd, REGISTER_EVENTFD, &r.fd, 1), EINVAL);
    CHECK("eventfd-async", reg(r.fd, REGISTER_EVENTFD_ASYNC, &efd, 1) == 0);
    push(&r, nop(4));
    CHECK("eventfd-async-inline", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    CHECK_ERR("eventfd-async-uncounted", read(efd, &n, 8), EAGAIN);
    reap(&r);
    close(efd);
    drop(&r);

    r = make(4, R_DISABLED | SINGLE_ISSUER, 0);
    push(&r, nop(1));
    CHECK_ERR("disabled", enter(r.fd, 1, 0, 0, NULL, 0), EBADFD);
    CHECK("enable", reg(r.fd, REGISTER_ENABLE_RINGS, NULL, 0) == 0);
    CHECK_ERR("enable-again", reg(r.fd, REGISTER_ENABLE_RINGS, NULL, 0), EBADFD);
    CHECK("enabled", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("enabled-cqe", &r, "1:0");
    drop(&r);

    r = make(4, 0, 0);
    struct rsrc_update u = {.offset = ~0u, .data = (uint64_t)r.fd};
    CHECK("ring-fds", reg(r.fd, REGISTER_RING_FDS, &u, 1) == 1 && u.offset == 0);
    push(&r, nop(1));
    CHECK("ring-fds-enter", enter(0, 1, 0, REGISTERED_RING, NULL, 0) == 1);
    REAPS("ring-fds-cqe", &r, "1:0");
    CHECK_ERR("ring-fds-range", enter(16, 1, 0, REGISTERED_RING, NULL, 0), EINVAL);
    CHECK_ERR("ring-fds-empty", enter(1, 1, 0, REGISTERED_RING, NULL, 0), EBADF);
    CHECK("ring-fds-register", reg(0, REGISTER_PERSONALITY | USE_REGISTERED_RING, NULL, 0) == 1);
    CHECK_ERR("ring-fds-unregister-data", reg(r.fd, UNREGISTER_RING_FDS, &u, 1), EINVAL);
    u.data = 0;
    CHECK("ring-fds-unregister", reg(r.fd, UNREGISTER_RING_FDS, &u, 1) == 1);
    CHECK_ERR("ring-fds-gone", enter(0, 0, 0, REGISTERED_RING, NULL, 0), EBADF);
    drop(&r);
}

/* The fdinfo lines after the common ones (from "SqMask"). */
static void fdinfo(void) {
    struct ring r = make(4, 0, 0);
    push(&r, nop(5));
    CHECK("fdinfo-submit", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    push(&r, inject(6, 3, 0));
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", r.fd);
    int fd = open(path, O_RDONLY);
    static char buf[4096];
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    char *body = strstr(buf, "SqMask");
    CHECK("fdinfo", body != NULL);
    if (body)
        printf("%s", body);
    drop(&r);
}

int main(void) {
    setup_params();
    mappings();
    nops();
    links();
    checks();
    overflow();
    task_work();
    waits();
    registration();
    fdinfo();
    FINISH();
}
