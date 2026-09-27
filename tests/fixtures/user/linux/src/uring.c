/* io_uring through its system calls (io_uring/, include/uapi/linux/io_uring.h):
 * setup and its parameters, the ring mappings, NOP submission and its
 * flags, links, request checks, dropped SQ indices, CQ overflow, deferred
 * task work, drains, waits, polling the ring, registration, registered
 * files and buffers (their tags, updates, allocation, cloning, and the
 * memory charged for them), and fdinfo. Only NOP and FILES_UPDATE requests
 * are used, and only what does not depend on how fast an async worker runs
 * is checked. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
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
struct rsrc_register {
    uint32_t nr, flags;
    uint64_t resv2, data, tags;
};
struct rsrc_update2 {
    uint32_t offset, resv;
    uint64_t data, tags;
    uint32_t nr, resv2;
};
struct index_range {
    uint32_t off, len;
    uint64_t resv;
};
struct clone_buffers {
    uint32_t src_fd, flags, src_off, dst_off, nr, pad[3];
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
enum { REGISTER_BUFFERS = 0, UNREGISTER_BUFFERS = 1, REGISTER_FILES = 2, UNREGISTER_FILES = 3,
       REGISTER_EVENTFD = 4, UNREGISTER_EVENTFD = 5, REGISTER_FILES_UPDATE = 6,
       REGISTER_EVENTFD_ASYNC = 7, REGISTER_PROBE = 8, REGISTER_PERSONALITY = 9,
       UNREGISTER_PERSONALITY = 10, REGISTER_ENABLE_RINGS = 12, REGISTER_FILES2 = 13,
       REGISTER_FILES_UPDATE2 = 14, REGISTER_BUFFERS2 = 15, REGISTER_BUFFERS_UPDATE = 16,
       REGISTER_RING_FDS = 20, UNREGISTER_RING_FDS = 21, REGISTER_FILE_ALLOC_RANGE = 25,
       REGISTER_CLONE_BUFFERS = 30 };
enum { OP_READV = 1, OP_WRITEV = 2, OP_FSYNC = 3, OP_READ_FIXED = 4, OP_WRITE_FIXED = 5,
       OP_SYNC_FILE_RANGE = 8, OP_FALLOCATE = 17, OP_READ = 22, OP_WRITE = 23, OP_FADVISE = 24,
       OP_MADVISE = 25, OP_FTRUNCATE = 55, OP_READV_FIXED = 60, OP_WRITEV_FIXED = 61 };
enum { RWF_HIPRI_ = 0x1, RWF_NOWAIT_ = 0x8, RWF_APPEND_ = 0x10, RWF_NOAPPEND_ = 0x20,
       RWF_ATOMIC_ = 0x40, RWF_NOSIGNAL_ = 0x100 };
enum { OP_FILES_UPDATE = 20, FIXED_FILE = 1, RSRC_SPARSE = 1, SRC_REGISTERED = 1,
       DST_REPLACE = 2, FILES_SKIP = -2 };
#define FILE_INDEX_ALLOC 0xffffffffULL
#define PTR(p) ((uint64_t)(uintptr_t)(p))
#define PAGE 4096
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

/* The fdinfo lines from "UserFiles" up to "PollList". */
static char *user_rsrc(int ring) {
    static char buf[16384], out[4096];
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", ring);
    int fd = open(path, O_RDONLY);
    long n = 0, got;
    while (fd >= 0 && n < (long)sizeof buf - 1 && (got = read(fd, buf + n, sizeof buf - 1 - n)) > 0)
        n += got;
    if (fd >= 0)
        close(fd);
    buf[n] = 0;
    char *a = strstr(buf, "UserFiles:"), *b = strstr(buf, "PollList:");
    out[0] = 0;
    if (a && b && b > a && (size_t)(b - a) < sizeof out) {
        memcpy(out, a, b - a);
        out[b - a] = 0;
    }
    return out;
}

#define TEXT(name, got, want)                                                 \
    do {                                                                      \
        const char *g_ = (got), *w_ = (want);                                 \
        CHECK(name, strcmp(g_, w_) == 0);                                     \
        if (strcmp(g_, w_) != 0)                                              \
            printf("  got \"%s\" want \"%s\"\n", g_, w_);                     \
    } while (0)

/* The path /proc/self/fd/<fd> links to, escaped as seq_file_path escapes
 * " \t\n\\". */
static char *fd_path(int fd) {
    static char bufs[4][1024];
    static int next;
    char path[64], link[256] = {0};
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    if (readlink(path, link, sizeof link - 1) < 0)
        link[0] = 0;
    char *out = bufs[next++ & 3], *o = out;
    for (const char *c = link; *c; c++) {
        if (*c == ' ' || *c == '\t' || *c == '\n' || *c == '\\')
            o += sprintf(o, "\\%03o", (unsigned char)*c);
        else
            *o++ = *c;
    }
    *o = 0;
    return out;
}

/* VmPin of /proc/self/status, in kB (-1 if missing). */
static long vm_pin(void) {
    static char b[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    long n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0)
        close(fd);
    b[n > 0 ? n : 0] = 0;
    char *l = strstr(b, "\nVmPin:");
    return l ? strtol(l + 7, NULL, 10) : -1;
}

static char *anon(size_t len, int prot) {
    return mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static long rsrc2(int fd, unsigned op, uint32_t nr, uint32_t flags, void *data, void *tags) {
    struct rsrc_register rr = {nr, flags, 0, PTR(data), PTR(tags)};
    return reg(fd, op, &rr, sizeof rr);
}
static long update2(int fd, unsigned op, uint32_t off, void *data, void *tags, uint32_t nr) {
    struct rsrc_update2 u = {off, 0, PTR(data), PTR(tags), nr, 0};
    return reg(fd, op, &u, sizeof u);
}

/* Run first, before any ring: a user without CAP_IPC_LOCK is charged its
 * rings' regions and pinned buffers against RLIMIT_MEMLOCK. */
static void memlock(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        struct rlimit rl = {4 * PAGE, 4 * PAGE};
        if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0 ||
            (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0))) {
            printf("FAIL memlock-drop-privileges\n");
            exit(1);
        }
        /* A ring of 4 entries: a page of rings and one of SQEs. */
        struct ring r = make(4, 0, 0);
        CHECK("memlock-ring", r.fd >= 0);
        char *buf = anon(3 * PAGE, PROT_READ | PROT_WRITE);
        long pin = vm_pin();
        struct iovec iov = {buf, 3 * PAGE};
        CHECK_ERR("memlock-buffer-over", reg(r.fd, REGISTER_BUFFERS, &iov, 1), ENOMEM);
        CHECK("memlock-buffer-over-unpinned", vm_pin() == pin);
        iov.iov_len = 2 * PAGE;
        CHECK("memlock-buffer", reg(r.fd, REGISTER_BUFFERS, &iov, 1) == 0 && vm_pin() - pin == 8);
        struct params p;
        memset(&p, 0, sizeof p);
        CHECK_ERR("memlock-second-ring", setup_raw(4, &p), ENOMEM);
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    CHECK("memlock", WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void files(void) {
    struct ring r = make(8, 0, 0);
    int p[2];
    CHECK("files-pipe", pipe(p) == 0);
    int fds[3] = {p[0], -1, p[1]};
    CHECK_ERR("files-no-array", reg(r.fd, REGISTER_FILES, NULL, 3), EFAULT);
    CHECK_ERR("files-none", reg(r.fd, REGISTER_FILES, fds, 0), EINVAL);
    CHECK_ERR("files-too-many", reg(r.fd, REGISTER_FILES, fds, (1u << 20) + 1), EMFILE);
    struct rlimit rl, low;
    getrlimit(RLIMIT_NOFILE, &rl);
    low = rl;
    low.rlim_cur = 2;
    setrlimit(RLIMIT_NOFILE, &low);
    CHECK_ERR("files-nofile", reg(r.fd, REGISTER_FILES, fds, 3), EMFILE);
    setrlimit(RLIMIT_NOFILE, &rl);
    CHECK("files", reg(r.fd, REGISTER_FILES, fds, 3) == 0);
    CHECK_ERR("files-busy", reg(r.fd, REGISTER_FILES, fds, 3), EBUSY);
    char want[1024];
    snprintf(want, sizeof want, "UserFiles:\t3\n    0: %s\n    2: %s\nUserBufs:\t0\n",
             fd_path(p[0]), fd_path(p[1]));
    TEXT("files-fdinfo", user_rsrc(r.fd), want);
    CHECK_ERR("files-unregister-arg", reg(r.fd, UNREGISTER_FILES, NULL, 1), EINVAL);
    CHECK("files-unregister", reg(r.fd, UNREGISTER_FILES, NULL, 0) == 0);
    CHECK_ERR("files-unregister-none", reg(r.fd, UNREGISTER_FILES, NULL, 0), ENXIO);
    TEXT("files-fdinfo-none", user_rsrc(r.fd), "UserFiles:\t0\nUserBufs:\t0\n");
    int ringy[2] = {p[0], r.fd}, bad[2] = {p[0], 999}, sparse[2] = {p[0], -1};
    CHECK_ERR("files-ring", reg(r.fd, REGISTER_FILES, ringy, 2), EBADF);
    CHECK_ERR("files-ring-gone", reg(r.fd, UNREGISTER_FILES, NULL, 0), ENXIO);
    CHECK_ERR("files-bad-fd", reg(r.fd, REGISTER_FILES, bad, 2), EBADF);
    uint64_t tags[3] = {5, 6, 0};
    CHECK_ERR("files-empty-tag", rsrc2(r.fd, REGISTER_FILES2, 2, 0, sparse, tags), EINVAL);
    REAPS("files-empty-tag-none", &r, "");
    CHECK_ERR("files-empty-tag-gone", reg(r.fd, UNREGISTER_FILES, NULL, 0), ENXIO);
    struct rsrc_register rr = {2, 0, 0, PTR(fds), 0};
    CHECK_ERR("files2-size", reg(r.fd, REGISTER_FILES2, &rr, 24), EINVAL);
    CHECK_ERR("files2-none", rsrc2(r.fd, REGISTER_FILES2, 0, 0, fds, NULL), EINVAL);
    CHECK_ERR("files2-flag", rsrc2(r.fd, REGISTER_FILES2, 2, 2, fds, NULL), EINVAL);
    CHECK_ERR("files2-sparse-data", rsrc2(r.fd, REGISTER_FILES2, 2, RSRC_SPARSE, fds, NULL), EINVAL);
    rr.resv2 = 1;
    CHECK_ERR("files2-resv", reg(r.fd, REGISTER_FILES2, &rr, sizeof rr), EINVAL);
    CHECK("files2-sparse", rsrc2(r.fd, REGISTER_FILES2, 3, RSRC_SPARSE, NULL, NULL) == 0);
    TEXT("files2-sparse-fdinfo", user_rsrc(r.fd), "UserFiles:\t3\nUserBufs:\t0\n");
    CHECK("files2-sparse-unregister", reg(r.fd, UNREGISTER_FILES, NULL, 0) == 0);

    /* Tags post as their nodes go: replaced, emptied, or unregistered
     * (from the last slot down); a skipped or emptied slot takes none. */
    int three[3] = {p[0], p[1], p[0]}, one[1] = {p[1]}, skip[2] = {FILES_SKIP, -1};
    int two[2] = {p[0], p[0]};
    uint64_t t3[3] = {16, 32, 0}, t1[1] = {48}, t00[2] = {0, 0}, t7[1] = {7}, t2[2] = {64, 80};
    CHECK("tags", rsrc2(r.fd, REGISTER_FILES2, 3, 0, three, t3) == 0);
    REAPS("tags-none", &r, "");
    CHECK("tags-replace", update2(r.fd, REGISTER_FILES_UPDATE2, 0, one, t1, 1) == 1);
    REAPS("tags-replace-cqe", &r, "16:0");
    CHECK("tags-skip-empty", update2(r.fd, REGISTER_FILES_UPDATE2, 0, skip, t00, 2) == 2);
    REAPS("tags-skip-empty-cqe", &r, "32:0");
    CHECK_ERR("tags-skip-tagged", update2(r.fd, REGISTER_FILES_UPDATE2, 0, skip, t7, 1), EINVAL);
    CHECK("tags-fill", update2(r.fd, REGISTER_FILES_UPDATE2, 1, two, t2, 2) == 2);
    REAPS("tags-fill-none", &r, "");
    CHECK("tags-unregister", reg(r.fd, UNREGISTER_FILES, NULL, 0) == 0);
    REAPS("tags-unregister-cqes", &r, "80:0 64:0 48:0");

    struct rsrc_update u = {0, 0, PTR(fds)};
    CHECK_ERR("update-none", reg(r.fd, REGISTER_FILES_UPDATE, &u, 0), EINVAL);
    CHECK_ERR("update-no-table", reg(r.fd, REGISTER_FILES_UPDATE, &u, 1), ENXIO);
    u.resv = 1;
    CHECK_ERR("update-resv", reg(r.fd, REGISTER_FILES_UPDATE, &u, 1), EINVAL);
    CHECK("update-sparse", rsrc2(r.fd, REGISTER_FILES2, 2, RSRC_SPARSE, NULL, NULL) == 0);
    u.resv = 0;
    u.offset = 1;
    CHECK("update", reg(r.fd, REGISTER_FILES_UPDATE, &u, 1) == 1);
    CHECK_ERR("update-past", reg(r.fd, REGISTER_FILES_UPDATE, &u, 2), EINVAL);
    u.offset = ~0u;
    CHECK_ERR("update-wrap", reg(r.fd, REGISTER_FILES_UPDATE, &u, 2), EOVERFLOW);
    struct rsrc_update2 u2 = {0, 0, PTR(fds), 0, 1, 0};
    CHECK_ERR("update2-size", reg(r.fd, REGISTER_FILES_UPDATE2, &u2, 16), EINVAL);
    u2.nr = 0;
    CHECK_ERR("update2-none", reg(r.fd, REGISTER_FILES_UPDATE2, &u2, sizeof u2), EINVAL);
    u2.nr = 1;
    u2.resv2 = 1;
    CHECK_ERR("update2-resv", reg(r.fd, REGISTER_FILES_UPDATE2, &u2, sizeof u2), EINVAL);
    /* A bad descriptor ends an update; its slot was emptied first. */
    CHECK("update-bad-second", update2(r.fd, REGISTER_FILES_UPDATE2, 0, bad, NULL, 2) == 1);
    snprintf(want, sizeof want, "UserFiles:\t2\n    0: %s\nUserBufs:\t0\n", fd_path(p[0]));
    TEXT("update-bad-second-fdinfo", user_rsrc(r.fd), want);
    CHECK_ERR("update-bad", update2(r.fd, REGISTER_FILES_UPDATE2, 0, bad + 1, NULL, 1), EBADF);
    TEXT("update-bad-emptied", user_rsrc(r.fd), "UserFiles:\t2\nUserBufs:\t0\n");
    CHECK("update-unregister", reg(r.fd, UNREGISTER_FILES, NULL, 0) == 0);

    /* seq_file_path's escapes. */
    char name[] = "/tmp/uring a\\b XXXXXX";
    int f = mkstemp(name);
    CHECK("files-escape", f >= 0 && reg(r.fd, REGISTER_FILES, &f, 1) == 0);
    snprintf(want, sizeof want, "UserFiles:\t1\n    0: %s\nUserBufs:\t0\n", fd_path(f));
    TEXT("files-escape-fdinfo", user_rsrc(r.fd), want);
    CHECK("files-escaped", strstr(want, "uring\\040a\\134b\\040") != NULL);
    unlink(name);
    close(f);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void file_ops(void) {
    /* A registered file stays open while its node lives. */
    struct ring r = make(8, 0, 0);
    int p[2];
    CHECK("held-pipe", pipe2(p, O_NONBLOCK) == 0);
    CHECK("held", reg(r.fd, REGISTER_FILES, &p[1], 1) == 0);
    close(p[1]);
    char c;
    CHECK_ERR("held-open", read(p[0], &c, 1), EAGAIN);
    CHECK("held-unregister", reg(r.fd, UNREGISTER_FILES, NULL, 0) == 0);
    CHECK("held-closed", read(p[0], &c, 1) == 0);

    /* io_nop's lookups: a missing file or buffer fails the request. */
    CHECK("lookup-files", reg(r.fd, REGISTER_FILES, &p[0], 1) == 0);
    struct sqe s = nopf(1, LINK);
    s.op_flags = NOP_FILE | NOP_FIXED_FILE;
    push(&r, s);
    push(&r, nop(2));
    s.user_data = 3;
    s.fd = 1;
    push(&r, s);
    push(&r, nop(4));
    CHECK("lookup-file", enter(r.fd, 4, 0, 0, NULL, 0) == 4);
    REAPS("lookup-file-cqes", &r, "1:0 3:0 2:0 4:-125");
    char *buf = anon(PAGE, PROT_READ | PROT_WRITE);
    struct iovec iov = {buf, PAGE};
    CHECK("lookup-buffers", reg(r.fd, REGISTER_BUFFERS, &iov, 1) == 0);
    s = nopf(5, LINK);
    s.op_flags = NOP_FIXED_BUFFER;
    push(&r, s);
    push(&r, nop(6));
    s.user_data = 7;
    s.buf_index = 1;
    push(&r, s);
    push(&r, nop(8));
    CHECK("lookup-buffer", enter(r.fd, 4, 0, 0, NULL, 0) == 4);
    REAPS("lookup-buffer-cqes", &r, "5:0 7:0 6:0 8:-125");
    drop(&r);

    /* A node a request uses goes, and posts its tag, when the request is
     * freed: on this ring, as its task work runs in a wait. */
    r = make(4, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    uint64_t tag = 119;
    int empty = -1;
    CHECK("in-use", rsrc2(r.fd, REGISTER_FILES2, 1, 0, &p[0], &tag) == 0);
    s = nop(1);
    s.op_flags = NOP_FILE | NOP_FIXED_FILE | NOP_TW;
    push(&r, s);
    CHECK("in-use-submit", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    CHECK("in-use-update", update2(r.fd, REGISTER_FILES_UPDATE2, 0, &empty, NULL, 1) == 1);
    REAPS("in-use-held", &r, "");
    CHECK("in-use-wait", enter(r.fd, 0, 1, GETEVENTS, NULL, 0) == 0);
    REAPS("in-use-released", &r, "1:0 119:0");
    drop(&r);

    /* IORING_OP_FILES_UPDATE. */
    r = make(8, 0, 0);
    int fds[4] = {p[0], p[0], p[0], p[0]};
    struct sqe up = nop(1);
    up.opcode = OP_FILES_UPDATE;
    up.addr = PTR(fds);
    push(&r, up);
    CHECK("op-update-no-slots", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    up.user_data = 2;
    up.len = 1;
    up.flags = FIXED_FILE;
    push(&r, up);
    CHECK("op-update-fixed", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    up.user_data = 3;
    up.flags = 0;
    up.op_flags = 1;
    push(&r, up);
    CHECK("op-update-flags", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("op-update-prep", &r, "1:-22 2:-22 3:-22");
    up.user_data = 4;
    up.op_flags = 0;
    up.flags = LINK;
    push(&r, up);
    push(&r, nop(5));
    CHECK("op-update-no-table", enter(r.fd, 2, 0, 0, NULL, 0) == 2);
    REAPS("op-update-no-table-cqes", &r, "4:-6 5:-125");
    CHECK("op-update-sparse", rsrc2(r.fd, REGISTER_FILES2, 4, RSRC_SPARSE, NULL, NULL) == 0);
    up.user_data = 6;
    up.flags = 0;
    up.off = 1;
    up.len = 2;
    push(&r, up);
    CHECK("op-update", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("op-update-cqe", &r, "6:2");
    /* The hint is past slot 2: slot 3, then from the start slot 0, then
     * none. */
    up.user_data = 7;
    up.off = FILE_INDEX_ALLOC;
    up.len = 3;
    push(&r, up);
    CHECK("op-alloc", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("op-alloc-cqe", &r, "7:2");
    CHECK("op-alloc-slots", fds[0] == 3 && fds[1] == 0 && fds[2] == p[0]);
    up.user_data = 8;
    up.len = 1;
    fds[0] = p[0];
    push(&r, up);
    CHECK("op-alloc-full", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("op-alloc-full-cqe", &r, "8:-23");

    /* IORING_REGISTER_FILE_ALLOC_RANGE. */
    struct index_range range = {0, 0, 0};
    CHECK_ERR("range-no-arg", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, NULL, 0), EINVAL);
    CHECK_ERR("range-nr", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 1), EINVAL);
    CHECK("range-unregister", reg(r.fd, UNREGISTER_FILES, NULL, 0) == 0);
    CHECK("range-empty", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 0) == 0);
    range.len = 1;
    CHECK_ERR("range-no-table", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 0), EINVAL);
    CHECK("range-sparse", rsrc2(r.fd, REGISTER_FILES2, 8, RSRC_SPARSE, NULL, NULL) == 0);
    range = (struct index_range){~0u, 2, 0};
    CHECK_ERR("range-wrap", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 0), EOVERFLOW);
    range = (struct index_range){6, 3, 0};
    CHECK_ERR("range-past", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 0), EINVAL);
    range = (struct index_range){2, 3, 1};
    CHECK_ERR("range-resv", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 0), EINVAL);
    range.resv = 0;
    CHECK("range", reg(r.fd, REGISTER_FILE_ALLOC_RANGE, &range, 0) == 0);
    up.user_data = 9;
    up.len = 4;
    for (int i = 0; i < 4; i++)
        fds[i] = p[0];
    push(&r, up);
    CHECK("range-alloc", enter(r.fd, 1, 0, 0, NULL, 0) == 1);
    REAPS("range-alloc-cqe", &r, "9:3");
    CHECK("range-alloc-slots", fds[0] == 2 && fds[1] == 3 && fds[2] == 4 && fds[3] == p[0]);
    close(p[0]);
    drop(&r);
}

static void buffers(void) {
    struct ring r = make(8, 0, 0);
    char *buf = anon(3 * PAGE, PROT_READ | PROT_WRITE);
    char *ro = anon(PAGE, PROT_READ);
    /* Pages 1 and 3 unmapped: a hole, and a range running into one. */
    char *holes = anon(4 * PAGE, PROT_READ | PROT_WRITE);
    munmap(holes + PAGE, PAGE);
    munmap(holes + 3 * PAGE, PAGE);
    long pin = vm_pin();
    struct iovec iov[2] = {{buf + 16, 0x1ff0}, {NULL, 0}};
    CHECK_ERR("bufs-no-array", reg(r.fd, REGISTER_BUFFERS, NULL, 1), EFAULT);
    CHECK_ERR("bufs-none", reg(r.fd, REGISTER_BUFFERS, iov, 0), EINVAL);
    CHECK_ERR("bufs-too-many", reg(r.fd, REGISTER_BUFFERS, iov, (1u << 14) + 1), EINVAL);
    CHECK("bufs", reg(r.fd, REGISTER_BUFFERS, iov, 2) == 0);
    CHECK_ERR("bufs-busy", reg(r.fd, REGISTER_BUFFERS, iov, 2), EBUSY);
    char want[512];
    snprintf(want, sizeof want, "UserFiles:\t0\nUserBufs:\t2\n    0: 0x%llx/8176\n    1: <none>\n",
             (unsigned long long)PTR(buf + 16));
    TEXT("bufs-fdinfo", user_rsrc(r.fd), want);
    CHECK("bufs-pinned", vm_pin() - pin == 8);
    CHECK_ERR("bufs-unregister-arg", reg(r.fd, UNREGISTER_BUFFERS, NULL, 1), EINVAL);
    CHECK("bufs-unregister", reg(r.fd, UNREGISTER_BUFFERS, NULL, 0) == 0);
    CHECK_ERR("bufs-unregister-none", reg(r.fd, UNREGISTER_BUFFERS, NULL, 0), ENXIO);
    CHECK("bufs-unpinned", vm_pin() == pin);
    struct {
        const char *name;
        void *base;
        size_t len;
        int err;
    } bad[] = {
        {"bufs-len-no-base", NULL, 5, EFAULT},
        {"bufs-base-no-len", buf, 0, EFAULT},
        {"bufs-over-1g", buf, (1u << 30) + 1, EFAULT},
        /* A 32-bit address cannot wrap the kernel's unsigned long. */
        {"bufs-wrap", (void *)(uintptr_t)-PAGE, 1, sizeof(void *) == 8 ? EOVERFLOW : EFAULT},
        {"bufs-read-only", ro, PAGE, EFAULT},
        {"bufs-unmapped", holes + PAGE, PAGE, EFAULT},
        {"bufs-into-hole", holes + 2 * PAGE, 2 * PAGE, EFAULT},
        {"bufs-negative", buf, (size_t)1 << (8 * sizeof(size_t) - 1), EINVAL},
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        struct iovec two[2] = {{buf, PAGE}, {bad[i].base, bad[i].len}};
        CHECK_ERR(bad[i].name, reg(r.fd, REGISTER_BUFFERS, two, 2), bad[i].err);
        CHECK_ERR(bad[i].name, reg(r.fd, UNREGISTER_BUFFERS, NULL, 0), ENXIO);
        CHECK(bad[i].name, vm_pin() == pin);
    }

    struct iovec two[2] = {{buf, PAGE}, {buf + PAGE, PAGE}};
    struct iovec third = {buf + 2 * PAGE, PAGE}, none = {NULL, 0};
    struct iovec mixed[2] = {{buf, PAGE}, {NULL, 1}};
    uint64_t tags[2] = {256, 0}, tag = 512;
    CHECK_ERR("bufs2-sparse-data", rsrc2(r.fd, REGISTER_BUFFERS2, 2, RSRC_SPARSE, two, tags), EINVAL);
    CHECK("bufs2", rsrc2(r.fd, REGISTER_BUFFERS2, 2, 0, two, tags) == 0 && vm_pin() - pin == 8);
    CHECK("bufs-replace", update2(r.fd, REGISTER_BUFFERS_UPDATE, 0, &third, &tag, 1) == 1);
    REAPS("bufs-replace-cqe", &r, "256:0");
    CHECK("bufs-replace-pinned", vm_pin() - pin == 8);
    CHECK_ERR("bufs-empty-tagged", update2(r.fd, REGISTER_BUFFERS_UPDATE, 1, &none, &tag, 1), EINVAL);
    CHECK("bufs-empty", update2(r.fd, REGISTER_BUFFERS_UPDATE, 1, &none, NULL, 1) == 1 &&
                            vm_pin() - pin == 4);
    snprintf(want, sizeof want, "UserFiles:\t0\nUserBufs:\t2\n    0: 0x%llx/4096\n    1: <none>\n",
             (unsigned long long)PTR(buf + 2 * PAGE));
    TEXT("bufs-update-fdinfo", user_rsrc(r.fd), want);
    CHECK_ERR("bufs-update-past", update2(r.fd, REGISTER_BUFFERS_UPDATE, 2, &none, NULL, 1), EINVAL);
    CHECK("bufs-update-bad-second", update2(r.fd, REGISTER_BUFFERS_UPDATE, 0, mixed, NULL, 2) == 1);
    REAPS("bufs-update-bad-second-cqe", &r, "512:0");
    CHECK("bufs2-unregister", reg(r.fd, UNREGISTER_BUFFERS, NULL, 0) == 0 && vm_pin() == pin);
    REAPS("bufs2-unregister-none", &r, "");
    drop(&r);
}

static void clones(void) {
    struct ring src = make(4, 0, 0), dst = make(4, 0, 0), none = make(4, 0, 0);
    char *buf = anon(2 * PAGE, PROT_READ | PROT_WRITE);
    long pin = vm_pin();
    struct iovec two[2] = {{buf, PAGE}, {buf + PAGE, PAGE}};
    uint64_t tags[2] = {1, 2};
    CHECK("clone-source", rsrc2(src.fd, REGISTER_BUFFERS2, 2, 0, two, tags) == 0);
    struct clone_buffers cb = {src.fd};
    CHECK_ERR("clone-no-arg", reg(dst.fd, REGISTER_CLONE_BUFFERS, NULL, 1), EINVAL);
    CHECK_ERR("clone-nr", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 0), EINVAL);
    cb.flags = 4;
    CHECK_ERR("clone-flag", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), EINVAL);
    cb.flags = 0;
    cb.pad[2] = 1;
    CHECK_ERR("clone-pad", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), EINVAL);
    cb.pad[2] = 0;
    int p[2];
    CHECK("clone-pipe", pipe(p) == 0);
    cb.src_fd = p[0];
    CHECK_ERR("clone-not-ring", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), EOPNOTSUPP);
    cb.src_fd = 999;
    CHECK_ERR("clone-bad-fd", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), EBADF);
    cb.src_fd = none.fd;
    CHECK_ERR("clone-no-buffers", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), ENXIO);
    struct {
        const char *name;
        uint32_t src_off, dst_off, nr;
        int err;
    } bad[] = {
        {"clone-offsets-no-count", 1, 0, 0, EINVAL},
        {"clone-too-many", 0, 0, 3, EINVAL},
        {"clone-past-source", 1, 0, 2, EOVERFLOW},
        {"clone-past-max", 0, 1u << 14, 1, EINVAL},
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        cb = (struct clone_buffers){src.fd, 0, bad[i].src_off, bad[i].dst_off, bad[i].nr};
        CHECK_ERR(bad[i].name, reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), bad[i].err);
    }
    /* All of them, pinned once, without tags. */
    cb = (struct clone_buffers){src.fd};
    CHECK("clone", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1) == 0 && vm_pin() - pin == 8);
    char want[512];
    snprintf(want, sizeof want, "%s", user_rsrc(src.fd));
    TEXT("clone-fdinfo", user_rsrc(dst.fd), want);
    CHECK_ERR("clone-busy", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1), EBUSY);
    cb = (struct clone_buffers){src.fd, DST_REPLACE, 0, 1, 1};
    CHECK("clone-replace", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1) == 0);
    snprintf(want, sizeof want,
             "UserFiles:\t0\nUserBufs:\t2\n    0: 0x%llx/4096\n    1: 0x%llx/4096\n",
             (unsigned long long)PTR(buf), (unsigned long long)PTR(buf));
    TEXT("clone-replace-fdinfo", user_rsrc(dst.fd), want);
    /* A buffer goes as its last holder lets go. */
    CHECK("clone-source-unregister", reg(src.fd, UNREGISTER_BUFFERS, NULL, 0) == 0 &&
                                         vm_pin() - pin == 4);
    REAPS("clone-source-tags", &src, "2:0 1:0");
    CHECK("clone-unregister", reg(dst.fd, UNREGISTER_BUFFERS, NULL, 0) == 0 && vm_pin() == pin);
    REAPS("clone-no-tags", &dst, "");
    /* By registered index; and a ring into itself. */
    struct iovec one = {buf, PAGE};
    CHECK("clone-source-again", reg(src.fd, REGISTER_BUFFERS, &one, 1) == 0);
    struct rsrc_update u = {5, 0, (uint64_t)src.fd};
    CHECK("clone-ring-fd", reg(src.fd, REGISTER_RING_FDS, &u, 1) == 1);
    cb = (struct clone_buffers){5, SRC_REGISTERED};
    CHECK("clone-registered", reg(dst.fd, REGISTER_CLONE_BUFFERS, &cb, 1) == 0);
    cb = (struct clone_buffers){src.fd, DST_REPLACE, 0, 1, 1};
    CHECK("clone-self", reg(src.fd, REGISTER_CLONE_BUFFERS, &cb, 1) == 0 && vm_pin() - pin == 4);
    TEXT("clone-self-fdinfo", user_rsrc(src.fd), want);
    close(p[0]);
    close(p[1]);
    drop(&src);
    drop(&dst);
    drop(&none);
}

/* A transfer's SQE. */
static struct sqe xfer(uint8_t op, int fd, void *addr, uint32_t len, int64_t off, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = op;
    s.fd = fd;
    s.addr = PTR(addr);
    s.len = len;
    s.off = (uint64_t)off;
    return s;
}

/* Queues an SQE, submits every queued one, waits for n CQEs, and reaps. */
static char *one(struct ring *r, struct sqe s, unsigned n) {
    push(r, s);
    uint32_t queued = *sq_u32(r, r->p.sq_off.tail) - *sq_u32(r, r->p.sq_off.head);
    long got = enter(r->fd, queued, n, GETEVENTS, NULL, 0);
    if (got != (long)queued)
        printf("  enter returned %ld errno %d\n", got, errno);
    return reap(r);
}

#define ONE(name, r, s, n, want)                                              \
    do {                                                                      \
        char *got_ = one(r, s, n);                                            \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

static int file_with(const char *text) {
    char name[] = "/tmp/uring-rw-XXXXXX";
    int fd = mkstemp(name);
    unlink(name);
    if (fd >= 0 && write(fd, text, strlen(text)) != (long)strlen(text))
        return -1;
    return fd;
}

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
    memlock();
    setup_params();
    mappings();
    nops();
    links();
    checks();
    overflow();
    task_work();
    waits();
    registration();
    files();
    file_ops();
    buffers();
    clones();
    transfers();
    transfer_checks();
    waiting();
    sync_ops();
    fdinfo();
    FINISH();
}
