/* Shared helpers for the io_uring fixtures (uring.c, uringio.c): the
 * io_uring structures and constants (include/uapi/linux/io_uring.h), the
 * system calls, a ring mapped as liburing maps it, SQE builders, CQE
 * reaping, and the checks they share. */
#ifndef RAX_FIXTURE_URING_H
#define RAX_FIXTURE_URING_H
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
       OP_MADVISE = 25, OP_FTRUNCATE = 55, OP_READV_FIXED = 60, OP_WRITEV_FIXED = 61,
       OP_OPENAT = 18, OP_CLOSE = 19, OP_STATX = 21, OP_OPENAT2 = 28, OP_RENAMEAT = 35,
       OP_UNLINKAT = 36, OP_MKDIRAT = 37, OP_SYMLINKAT = 38, OP_LINKAT = 39,
       OP_FIXED_FD_INSTALL = 54, OP_PIPE = 62, OP_FSETXATTR = 41, OP_SETXATTR = 42,
       OP_FGETXATTR = 43, OP_GETXATTR = 44 };
#if defined(__aarch64__) || defined(__arm__)
#define RAW_LARGEFILE 0400000
#else
#define RAW_LARGEFILE 0100000
#endif
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

static struct sqe path_op(uint8_t op, int fd, const char *a, const void *b, uint32_t len,
                          uint32_t flags, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = op;
    s.fd = fd;
    s.addr = PTR(a);
    s.off = PTR(b);
    s.len = len;
    s.op_flags = flags;
    return s;
}

/* Submits one SQE expected to fail its preparation, and reaps. */
static char *prep_fails(struct ring *r, struct sqe s) {
    push(r, s);
    if (enter(r->fd, 1, 0, 0, NULL, 0) != 1)
        printf("  enter failed errno %d\n", errno);
    return reap(r);
}

#define PREP(name, r, s, want)                                                \
    do {                                                                      \
        char *got_ = prep_fails(r, s);                                        \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

/* The lowest free descriptor. */
static int lowest_free(void) {
    int fd = dup(0);
    close(fd);
    return fd;
}

static int cqe_res(char *text) {
    char *colon = strchr(text, ':');
    return colon ? atoi(colon + 1) : -99999;
}

#endif
