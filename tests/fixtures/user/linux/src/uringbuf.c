/* io_uring's provided buffers (io_uring/kbuf.c, Linux 6.19): PROVIDE_BUFFERS
 * and REMOVE_BUFFERS, buffer rings (IORING_REGISTER_PBUF_RING, their
 * mappings, IOU_PBUF_RING_INC, IORING_REGISTER_PBUF_STATUS, the memlock
 * charge), and the requests that select from them: READ, READV, RECV,
 * RECVMSG, SEND, bundles (with the message state a ring caches),
 * multishot RECV and RECVMSG (struct io_uring_recvmsg_out), and
 * READ_MULTISHOT. Requests the async workers run are waited for alone. */
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "uring.h"

enum { OP_SENDMSG = 9, OP_RECVMSG = 10, OP_SEND = 26, OP_RECV = 27, OP_PROVIDE_BUFFERS = 31,
       OP_REMOVE_BUFFERS = 32, OP_READ_MULTISHOT = 49 };
enum { REGISTER_PBUF_RING = 22, UNREGISTER_PBUF_RING = 23, REGISTER_PBUF_STATUS = 26 };
enum { RING_MMAP = 1, RING_INC = 2 };
enum { RECV_MULTISHOT = 1 << 1, BUNDLE = 1 << 4 };
#define OFF_PBUF_RING 0x80000000ULL

struct buf_reg {
    uint64_t ring_addr;
    uint32_t ring_entries;
    uint16_t bgid, flags;
    uint64_t resv[3];
};
struct buf_status {
    uint32_t buf_group, head;
    uint32_t resv[8];
};
struct ubuf {
    uint64_t addr;
    uint32_t len;
    uint16_t bid, resv;
};
struct recvmsg_out {
    uint32_t namelen, controllen, payloadlen, flags;
};

static struct sqe provide(int n, void *addr, uint32_t len, uint16_t group, uint64_t bid,
                          uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_PROVIDE_BUFFERS;
    s.fd = n;
    s.addr = PTR(addr);
    s.len = len;
    s.off = bid;
    s.buf_index = group;
    return s;
}

static struct sqe remove_bufs(int n, uint16_t group, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = OP_REMOVE_BUFFERS;
    s.fd = n;
    s.buf_index = group;
    return s;
}

/* A request of len bytes on fd with a buffer of group. */
static struct sqe sel(uint8_t op, int fd, uint32_t len, uint16_t group, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = op;
    s.flags = BUFFER_SELECT;
    s.fd = fd;
    s.len = len;
    s.buf_index = group;
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

/* Queues an SQE, submits, waits for n CQEs, and reaps with the flags. */
static char *onef(struct ring *r, struct sqe s, unsigned n) {
    push(r, s);
    uint32_t queued = *sq_u32(r, r->p.sq_off.tail) - *sq_u32(r, r->p.sq_off.head);
    long got = enter(r->fd, queued, n, GETEVENTS, NULL, 0);
    if (got != (long)queued)
        printf("  enter returned %ld errno %d\n", got, errno);
    return reapf(r);
}

#define ONEF(name, r, s, n, want)                                             \
    do {                                                                      \
        char *got_ = onef(r, s, n);                                           \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

static void put(int fd, const char *s) {
    if (write(fd, s, strlen(s)) != (long)strlen(s))
        printf("  write failed errno %d\n", errno);
}

/* Reads what fd has (up to n bytes) as a string. */
static char *get(int fd, size_t n) {
    static char buf[256];
    long got = read(fd, buf, n < sizeof buf - 1 ? n : sizeof buf - 1);
    buf[got > 0 ? got : 0] = 0;
    return buf;
}

static long pbuf(int fd, unsigned op, void *ring, uint32_t entries, uint16_t bgid,
                 uint16_t flags) {
    struct buf_reg b = {PTR(ring), entries, bgid, flags, {0, 0, 0}};
    return reg(fd, op, &b, 1);
}

/* The ring head of group, or -errno. */
static long head(int fd, uint32_t group) {
    struct buf_status s = {group, 0, {0}};
    return reg(fd, REGISTER_PBUF_STATUS, &s, 1) == 0 ? (long)s.head : -errno;
}

static void ring_buf(struct ubuf *ring, unsigned index, void *addr, uint32_t len, uint16_t bid) {
    ring[index].addr = PTR(addr);
    ring[index].len = len;
    ring[index].bid = bid;
}

/* The tail is the first entry's resv. */
static void set_tail(struct ubuf *ring, uint16_t tail) {
    __atomic_store_n(&ring[0].resv, tail, __ATOMIC_RELEASE);
}

static void *pbuf_map(int fd, size_t len, unsigned bgid) {
    return mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                (off_t)(OFF_PBUF_RING | (uint64_t)bgid << 16));
}

static int tmp_file(const char *text, int flags) {
    char name[] = "/tmp/uringbuf-XXXXXX";
    int fd = mkstemp(name);
    if (fd >= 0 && write(fd, text, strlen(text)) != (long)strlen(text))
        printf("  write failed errno %d\n", errno);
    int other = open(name, flags);
    unlink(name);
    close(fd);
    return other;
}

/* Run first, in a child of its own user: a ring's pages are charged
 * against RLIMIT_MEMLOCK without CAP_IPC_LOCK (io_create_region). */
static void charge(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        struct rlimit rl = {3 * PAGE, 3 * PAGE};
        if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0 ||
            (getuid() == 0 && (setgid(65532) != 0 || setuid(65532) != 0))) {
            printf("FAIL charge-drop-privileges\n");
            exit(1);
        }
        /* An 8-entry ring: a page of rings, one of SQEs; a ring of 256
         * buffers is a page more. */
        struct ring r = make(8, 0, 0);
        char *ring = anon(PAGE, PROT_READ | PROT_WRITE);
        CHECK("charge-user-ring", pbuf(r.fd, REGISTER_PBUF_RING, ring, 256, 1, 0) == 0);
        CHECK_ERR("charge-over", pbuf(r.fd, REGISTER_PBUF_RING, NULL, 256, 2, RING_MMAP), ENOMEM);
        CHECK("charge-unregister", pbuf(r.fd, UNREGISTER_PBUF_RING, NULL, 0, 1, 0) == 0);
        CHECK("charge-uncharged", pbuf(r.fd, REGISTER_PBUF_RING, NULL, 256, 2, RING_MMAP) == 0);
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    CHECK("charge", WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void legacy(void) {
    struct ring r = make(16, SUBMIT_ALL, 0);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    /* io_provide_buffers_prep: 1 to 65536 buffers (the descriptor field,
     * sign-extended), a length, a range that neither wraps nor leaves user
     * space, IDs within 16 bits; no flags or file slot. */
    push(&r, provide(0, mem, 16, 1, 0, 1));
    push(&r, provide(65537, mem, 16, 1, 0, 2));
    push(&r, provide(-1, mem, 16, 1, 0, 3));
    push(&r, provide(1, mem, 0, 1, 0, 4));
    struct sqe s = provide(1, mem, 16, 1, 0, 5);
    s.addr = ~0ULL - 8;
    push(&r, s);
    s = provide(1, mem, 16, 1, 0, 6);
    s.addr = 0xffffffff00000000ULL;
    push(&r, s);
    push(&r, provide(1, mem, 16, 1, 0x10000, 7));
    push(&r, provide(2, mem, 16, 1, 0xffff, 8));
    s = provide(1, mem, 16, 1, 0, 9);
    s.op_flags = 1;
    push(&r, s);
    s = provide(1, mem, 16, 1, 0, 10);
    s.file_index = 1;
    push(&r, s);
    SUB("legacy-provide-prep", &r, "1:-7 2:-7 3:-7 4:-22 5:-75 6:-14 7:-7 8:-22 9:-22 10:-22");
    push(&r, provide(4, mem, 16, 1, 10, 11));
    SUB("legacy-provide", &r, "11:0");
    /* io_remove_buffers_prep: a count of 1 to 65536 and nothing else; the
     * group must exist, and the removal says how many went. An emptied
     * group stays. */
    s = remove_bufs(1, 1, 12);
    s.addr = PTR(mem);
    push(&r, s);
    s = remove_bufs(1, 1, 13);
    s.len = 1;
    push(&r, s);
    s = remove_bufs(1, 1, 14);
    s.off = 1;
    push(&r, s);
    s = remove_bufs(1, 1, 15);
    s.op_flags = 1;
    push(&r, s);
    push(&r, remove_bufs(0, 1, 16));
    push(&r, remove_bufs(65537, 1, 17));
    push(&r, remove_bufs(1, 2, 18));
    push(&r, remove_bufs(3, 1, 19));
    push(&r, remove_bufs(3, 1, 20));
    push(&r, remove_bufs(1, 1, 21));
    SUB("legacy-remove", &r, "12:-22 13:-22 14:-22 15:-22 16:-22 17:-22 18:-2 19:3 20:1 21:0");
    /* io_add_buffers: at most 65535 in a group; a provision adding none
     * fails, one adding some succeeds. */
    push(&r, provide(65535, mem, 1, 2, 0, 22));
    push(&r, provide(1, mem, 1, 2, 0, 23));
    SUB("legacy-full", &r, "22:0 23:-75");
    push(&r, remove_bufs(2, 2, 24));
    push(&r, provide(3, mem, 1, 2, 0, 25));
    push(&r, remove_bufs(65536, 2, 26));
    SUB("legacy-full-some", &r, "24:2 25:0 26:65535");
    drop(&r);
}

static void reads(void) {
    struct ring r = make(8, 0, 0);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int p[2];
    CHECK("reads-pipe", pipe(p) == 0);
    push(&r, provide(4, mem, 16, 1, 10, 1));
    SUB("reads-provide", &r, "1:0");
    put(p[1], "abcdefghij");
    /* io_buffer_select: the group's first buffer, the length asked for at
     * most its own (0: all of it); the completion reports its ID. */
    push(&r, sel(OP_READ, p[0], 4, 1, 2));
    push(&r, sel(OP_READ, p[0], 0, 1, 3));
    SUB("reads-select", &r, "2:4/a0001 3:6/b0001");
    CHECK("reads-data", memcmp(mem, "abcd", 4) == 0 && memcmp(mem + 16, "efghij", 6) == 0);
    /* Waiting, a read keeps its buffer (io_read hands back only a
     * ring's): 12 is not in the group while it waits. */
    push(&r, sel(OP_READ, p[0], 0, 1, 4));
    SUB("reads-waits", &r, "");
    push(&r, remove_bufs(8, 1, 5));
    SUB("reads-kept", &r, "5:1");
    put(p[1], "klm");
    REAPF("reads-woken", &r, "4:3/c0001");
    /* An empty group, a missing one: ENOBUFS. */
    push(&r, sel(OP_READ, p[0], 0, 1, 6));
    push(&r, sel(OP_READ, p[0], 0, 9, 7));
    SUB("reads-enobufs", &r, "6:-105 7:-105");
    /* Failing, a read reports the buffer it took, which is gone
     * (io_req_defer_failed): the write end cannot be read. */
    push(&r, provide(2, mem, 16, 1, 20, 8));
    push(&r, sel(OP_READ, p[1], 0, 1, 9));
    SUB("reads-failed", &r, "8:0 9:-9/140001");
    /* io_iov_buffer_select_prep: READV takes one vector, for its length. */
    struct iovec iov = {NULL, 3};
    struct sqe s = sel(OP_READV, p[0], 2, 1, 10);
    s.addr = PTR(&iov);
    PREP("reads-readv-two", &r, s, "10:-22");
    put(p[1], "nopqr");
    s = sel(OP_READV, p[0], 1, 1, 11);
    s.addr = PTR(&iov);
    push(&r, s);
    SUB("reads-readv", &r, "11:3/150001");
    CHECK("reads-readv-data", memcmp(mem + 16, "nop", 3) == 0);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void handback(void) {
    struct ring r = make(8, 0, 0);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    char *big = anon(1 << 16, PROT_READ | PROT_WRITE);
    int sv[2], p[2];
    CHECK("handback-socketpair", socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
    CHECK("handback-pipe", pipe(p) == 0);
    push(&r, provide(2, mem, 16, 1, 30, 1));
    SUB("handback-provide", &r, "1:0");
    /* io_recv's -EAGAIN hands the buffer back (io_kbuf_recycle): a read
     * takes it meanwhile, and the receive then takes the next. */
    push(&r, sel(OP_RECV, sv[1], 0, 1, 2));
    SUB("handback-recv-waits", &r, "");
    put(p[1], "xy");
    push(&r, sel(OP_READ, p[0], 0, 1, 3));
    SUB("handback-read", &r, "3:2/1e0001");
    put(sv[0], "hello");
    REAPF("handback-recv", &r, "2:5/1f0001");
    /* io_send keeps its buffer while it waits for room: with the socket
     * full, only the other is left to remove. */
    long filled = 0, drained = 0, n;
    while ((n = write(sv[0], big, 1 << 16)) > 0)
        filled += n;
    memcpy(mem, "0123456789abcdef", 16);
    push(&r, provide(2, mem, 16, 2, 40, 4));
    push(&r, sel(OP_SEND, sv[0], 0, 2, 5));
    SUB("handback-send-waits", &r, "4:0");
    push(&r, remove_bufs(8, 2, 6));
    SUB("handback-send-kept", &r, "6:1");
    /* Room: the send completes with the buffer it kept, whole, after what
     * filled the socket. */
    char tail[16] = {0};
    for (int tries = 0; drained < filled + 16 && tries < 2;) {
        n = read(sv[1], big, 1 << 16);
        if (n <= 0) {
            tries++;
            continue;
        }
        drained += n;
        if (n >= 16) {
            memcpy(tail, big + n - 16, 16);
        } else {
            memmove(tail, tail + n, 16 - n);
            memcpy(tail + 16 - n, big, n);
        }
    }
    REAPF("handback-send", &r, "5:16/280001");
    CHECK("handback-send-data", drained == filled + 16 && memcmp(tail, "0123456789abcdef", 16) == 0);
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void rings(void) {
    struct ring r = make(8, 0, 0);
    char *ring = anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    char *gone = anon(PAGE, PROT_READ | PROT_WRITE);
    munmap(gone, PAGE);
    /* __io_uring_register: an argument, and one. */
    struct buf_reg b = {PTR(ring), 4, 3, 0, {0, 0, 0}};
    CHECK_ERR("rings-no-arg", reg(r.fd, REGISTER_PBUF_RING, NULL, 1), EINVAL);
    CHECK_ERR("rings-two-args", reg(r.fd, REGISTER_PBUF_RING, &b, 2), EINVAL);
    CHECK_ERR("rings-arg-fault", reg(r.fd, REGISTER_PBUF_RING, (void *)8, 1), EFAULT);
    /* io_register_pbuf_ring: reserved words zero, known flags, a power of
     * two below 65536. */
    b.resv[0] = 1;
    CHECK_ERR("rings-resv", reg(r.fd, REGISTER_PBUF_RING, &b, 1), EINVAL);
    CHECK_ERR("rings-flags", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 3, 4), EINVAL);
    CHECK_ERR("rings-entries-3", pbuf(r.fd, REGISTER_PBUF_RING, ring, 3, 3, 0), EINVAL);
    CHECK_ERR("rings-entries-0", pbuf(r.fd, REGISTER_PBUF_RING, ring, 0, 3, 0), EINVAL);
    CHECK_ERR("rings-entries-65536", pbuf(r.fd, REGISTER_PBUF_RING, ring, 65536, 3, 0), EINVAL);
    /* io_create_region: a ring in the process's memory needs its address,
     * page aligned, and mapped to be pinned. */
    CHECK_ERR("rings-user-none", pbuf(r.fd, REGISTER_PBUF_RING, NULL, 4, 3, 0), EFAULT);
    CHECK_ERR("rings-user-align", pbuf(r.fd, REGISTER_PBUF_RING, ring + 8, 4, 3, 0), EINVAL);
    CHECK_ERR("rings-user-unmapped", pbuf(r.fd, REGISTER_PBUF_RING, gone, 4, 3, 0), EFAULT);
    CHECK("rings-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 3, 0) == 0);
    /* A group has one ring and no provided buffers; an emptied group gives
     * way. Provided buffers are not for a ring's group. */
    CHECK_ERR("rings-exists", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 3, 0), EEXIST);
    push(&r, provide(1, mem, 16, 5, 0, 1));
    SUB("rings-legacy", &r, "1:0");
    CHECK_ERR("rings-legacy-exists", pbuf(r.fd, REGISTER_PBUF_RING, mem, 4, 5, 0), EEXIST);
    push(&r, remove_bufs(1, 5, 2));
    SUB("rings-legacy-emptied", &r, "2:1");
    CHECK("rings-legacy-replaced", pbuf(r.fd, REGISTER_PBUF_RING, mem, 4, 5, 0) == 0);
    push(&r, provide(1, mem, 16, 5, 0, 3));
    push(&r, remove_bufs(1, 5, 4));
    SUB("rings-not-legacy", &r, "3:-22 4:-22");
    /* io_register_pbuf_status: a ring's head. */
    CHECK("rings-status", head(r.fd, 3) == 0);
    CHECK("rings-status-missing", head(r.fd, 9) == -ENOENT);
    CHECK("rings-status-wide", head(r.fd, 0x10003) == -ENOENT);
    push(&r, provide(1, mem, 16, 6, 0, 5));
    SUB("rings-legacy-6", &r, "5:0");
    CHECK("rings-status-legacy", head(r.fd, 6) == -EINVAL);
    struct buf_status st = {3, 0, {1}};
    CHECK_ERR("rings-status-resv", reg(r.fd, REGISTER_PBUF_STATUS, &st, 1), EINVAL);
    /* io_uring_get_unmapped_area: a ring in the process's memory, or a
     * missing one, has no region to map. */
    void *m = pbuf_map(r.fd, PAGE, 3);
    CHECK("rings-map-user", m == MAP_FAILED && errno == ENOMEM);
    m = pbuf_map(r.fd, PAGE, 9);
    CHECK("rings-map-missing", m == MAP_FAILED && errno == ENOMEM);
    /* IOU_PBUF_RING_MMAP: pages of the ring's own (its address ignored),
     * mapped whole (io_region_mmap). */
    CHECK("rings-mmap", pbuf(r.fd, REGISTER_PBUF_RING, (void *)0x1234, 512, 7, RING_MMAP) == 0);
    m = pbuf_map(r.fd, PAGE, 7);
    CHECK("rings-map-short", m == MAP_FAILED && errno == EFAULT);
    struct ubuf *mr = pbuf_map(r.fd, 2 * PAGE, 7);
    CHECK("rings-map", mr != MAP_FAILED);
    if (mr == MAP_FAILED)
        return;
    int p[2];
    CHECK("rings-pipe", pipe(p) == 0);
    ring_buf(mr, 0, mem + 64, 8, 70);
    set_tail(mr, 1);
    put(p[1], "hi");
    push(&r, sel(OP_READ, p[0], 0, 7, 6));
    SUB("rings-map-read", &r, "6:2/460001");
    CHECK("rings-map-data", memcmp(mem + 64, "hi", 2) == 0 && head(r.fd, 7) == 1);
    /* io_unregister_pbuf_ring: no flags or reserved words, a group with a
     * ring. The mapping stays. */
    CHECK_ERR("rings-unregister-flags", pbuf(r.fd, UNREGISTER_PBUF_RING, NULL, 0, 7, RING_MMAP),
              EINVAL);
    b = (struct buf_reg){0, 0, 7, 0, {0, 0, 1}};
    CHECK_ERR("rings-unregister-resv", reg(r.fd, UNREGISTER_PBUF_RING, &b, 1), EINVAL);
    CHECK_ERR("rings-unregister-missing", pbuf(r.fd, UNREGISTER_PBUF_RING, NULL, 0, 9, 0), ENOENT);
    CHECK_ERR("rings-unregister-legacy", pbuf(r.fd, UNREGISTER_PBUF_RING, NULL, 0, 6, 0), EINVAL);
    b = (struct buf_reg){0, 0, 7, 0, {0, 0, 0}};
    CHECK_ERR("rings-unregister-args", reg(r.fd, UNREGISTER_PBUF_RING, &b, 0), EINVAL);
    CHECK("rings-unregister", pbuf(r.fd, UNREGISTER_PBUF_RING, NULL, 0, 7, 0) == 0);
    CHECK("rings-unregistered", head(r.fd, 7) == -ENOENT);
    m = pbuf_map(r.fd, 2 * PAGE, 7);
    CHECK("rings-unregistered-map", m == MAP_FAILED && errno == ENOMEM);
    CHECK("rings-mapping-stays", mr[0].len == 8 && mr[0].bid == 70);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void ring_select(void) {
    struct ring r = make(8, 0, 0);
    struct ubuf *ring = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int p[2], sv[2];
    CHECK("select-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 3, 0) == 0);
    CHECK("select-pipe", pipe(p) == 0);
    ring_buf(ring, 0, mem, 8, 20);
    ring_buf(ring, 1, mem + 8, 8, 21);
    set_tail(ring, 2);
    /* A file with a wait queue: the head moves as the read completes. */
    put(p[1], "abcdef");
    push(&r, sel(OP_READ, p[0], 0, 3, 1));
    SUB("select-read", &r, "1:6/140001");
    CHECK("select-read-head", head(r.fd, 3) == 1 && memcmp(mem, "abcdef", 6) == 0);
    /* Waiting, the read hands its buffer back (io_kbuf_recycle_ring). */
    push(&r, sel(OP_READ, p[0], 0, 3, 2));
    SUB("select-waits", &r, "");
    CHECK("select-waits-head", head(r.fd, 3) == 1);
    put(p[1], "xyz");
    REAPF("select-woken", &r, "2:3/150001");
    CHECK("select-woken-head", head(r.fd, 3) == 2);
    /* Empty (the tail at the head): ENOBUFS. */
    push(&r, sel(OP_READ, p[0], 0, 3, 3));
    SUB("select-empty", &r, "3:-105");
    ring_buf(ring, 2, mem + 16, 8, 22);
    ring_buf(ring, 3, mem + 24, 8, 23);
    set_tail(ring, 4);
    /* Failing, a read hands back a buffer it has not taken... */
    push(&r, sel(OP_READ, p[1], 0, 3, 4));
    SUB("select-failed", &r, "4:-9");
    CHECK("select-failed-head", head(r.fd, 3) == 2);
    /* ... but a file without a wait queue takes it at once
     * (io_should_commit), and the failure reports it. */
    int wo = tmp_file("wwwwwwww", O_WRONLY);
    push(&r, sel(OP_READ, wo, 0, 3, 5));
    SUB("select-failed-taken", &r, "5:-9/160001");
    CHECK("select-failed-taken-head", head(r.fd, 3) == 3);
    int ro = tmp_file("rrrrrrrr", O_RDONLY);
    ONEF("select-file", &r, sel(OP_READ, ro, 4, 3, 6), 1, "6:4/170001");
    CHECK("select-file-head", head(r.fd, 3) == 4 && memcmp(mem + 24, "rrrr", 4) == 0);
    /* A receive: IORING_CQE_F_SOCK_NONEMPTY with data left. */
    CHECK("select-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    ring_buf(ring, 0, mem, 8, 30);
    set_tail(ring, 5);
    put(sv[0], "hello world");
    push(&r, sel(OP_RECV, sv[1], 5, 3, 7));
    SUB("select-recv", &r, "7:5/1e0005");
    CHECK("select-recv-rest", strcmp(get(sv[1], 64), " world") == 0);
    /* A send takes its buffer at once, cut to the length asked for (the
     * entry's length rewritten: io_ring_buffers_peek). */
    memcpy(mem + 32, "ABCDEFGH", 8);
    ring_buf(ring, 1, mem + 32, 8, 31);
    set_tail(ring, 6);
    push(&r, sel(OP_SEND, sv[0], 3, 3, 8));
    SUB("select-send", &r, "8:3/1f0001");
    CHECK("select-send-cut", ring[1].len == 3 && head(r.fd, 3) == 6);
    CHECK("select-send-data", strcmp(get(sv[1], 64), "ABC") == 0);
    /* Without the group: a send's io_buffers_select finds none (ENOENT), a
     * receive's io_buffer_select no buffer (ENOBUFS). */
    push(&r, sel(OP_SEND, sv[0], 3, 9, 9));
    push(&r, sel(OP_RECV, sv[1], 3, 9, 10));
    SUB("select-no-group", &r, "9:-2 10:-105");
    close(wo);
    close(ro);
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void incremental(void) {
    struct ring r = make(8, 0, 0);
    struct ubuf *ring = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int p[2], sv[2];
    CHECK("inc-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 2, 4, RING_INC) == 0);
    CHECK("inc-pipe", pipe(p) == 0);
    ring_buf(ring, 0, mem, 10, 40);
    set_tail(ring, 1);
    /* io_kbuf_inc_commit: the head buffer moves on by what was used and
     * stays (IORING_CQE_F_BUF_MORE)... */
    put(p[1], "abcd");
    push(&r, sel(OP_READ, p[0], 0, 4, 1));
    SUB("inc-part", &r, "1:4/280011");
    CHECK("inc-part-entry", ring[0].addr == PTR(mem + 4) && ring[0].len == 6);
    CHECK("inc-part-head", head(r.fd, 4) == 0);
    /* ... until it is used up. */
    put(p[1], "efghijkl");
    push(&r, sel(OP_READ, p[0], 0, 4, 2));
    SUB("inc-rest", &r, "2:6/280001");
    CHECK("inc-rest-entry", ring[0].len == 0 && head(r.fd, 4) == 1);
    CHECK("inc-data", memcmp(mem, "abcdefghij", 10) == 0);
    /* A send uses part of one. */
    CHECK("inc-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    memcpy(mem + 16, "ABCDEFGH", 8);
    ring_buf(ring, 1, mem + 16, 8, 41);
    set_tail(ring, 2);
    push(&r, sel(OP_SEND, sv[0], 3, 4, 3));
    SUB("inc-send", &r, "3:3/290001");
    CHECK("inc-send-entry", ring[1].addr == PTR(mem + 19) && ring[1].len == 5);
    CHECK("inc-send-head", head(r.fd, 4) == 1);
    CHECK("inc-send-data", strcmp(get(sv[1], 64), "ABC") == 0);
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static struct sqe bundle(int fd, uint8_t op, uint32_t len, uint64_t data) {
    struct sqe s = sel(op, fd, len, 5, data);
    s.ioprio = BUNDLE;
    return s;
}

/* A ring of its own: which message state a request takes from the ring's
 * cache depends on the requests before it. */
static void bundles(void) {
    struct ring r = make(8, 0, 0);
    struct ubuf *ring = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int sv[2];
    CHECK("bundle-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 8, 5, 0) == 0);
    CHECK("bundle-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    for (unsigned i = 0; i < 4; i++)
        ring_buf(ring, i, mem + 4 * i, 4, 50 + i);
    set_tail(ring, 4);
    /* io_recv_buf_select: with no length and nothing known to be queued,
     * one buffer; a full one with more queued goes on (IORING_RECV_RETRY)
     * with as many as that needs, and the completion reports the first.
     * (Two writes: a Unix stream's msg_inq counts an skb read in part at
     * its whole length.) */
    put(sv[0], "abcd");
    put(sv[0], "efghijkl");
    push(&r, bundle(sv[1], OP_RECV, 0, 1));
    SUB("bundle-recv", &r, "1:12/320001");
    CHECK("bundle-recv-data", memcmp(mem, "abcdefghijkl", 12) == 0 && head(r.fd, 5) == 3);
    /* A message of three vectors leaves its message state, with an array
     * of three, in the ring's cache (io_netmsg_recycle); the next receive
     * takes it, and with it maps three buffers at once. */
    for (unsigned i = 4; i < 8; i++)
        ring_buf(ring, i, mem + 4 * i, 4, 50 + i);
    set_tail(ring, 8);
    char data[] = "0123456789";
    struct iovec v[3] = {{data, 3}, {data + 3, 3}, {data + 6, 4}};
    struct msghdr m = {.msg_iov = v, .msg_iovlen = 3};
    struct sqe s = nop(3);
    s.opcode = OP_SENDMSG;
    s.fd = sv[0];
    s.addr = PTR(&m);
    push(&r, s);
    SUB("bundle-sendmsg", &r, "3:10");
    push(&r, bundle(sv[1], OP_RECV, 0, 4));
    SUB("bundle-cached-array", &r, "4:10/350001");
    CHECK("bundle-cached-array-data", memcmp(mem + 12, "0123456789", 10) == 0 && head(r.fd, 5) == 6);
    /* A length maps whole buffers as far as it goes: one that would be cut
     * ends the mapping (IORING_RECV_PARTIAL_MAP, no retry)... */
    put(sv[0], "ABCDEFGH");
    push(&r, bundle(sv[1], OP_RECV, 6, 5));
    SUB("bundle-partial", &r, "5:4/380005");
    CHECK("bundle-partial-head", head(r.fd, 5) == 7);
    /* ... unless it is the first, cut to fit in the ring. */
    push(&r, bundle(sv[1], OP_RECV, 2, 6));
    SUB("bundle-first-cut", &r, "6:2/390005");
    CHECK("bundle-first-cut-entry", ring[7].len == 2 && head(r.fd, 5) == 8);
    CHECK("bundle-first-cut-rest", strcmp(get(sv[1], 64), "GH") == 0);
    /* A bundle send takes buffers for all it asks, sent whole. */
    memcpy(mem, "abcdefgh", 8);
    ring_buf(ring, 0, mem, 4, 60);
    ring_buf(ring, 1, mem + 4, 4, 61);
    set_tail(ring, 10);
    push(&r, bundle(sv[0], OP_SEND, 0, 7));
    SUB("bundle-send", &r, "7:8/3c0001");
    CHECK("bundle-send-data", head(r.fd, 5) == 10 && strcmp(get(sv[1], 64), "abcdefgh") == 0);
    /* io_wq_submit_work: a bundle send (REQ_F_MULTISHOT) never runs in a
     * worker but waits for its socket, once; one writable already ends it
     * (IO_APOLL_READY: ECANCELED). */
    s = bundle(sv[0], OP_SEND, 0, 8);
    s.flags |= ASYNC;
    ONEF("bundle-send-async", &r, s, 1, "8:-125");
    close(sv[0]);
    close(sv[1]);
    drop(&r);
}

static struct sqe mshot(int fd, uint8_t op, uint16_t group, uint64_t data) {
    struct sqe s = sel(op, fd, 0, group, data);
    s.ioprio = RECV_MULTISHOT;
    return s;
}

static void multishot(void) {
    struct ring r = make(8, 0, 0);
    struct ubuf *ring = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    struct ubuf *ring2 = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int sv[2];
    CHECK("mshot-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 6, 0) == 0);
    CHECK("mshot-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    for (unsigned i = 0; i < 4; i++)
        ring_buf(ring, i, mem + 4 * i, 4, 60 + i);
    set_tail(ring, 4);
    /* io_recv_finish: each buffer posted with IORING_CQE_F_MORE, at once
     * while data is left, then waiting for more. */
    push(&r, mshot(sv[1], OP_RECV, 6, 1));
    SUB("mshot-waits", &r, "");
    put(sv[0], "abcdefghij");
    REAPF("mshot-each", &r, "1:4/3c0007 1:4/3d0007 1:2/3e0003");
    put(sv[0], "xyz");
    REAPF("mshot-more", &r, "1:3/3f0003");
    /* Out of buffers, the request ends. */
    put(sv[0], "q");
    REAPF("mshot-enobufs", &r, "1:-105");
    CHECK("mshot-head", head(r.fd, 6) == 4);
    /* A CQ without room ends it too (io_req_post_cqe never overflows): the
     * final completion carries the last receive, and overflows. */
    struct ring small = make(1, 0, 0);
    CHECK("mshot-small-register", pbuf(small.fd, REGISTER_PBUF_RING, ring2, 4, 7, 0) == 0);
    for (unsigned i = 0; i < 4; i++)
        ring_buf(ring2, i, mem + 64 + 4 * i, 4, 70 + i);
    set_tail(ring2, 4);
    put(sv[0], "0123456789");
    push(&small, mshot(sv[1], OP_RECV, 7, 2));
    SUB("mshot-cq-full", &small, "2:4/460007 2:4/470007");
    CHECK("mshot-cq-overflow", *sq_u32(&small, small.p.sq_off.flags) & SQ_CQ_OVERFLOW);
    enter(small.fd, 0, 0, GETEVENTS, NULL, 0);
    REAPF("mshot-cq-final", &small, "2:3/480001");
    CHECK("mshot-cq-data", memcmp(mem + 64, "q0123456789", 11) == 0);
    close(sv[0]);
    close(sv[1]);
    drop(&small);
    drop(&r);
}

static void recvmsg_mshot(void) {
    struct ring r = make(8, 0, 0);
    struct ubuf *ring = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int sv[2];
    CHECK("recvmsg-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 8, 0) == 0);
    CHECK("recvmsg-socketpair", socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    for (unsigned i = 0; i < 3; i++)
        ring_buf(ring, i, mem + 128 * i, 128, 80 + i);
    ring_buf(ring, 3, mem + 384, 56, 83);
    set_tail(ring, 4);
    /* The sender bound to an abstract name. */
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    int len = snprintf(a.sun_path + 1, sizeof a.sun_path - 1, "rax-uringbuf-%d", getpid());
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + len);
    CHECK("recvmsg-bind", bind(sv[0], (struct sockaddr *)&a, alen) == 0);
    /* Room for a 32-byte name and no control data: 48 bytes of header. */
    struct msghdr m = {.msg_namelen = 32};
    put(sv[0], "hi");
    put(sv[0], "there");
    struct sqe s = mshot(sv[1], OP_RECVMSG, 8, 1);
    s.addr = PTR(&m);
    /* io_recvmsg_multishot: struct io_uring_recvmsg_out, the name, then
     * the payload; the result counts the header and name room. */
    push(&r, s);
    SUB("recvmsg-each", &r, "1:50/500003 1:53/510003");
    struct recvmsg_out *o = (void *)mem;
    CHECK("recvmsg-out", o->namelen == alen && o->controllen == 0 && o->payloadlen == 2 &&
                             o->flags == 0);
    CHECK("recvmsg-name", memcmp(mem + 16, &a, alen) == 0);
    CHECK("recvmsg-payload", memcmp(mem + 48, "hi", 2) == 0 && memcmp(mem + 128 + 48, "there", 5) == 0);
    /* Truncated: MSG_TRUNC, and what fit (the socket says no more without
     * MSG_TRUNC asked for). */
    char x[100];
    memset(x, 'x', sizeof x);
    CHECK("recvmsg-send-long", write(sv[0], x, sizeof x) == sizeof x);
    REAPF("recvmsg-trunc", &r, "1:128/520003");
    o = (void *)(mem + 256);
    CHECK("recvmsg-trunc-out", o->payloadlen == 80 && o->flags == MSG_TRUNC);
    /* A datagram socket says nothing of what is queued (msg_inq -1), so
     * the receive goes on at once, and without a buffer ends. */
    put(sv[0], "0123456789");
    REAPF("recvmsg-enobufs", &r, "1:56/530003 1:-105");
    o = (void *)(mem + 384);
    CHECK("recvmsg-small-out", o->payloadlen == 8 && o->flags == MSG_TRUNC);
    /* With MSG_TRUNC the payload's whole length is reported. */
    ring_buf(ring, 0, mem, 56, 84);
    set_tail(ring, 5);
    put(sv[0], "0123456789");
    s = mshot(sv[1], OP_RECVMSG, 8, 2);
    s.addr = PTR(&m);
    s.op_flags = MSG_TRUNC;
    push(&r, s);
    SUB("recvmsg-msg-trunc", &r, "2:56/540003 2:-105");
    o = (void *)mem;
    CHECK("recvmsg-msg-trunc-out", o->payloadlen == 10 && o->flags == MSG_TRUNC);
    /* io_recvmsg_prep_multishot: a buffer the header does not fit (EFAULT,
     * the buffer handed back). */
    ring_buf(ring, 1, mem, 16, 85);
    set_tail(ring, 6);
    put(sv[0], "late");
    s = mshot(sv[1], OP_RECVMSG, 8, 3);
    s.addr = PTR(&m);
    push(&r, s);
    SUB("recvmsg-efault", &r, "3:-14");
    CHECK("recvmsg-efault-head", head(r.fd, 8) == 5);
    close(sv[0]);
    close(sv[1]);
    drop(&r);
}

static struct sqe rmshot(int fd, uint64_t data) {
    struct sqe s = sel(OP_READ_MULTISHOT, fd, 0, 9, data);
    return s;
}

static void readmshot(void) {
    struct ring r = make(8, 0, 0);
    struct ubuf *ring = (void *)anon(PAGE, PROT_READ | PROT_WRITE);
    char *mem = anon(PAGE, PROT_READ | PROT_WRITE);
    int p[2];
    CHECK("readmshot-register", pbuf(r.fd, REGISTER_PBUF_RING, ring, 4, 9, 0) == 0);
    CHECK("readmshot-pipe", pipe(p) == 0);
    for (unsigned i = 0; i < 4; i++)
        ring_buf(ring, i, mem + 8 * i, 8, 90 + i);
    set_tail(ring, 4);
    /* io_read_mshot_prep: a provided buffer, no address or length. */
    struct sqe s = rmshot(p[0], 1);
    s.flags = 0;
    PREP("readmshot-no-select", &r, s, "1:-22");
    s = rmshot(p[0], 2);
    s.len = 8;
    PREP("readmshot-len", &r, s, "2:-22");
    s = rmshot(p[0], 3);
    s.addr = PTR(mem);
    PREP("readmshot-addr", &r, s, "3:-22");
    /* io_read_mshot: a file with a wait queue (EBADFD). */
    int ro = tmp_file("rrrr", O_RDONLY);
    push(&r, rmshot(ro, 4));
    SUB("readmshot-file", &r, "4:-77");
    /* RWF_NOWAIT: nothing to read fails it, its buffer handed back. */
    s = rmshot(p[0], 5);
    s.op_flags = RWF_NOWAIT_;
    push(&r, s);
    SUB("readmshot-nowait", &r, "5:-11");
    CHECK("readmshot-nowait-head", head(r.fd, 9) == 0);
    /* Each read posted with IORING_CQE_F_MORE, the next at once
     * (io_poll_multishot_retry), short ones and all. */
    push(&r, rmshot(p[0], 6));
    SUB("readmshot-waits", &r, "");
    put(p[1], "abcdefghijk");
    REAPF("readmshot-each", &r, "6:8/5a0003 6:3/5b0003");
    CHECK("readmshot-data", memcmp(mem, "abcdefghijk", 11) == 0);
    /* The end of the file ends it (0), its buffer handed back. */
    close(p[1]);
    REAPF("readmshot-eof", &r, "6:0");
    CHECK("readmshot-eof-head", head(r.fd, 9) == 2);
    close(ro);
    close(p[0]);
    drop(&r);
}

int main(void) {
    charge();
    legacy();
    reads();
    handback();
    rings();
    ring_select();
    incremental();
    bundles();
    multishot();
    recvmsg_mshot();
    readmshot();
    FINISH();
}
