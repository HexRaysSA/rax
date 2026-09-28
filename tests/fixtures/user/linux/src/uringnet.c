/* io_uring's socket requests (io_uring/net.c, Linux 6.19): SEND, RECV,
 * SENDMSG, RECVMSG (vectors, flags, the header read at preparation,
 * MSG_WAITALL's parts, IORING_CQE_F_SOCK_NONEMPTY), SOCKET, BIND, LISTEN,
 * CONNECT, ACCEPT (one-shot, multishot, into registered slots,
 * IORING_ACCEPT_DONTWAIT), SHUTDOWN, the checks of preparation and issue,
 * and TCP on the loopback interface. Nothing here goes to the async
 * workers, whose order is not the submission's, but SHUTDOWN, whose
 * completions are waited for. */
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "uring.h"

enum { OP_SENDMSG = 9, OP_RECVMSG = 10, OP_ACCEPT = 13, OP_CONNECT = 16, OP_SEND = 26,
       OP_RECV = 27, OP_SHUTDOWN = 34, OP_SOCKET = 45, OP_BIND = 56, OP_LISTEN = 57,
       OP_CANCEL = 14 };
enum { POLL_FIRST = 1, RECV_MULTISHOT = 1 << 1, BUNDLE = 1 << 4 };
enum { ACCEPT_MULTISHOT = 1, ACCEPT_DONTWAIT = 1 << 1 };

static struct sqe sr_sqe(uint8_t op, int fd, void *buf, uint32_t len, uint32_t flags,
                         uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = op;
    s.fd = fd;
    s.addr = PTR(buf);
    s.len = len;
    s.op_flags = flags;
    return s;
}

static struct sqe op_sqe(uint8_t op, int fd, uint64_t data) {
    struct sqe s = nop(data);
    s.opcode = op;
    s.fd = fd;
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

/* Submits every queued SQE, waits for n completions, and reaps. */
static char *wait_all(struct ring *r, unsigned n) {
    uint32_t queued = *sq_u32(r, r->p.sq_off.tail) - *sq_u32(r, r->p.sq_off.head);
    long got = enter(r->fd, queued, n, GETEVENTS, NULL, 0);
    if (got != (long)queued)
        printf("  enter returned %ld errno %d\n", got, errno);
    return reapf(r);
}

#define WAIT_ALL(name, r, n, want)                                            \
    do {                                                                      \
        char *got_ = wait_all(r, n);                                          \
        CHECK(name, strcmp(got_, want) == 0);                                 \
        if (strcmp(got_, want) != 0)                                          \
            printf("  got \"%s\" want \"%s\"\n", got_, want);                 \
    } while (0)

static void put(int fd, const char *s) {
    if (write(fd, s, strlen(s)) != (long)strlen(s))
        printf("  write failed errno %d\n", errno);
}

/* An abstract Unix address named for this test and the case. */
static socklen_t abstract(struct sockaddr_un *a, const char *tag) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    int n = snprintf(a->sun_path + 1, sizeof a->sun_path - 1, "rax-uringnet-%d-%s", getpid(), tag);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

static void pairs(void) {
    struct ring r = make(8, 0, 0);
    int sv[2];
    char buf[16] = {0};
    CHECK("pairs-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    push(&r, sr_sqe(OP_SEND, sv[0], "hello", 5, 0, 1));
    SUB("pairs-send", &r, "1:5");
    /* msg_inq: what is left says IORING_CQE_F_SOCK_NONEMPTY. */
    push(&r, sr_sqe(OP_RECV, sv[1], buf, 3, 0, 2));
    SUB("pairs-recv-part", &r, "2:3/4");
    push(&r, sr_sqe(OP_RECV, sv[1], buf + 3, 10, 0, 3));
    SUB("pairs-recv-rest", &r, "3:2");
    CHECK("pairs-data", memcmp(buf, "hello", 5) == 0);
    /* Nothing to receive: it waits, and the send wakes it. */
    push(&r, sr_sqe(OP_RECV, sv[1], buf, 8, 0, 4));
    push(&r, sr_sqe(OP_SEND, sv[0], "hi", 2, 0, 5));
    SUB("pairs-wake", &r, "5:2 4:2");
    push(&r, sr_sqe(OP_RECV, sv[1], buf, 8, MSG_DONTWAIT, 6));
    SUB("pairs-dontwait", &r, "6:-11");
    /* IORING_RECVSEND_POLL_FIRST: waits first, though data is there. */
    put(sv[0], "zz");
    struct sqe s = sr_sqe(OP_RECV, sv[1], buf, 8, 0, 7);
    s.ioprio = POLL_FIRST;
    push(&r, s);
    SUB("pairs-poll-first", &r, "7:2");
    /* Sends never raise SIGPIPE (MSG_NOSIGNAL is theirs). */
    close(sv[1]);
    push(&r, sr_sqe(OP_SEND, sv[0], "x", 1, 0, 8));
    SUB("pairs-epipe", &r, "8:-32");
    close(sv[0]);
    drop(&r);
}

static void waitall(void) {
    struct ring r = make(8, 0, 0);
    int sv[2];
    char buf[16] = {0};
    CHECK("waitall-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    push(&r, sr_sqe(OP_RECV, sv[1], buf, 6, MSG_WAITALL, 1));
    SUB("waitall-waits", &r, "");
    put(sv[0], "abc");
    REAPF("waitall-part", &r, "");
    put(sv[0], "def");
    REAPF("waitall-whole", &r, "1:6");
    CHECK("waitall-data", memcmp(buf, "abcdef", 6) == 0);
    /* Cancelled in part, it reports what it moved (io_sendrecv_fail). */
    push(&r, sr_sqe(OP_RECV, sv[1], buf, 6, MSG_WAITALL, 2));
    SUB("waitall-cancel-waits", &r, "");
    put(sv[0], "gh");
    struct sqe c = nop(3);
    c.opcode = OP_CANCEL;
    c.addr = 2;
    push(&r, c);
    SUB("waitall-cancelled", &r, "3:0 2:2");
    close(sv[0]);
    close(sv[1]);
    drop(&r);
}

static void messages(void) {
    struct ring r = make(8, 0, 0);
    int sv[2];
    char data[] = "onetwo", buf[16] = {0};
    CHECK("messages-socketpair", socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    struct iovec out[2] = {{data, 3}, {data + 3, 3}};
    struct msghdr m = {.msg_iov = out, .msg_iovlen = 2};
    push(&r, sr_sqe(OP_SENDMSG, sv[0], &m, 0, 0, 1));
    SUB("messages-sendmsg", &r, "1:6");
    /* A datagram longer than the vectors: MSG_TRUNC in msg_flags. */
    struct iovec in[2] = {{buf, 2}, {buf + 2, 2}};
    struct msghdr n = {.msg_iov = in, .msg_iovlen = 2};
    push(&r, sr_sqe(OP_RECVMSG, sv[1], &n, 0, 0, 2));
    SUB("messages-recvmsg", &r, "2:4");
    CHECK("messages-data", memcmp(buf, "onet", 4) == 0);
    CHECK("messages-trunc", n.msg_flags == MSG_TRUNC);
    /* The header and vectors are read as the request is prepared. */
    struct iovec one = {buf, 8};
    struct msghdr p = {.msg_iov = &one, .msg_iovlen = 1};
    push(&r, sr_sqe(OP_RECVMSG, sv[1], &p, 0, 0, 3));
    SUB("messages-prepared-waits", &r, "");
    char other[8];
    one.iov_base = other;
    put(sv[0], "x");
    REAPF("messages-prepared", &r, "3:1");
    CHECK("messages-prepared-buffer", buf[0] == 'x');
    /* MSG_WAITALL with a truncated datagram fails its link. */
    put(sv[0], "long");
    struct iovec small = {buf, 2};
    struct msghdr q = {.msg_iov = &small, .msg_iovlen = 1};
    struct sqe s = sr_sqe(OP_RECVMSG, sv[1], &q, 0, MSG_WAITALL, 4);
    s.flags = LINK;
    push(&r, s);
    push(&r, nop(5));
    SUB("messages-waitall-trunc", &r, "4:2 5:-125");
    close(sv[0]);
    close(sv[1]);
    drop(&r);
}

static void prep(void) {
    struct ring r = make(8, 0, 0);
    int sv[2];
    char buf[8];
    struct msghdr m = {0};
    struct sockaddr_un a;
    CHECK("prep-socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    struct sqe s = sr_sqe(OP_SEND, sv[0], buf, 1, 0, 1);
    s.ioprio = 1 << 6;
    PREP("prep-send-flags", &r, s, "1:-22");
    s = sr_sqe(OP_SEND, sv[0], buf, 1, 0, 2);
    s.ioprio = RECV_MULTISHOT;
    PREP("prep-send-multishot", &r, s, "2:-22");
    s = sr_sqe(OP_SEND, sv[0], buf, 1, 0, 3);
    s.file_index = 1 << 16;
    PREP("prep-send-pad", &r, s, "3:-22");
    s = sr_sqe(OP_SEND, sv[0], buf, 1, 0, 4);
    s.off = PTR(&a);
    s.file_index = 200;
    PREP("prep-send-addr-len", &r, s, "4:-22");
    s = sr_sqe(OP_RECV, sv[0], buf, 1, 0, 5);
    s.off = 1;
    PREP("prep-recv-addr2", &r, s, "5:-22");
    s = sr_sqe(OP_RECV, sv[0], buf, 1, 0, 6);
    s.file_index = 1;
    PREP("prep-recv-optlen", &r, s, "6:-22");
    s = sr_sqe(OP_RECV, sv[0], buf, 1, 0, 7);
    s.ioprio = RECV_MULTISHOT;
    PREP("prep-recv-multishot", &r, s, "7:-22");
    s = sr_sqe(OP_SENDMSG, sv[0], &m, 0, 0, 8);
    s.ioprio = BUNDLE;
    PREP("prep-sendmsg-bundle", &r, s, "8:-22");
    s = sr_sqe(OP_RECVMSG, sv[0], &m, 0, 0, 9);
    s.ioprio = BUNDLE;
    PREP("prep-recvmsg-bundle", &r, s, "9:-22");
    s = sr_sqe(OP_SENDMSG, sv[0], &m, 0, 0, 10);
    s.off = 1;
    PREP("prep-sendmsg-addr2", &r, s, "10:-22");
    PREP("prep-recvmsg-fault", &r, sr_sqe(OP_RECVMSG, sv[0], (void *)16, 0, 0, 11), "11:-14");
    s = sr_sqe(OP_SENDMSG, sv[0], &m, 0, 0, 12);
    s.flags = BUFFER_SELECT;
    PREP("prep-sendmsg-select", &r, s, "12:-95");
    s = op_sqe(OP_ACCEPT, sv[0], 13);
    s.len = 1;
    PREP("prep-accept-len", &r, s, "13:-22");
    s = op_sqe(OP_ACCEPT, sv[0], 14);
    s.ioprio = 1 << 3;
    PREP("prep-accept-flags", &r, s, "14:-22");
    s = op_sqe(OP_ACCEPT, sv[0], 15);
    s.op_flags = 1;
    PREP("prep-accept-sock-flags", &r, s, "15:-22");
    s = op_sqe(OP_ACCEPT, sv[0], 16);
    s.file_index = 1;
    s.op_flags = SOCK_CLOEXEC;
    PREP("prep-accept-slot-cloexec", &r, s, "16:-22");
    s = op_sqe(OP_ACCEPT, sv[0], 17);
    s.file_index = 1;
    s.ioprio = ACCEPT_MULTISHOT;
    PREP("prep-accept-multishot-slot", &r, s, "17:-22");
    s = op_sqe(OP_SOCKET, AF_UNIX, 18);
    s.addr = 1;
    PREP("prep-socket-addr", &r, s, "18:-22");
    s = op_sqe(OP_SOCKET, AF_UNIX, 19);
    s.off = SOCK_STREAM | 1 << 12;
    PREP("prep-socket-type-flags", &r, s, "19:-22");
    s = op_sqe(OP_CONNECT, sv[0], 20);
    s.len = 1;
    PREP("prep-connect-len", &r, s, "20:-22");
    s = op_sqe(OP_CONNECT, sv[0], 21);
    s.addr = PTR(&a);
    s.off = 200;
    PREP("prep-connect-addr-len", &r, s, "21:-22");
    s = op_sqe(OP_LISTEN, sv[0], 22);
    s.addr = 1;
    PREP("prep-listen-addr", &r, s, "22:-22");
    s = op_sqe(OP_SHUTDOWN, sv[0], 23);
    s.off = 1;
    PREP("prep-shutdown-off", &r, s, "23:-22");
    s = op_sqe(OP_BIND, sv[0], 24);
    s.addr = 16;
    s.off = 16;
    PREP("prep-bind-fault", &r, s, "24:-14");
    close(sv[0]);
    close(sv[1]);
    drop(&r);
}

static void checks(void) {
    struct ring r = make(8, 0, 0);
    int sv[2], p[2];
    char buf[8];
    CHECK("checks-files", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(p) == 0);
    push(&r, sr_sqe(OP_RECV, p[0], buf, 4, 0, 1));
    push(&r, sr_sqe(OP_SEND, p[1], buf, 1, 0, 2));
    SUB("checks-not-sockets", &r, "1:-88 2:-88");
    /* No buffer group: io_buffer_select finds no buffer (ENOBUFS),
     * io_buffers_select no list (ENOENT). */
    struct sqe s = sr_sqe(OP_RECV, sv[1], NULL, 4, 0, 3);
    s.flags = BUFFER_SELECT;
    push(&r, s);
    s = sr_sqe(OP_SEND, sv[0], NULL, 4, 0, 4);
    s.flags = BUFFER_SELECT;
    push(&r, s);
    SUB("checks-no-buffers", &r, "3:-105 4:-2");
    push(&r, sr_sqe(OP_SEND, 999, buf, 1, 0, 5));
    SUB("checks-no-file", &r, "5:-9");
    /* A failed SHUTDOWN keeps its link. */
    s = op_sqe(OP_SHUTDOWN, sv[0], 6);
    s.len = 7;
    s.flags = LINK;
    push(&r, s);
    push(&r, nop(7));
    WAIT_ALL("checks-shutdown-link", &r, 2, "6:-22 7:0");
    s = op_sqe(OP_SHUTDOWN, sv[0], 8);
    s.len = SHUT_WR;
    push(&r, s);
    WAIT_ALL("checks-shutdown", &r, 1, "8:0");
    push(&r, sr_sqe(OP_RECV, sv[1], buf, 4, 0, 9));
    SUB("checks-shut-peer-eof", &r, "9:0");
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
    drop(&r);
}

static void unixconn(void) {
    struct ring r = make(8, 0, 0);
    struct sockaddr_un a, peer;
    socklen_t alen = abstract(&a, "conn"), plen = sizeof peer;
    struct sqe s = op_sqe(OP_SOCKET, AF_UNIX, 1);
    s.off = SOCK_STREAM;
    push(&r, s);
    s.user_data = 2;
    push(&r, s);
    char *got = sub(&r);
    int lfd = -1, cfd = -1;
    CHECK("unix-sockets", sscanf(got, "1:%d 2:%d", &lfd, &cfd) == 2 && lfd >= 0 && cfd > lfd);
    s = op_sqe(OP_BIND, lfd, 3);
    s.addr = PTR(&a);
    s.off = alen;
    push(&r, s);
    s = op_sqe(OP_LISTEN, lfd, 4);
    s.len = 4;
    push(&r, s);
    SUB("unix-bind-listen", &r, "3:0 4:0");
    /* The accept waits; the connect completes and wakes it. */
    s = op_sqe(OP_ACCEPT, lfd, 5);
    s.addr = PTR(&peer);
    s.off = PTR(&plen);
    push(&r, s);
    SUB("unix-accept-waits", &r, "");
    s = op_sqe(OP_CONNECT, cfd, 6);
    s.addr = PTR(&a);
    s.off = alen;
    push(&r, s);
    got = sub(&r);
    int afd = -1;
    CHECK("unix-connect-accept", sscanf(got, "6:0 5:%d", &afd) == 1 && afd > cfd);
    if (afd <= cfd)
        printf("  got \"%s\"\n", got);
    CHECK("unix-peer", plen == sizeof(sa_family_t) && peer.sun_family == AF_UNIX);
    /* The new socket carries data both ways. */
    char buf[4] = {0};
    push(&r, sr_sqe(OP_SEND, afd, "ok", 2, 0, 7));
    push(&r, sr_sqe(OP_RECV, cfd, buf, 4, 0, 8));
    SUB("unix-traffic", &r, "7:2 8:2");
    s = op_sqe(OP_ACCEPT, lfd, 9);
    s.ioprio = ACCEPT_DONTWAIT;
    push(&r, s);
    SUB("unix-dontwait", &r, "9:-11");
    /* Cloexec and nonblocking asked for. */
    int c2 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("unix-connect-2", connect(c2, (struct sockaddr *)&a, alen) == 0);
    s = op_sqe(OP_ACCEPT, lfd, 10);
    s.op_flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
    push(&r, s);
    got = sub(&r);
    int a2 = -1;
    CHECK("unix-accept-flags", sscanf(got, "10:%d", &a2) == 1 &&
                                   fcntl(a2, F_GETFD) == FD_CLOEXEC &&
                                   (fcntl(a2, F_GETFL) & O_NONBLOCK));
    close(a2);
    close(c2);
    close(afd);
    close(cfd);
    close(lfd);
    drop(&r);
}

static void multishot(void) {
    struct ring r = make(8, 0, 0);
    struct sockaddr_un a;
    socklen_t alen = abstract(&a, "multi");
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("multishot-listen", bind(lfd, (struct sockaddr *)&a, alen) == 0 && listen(lfd, 8) == 0);
    /* Registered slots: accepts into allocated ones. */
    int slots[4] = {-1, -1, -1, -1};
    CHECK("multishot-register", reg(r.fd, REGISTER_FILES, slots, 4) == 0);
    int c1 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("multishot-connect-1", connect(c1, (struct sockaddr *)&a, alen) == 0);
    struct sqe s = op_sqe(OP_ACCEPT, lfd, 1);
    s.file_index = (uint32_t)FILE_INDEX_ALLOC;
    push(&r, s);
    SUB("multishot-direct", &r, "1:0");
    /* Multishot: each connection with IORING_CQE_F_MORE. */
    s = op_sqe(OP_ACCEPT, lfd, 2);
    s.ioprio = ACCEPT_MULTISHOT;
    s.file_index = (uint32_t)FILE_INDEX_ALLOC;
    push(&r, s);
    SUB("multishot-waits", &r, "");
    int c2 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("multishot-connect-2", connect(c2, (struct sockaddr *)&a, alen) == 0);
    REAPF("multishot-first", &r, "2:1/2");
    int c3 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("multishot-connect-3", connect(c3, (struct sockaddr *)&a, alen) == 0);
    REAPF("multishot-second", &r, "2:2/2");
    int c4 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("multishot-connect-4", connect(c4, (struct sockaddr *)&a, alen) == 0);
    REAPF("multishot-third", &r, "2:3/2");
    /* The table is full: ENFILE ends it. */
    int c5 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("multishot-connect-5", connect(c5, (struct sockaddr *)&a, alen) == 0);
    REAPF("multishot-full", &r, "2:-23");
    close(c1);
    close(c2);
    close(c3);
    close(c4);
    close(c5);
    close(lfd);
    drop(&r);
}

static void tcp(void) {
    struct ring r = make(8, 0, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t alen = sizeof a;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK("tcp-listen", bind(lfd, (struct sockaddr *)&a, alen) == 0 && listen(lfd, 8) == 0 &&
                            getsockname(lfd, (struct sockaddr *)&a, &alen) == 0);
    int c1 = socket(AF_INET, SOCK_STREAM, 0), c2 = socket(AF_INET, SOCK_STREAM, 0);
    struct sqe s = op_sqe(OP_CONNECT, c1, 1);
    s.addr = PTR(&a);
    s.off = alen;
    push(&r, s);
    s.fd = c2;
    s.user_data = 2;
    push(&r, s);
    uint32_t queued = *sq_u32(&r, r.p.sq_off.tail) - *sq_u32(&r, r.p.sq_off.head);
    CHECK("tcp-connect-submit", enter(r.fd, queued, 2, GETEVENTS, NULL, 0) == 2);
    char *got = reapf(&r);
    CHECK("tcp-connected", strcmp(got, "1:0 2:0") == 0 || strcmp(got, "2:0 1:0") == 0);
    /* Two queued: the first accept says more are (inet_csk_accept). */
    push(&r, op_sqe(OP_ACCEPT, lfd, 3));
    push(&r, op_sqe(OP_ACCEPT, lfd, 4));
    got = sub(&r);
    int a3 = -1, a4 = -1;
    CHECK("tcp-accept-queue", sscanf(got, "3:%d/4 4:%d", &a3, &a4) == 2 && a3 >= 0 && a4 > a3);
    if (a3 < 0 || a4 <= a3)
        printf("  got \"%s\"\n", got);
    /* A receive with data left, then after the peer's FIN
     * (tcp_inq_hint: 1 once finished). */
    put(c1, "tcpdata");
    char buf[16];
    push(&r, sr_sqe(OP_RECV, a3, buf, 3, MSG_WAITALL, 5));
    WAIT_ALL("tcp-recv-part", &r, 1, "5:3/4");
    push(&r, sr_sqe(OP_RECV, a3, buf, 4, MSG_WAITALL, 6));
    WAIT_ALL("tcp-recv-rest", &r, 1, "6:4");
    close(c1);
    push(&r, sr_sqe(OP_RECV, a3, buf, 4, 0, 7));
    WAIT_ALL("tcp-recv-eof", &r, 1, "7:0/4");
    close(a3);
    close(a4);
    close(c2);
    close(lfd);
    drop(&r);
}

int main(void) {
    pairs();
    waitall();
    messages();
    prep();
    checks();
    unixconn();
    multishot();
    tcp();
    FINISH();
}
