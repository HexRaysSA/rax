/* Sockets: creation and its checks; Unix stream sockets on paths and in the
 * abstract namespace (with autobind and peer credentials); Unix datagrams;
 * socketpair end-of-file, shutdown, POLLRDHUP, and SIGPIPE; TCP and UDP
 * over the IPv4 loopback with their errors; socket options (timeouts,
 * buffer sizes, TCP_NODELAY); and passing a descriptor with SCM_RIGHTS.
 * Ports are chosen by the kernel; paths live under /tmp. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static volatile sig_atomic_t pipes;
static void on_pipe(int sig) {
    (void)sig;
    pipes++;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int getint(int fd, int level, int opt) {
    int v = -1;
    socklen_t len = sizeof v;
    return getsockopt(fd, level, opt, &v, &len) == 0 && len == sizeof v ? v : -1000;
}

static socklen_t un_addr(struct sockaddr_un *a, const char *path, int abstract) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (abstract) {
        memcpy(a->sun_path + 1, path, n);
        return offsetof(struct sockaddr_un, sun_path) + 1 + n;
    }
    memcpy(a->sun_path, path, n);
    return offsetof(struct sockaddr_un, sun_path) + n + 1;
}

static void creation(void) {
    CHECK_ERR("family", socket(999, SOCK_STREAM, 0), EAFNOSUPPORT);
    CHECK_ERR("type", socket(AF_INET, 99, 0), EINVAL);
    CHECK_ERR("type-flags", socket(AF_INET, SOCK_STREAM | 0x100, 0), EINVAL);
    CHECK_ERR("protocol", socket(AF_INET, SOCK_STREAM, IPPROTO_UDP), EPROTONOSUPPORT);
    CHECK_ERR("unix-protocol", socket(AF_UNIX, SOCK_STREAM, 5), EPROTONOSUPPORT);
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK("flags", s >= 0 && (fcntl(s, F_GETFL) & O_NONBLOCK) &&
                       (fcntl(s, F_GETFD) & FD_CLOEXEC));
    struct stat st;
    char link[64] = {0}, path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", s);
    readlink(path, link, sizeof link - 1);
    CHECK("stat", fstat(s, &st) == 0 && S_ISSOCK(st.st_mode) && !strncmp(link, "socket:[", 8));
    CHECK("so-type", getint(s, SOL_SOCKET, SO_TYPE) == SOCK_DGRAM &&
                         getint(s, SOL_SOCKET, SO_DOMAIN) == AF_INET &&
                         getint(s, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_UDP);
    CHECK_ERR("bad-level", getint(s, 12345, 1) == -1000 ? -1 : 0, EOPNOTSUPP);
    CHECK_ERR("bad-option", getint(s, SOL_SOCKET, 12345) == -1000 ? -1 : 0, ENOPROTOOPT);
    CHECK_ERR("listen-dgram", listen(s, 1), EOPNOTSUPP);
    CHECK_ERR("not-a-socket", listen(0, 1), ENOTSOCK);
    close(s);
}

static void unix_stream(void) {
    char p[64];
    snprintf(p, sizeof p, "/tmp/rax-sock-%d", getpid());
    unlink(p);
    struct sockaddr_un a, b;
    socklen_t alen = un_addr(&a, p, 0), blen;
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("un-bind", bind(l, (struct sockaddr *)&a, alen) == 0);
    struct stat st;
    CHECK("un-node", stat(p, &st) == 0 && S_ISSOCK(st.st_mode));
    int again = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK_ERR("un-addr-in-use", bind(again, (struct sockaddr *)&a, alen), EADDRINUSE);
    CHECK_ERR("un-bound-twice", bind(l, (struct sockaddr *)&a, alen), EADDRINUSE);
    CHECK_ERR("un-refused", connect(again, (struct sockaddr *)&a, alen), ECONNREFUSED);
    CHECK("un-listen", listen(l, 4) == 0 && getint(l, SOL_SOCKET, SO_ACCEPTCONN) == 1);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("un-connect", connect(c, (struct sockaddr *)&a, alen) == 0);
    CHECK_ERR("un-isconn", connect(c, (struct sockaddr *)&a, alen), EISCONN);
    int s = accept(l, 0, 0);
    CHECK("un-accept", s >= 0);
    blen = sizeof b;
    CHECK("un-peername", getpeername(c, (struct sockaddr *)&b, &blen) == 0 && blen == alen &&
                             !strcmp(b.sun_path, p));
    blen = sizeof b;
    CHECK("un-unbound-name", getsockname(c, (struct sockaddr *)&b, &blen) == 0 &&
                                 blen == sizeof(sa_family_t) && b.sun_family == AF_UNIX);
    struct ucred cr;
    socklen_t crl = sizeof cr;
    CHECK("un-peercred", getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &crl) == 0 &&
                             cr.pid == getpid() && cr.uid == getuid() && cr.gid == getgid());
    CHECK("un-data", write(c, "hello", 5) == 5);
    char buf[16] = {0};
    CHECK("un-recv", read(s, buf, sizeof buf) == 5 && !memcmp(buf, "hello", 5));
    close(c);
    CHECK("un-eof", read(s, buf, sizeof buf) == 0);
    close(s);
    close(l);
    close(again);
    struct sockaddr_un missing;
    socklen_t ml = un_addr(&missing, "/tmp/rax-sock-missing-path", 0);
    int m = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK_ERR("un-no-path", connect(m, (struct sockaddr *)&missing, ml), ENOENT);
    CHECK_ERR("un-bad-family", bind(m, (struct sockaddr *)&(struct sockaddr_in){0}, 16), EINVAL);
    close(m);
    unlink(p);

    /* The abstract namespace: no file, the name back from getsockname. */
    char name[32];
    snprintf(name, sizeof name, "rax-abstract-%d", getpid());
    alen = un_addr(&a, name, 1);
    l = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("abs-bind", bind(l, (struct sockaddr *)&a, alen) == 0 && listen(l, 1) == 0);
    blen = sizeof b;
    CHECK("abs-name", getsockname(l, (struct sockaddr *)&b, &blen) == 0 && blen == alen &&
                          b.sun_path[0] == 0 && !memcmp(b.sun_path + 1, name, strlen(name)));
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("abs-connect", connect(c, (struct sockaddr *)&a, alen) == 0);
    s = accept(l, 0, 0);
    CHECK("abs-data", write(c, "x", 1) == 1 && read(s, buf, 1) == 1 && buf[0] == 'x');
    close(s);
    close(c);
    close(l);
    /* Autobind: a bare family binds a five-hex-digit abstract name. */
    int au = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un fam = {.sun_family = AF_UNIX};
    blen = sizeof b;
    CHECK("autobind", bind(au, (struct sockaddr *)&fam, sizeof(sa_family_t)) == 0 &&
                          getsockname(au, (struct sockaddr *)&b, &blen) == 0 &&
                          blen == offsetof(struct sockaddr_un, sun_path) + 6 &&
                          b.sun_path[0] == 0);
    close(au);
}

static void unix_dgram(void) {
    int sv[2];
    CHECK("dgram-pair", socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    send(sv[0], "abc", 3, 0);
    send(sv[0], "defgh", 5, 0);
    char buf[16];
    CHECK("dgram-boundary", recv(sv[1], buf, sizeof buf, 0) == 3);
    CHECK("dgram-trunc", recv(sv[1], buf, 2, 0) == 2);
    send(sv[0], "ijklm", 5, 0);
    CHECK("dgram-trunc-flag", recv(sv[1], buf, 2, MSG_TRUNC) == 5);
    send(sv[0], "no", 2, 0);
    CHECK("dgram-peek", recv(sv[1], buf, sizeof buf, MSG_PEEK) == 2 &&
                            recv(sv[1], buf, sizeof buf, 0) == 2);
    CHECK_ERR("dgram-empty", recv(sv[1], buf, sizeof buf, MSG_DONTWAIT), EAGAIN);
    close(sv[0]);
    close(sv[1]);
}

static void pairs(void) {
    int sv[2];
    CHECK("pair", socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0 &&
                      (fcntl(sv[0], F_GETFD) & FD_CLOEXEC));
    /* The descriptors are reserved and written out before the family is
     * asked for a pair. */
    int bad[2] = {-7, -7};
    CHECK_ERR("pair-inet", socketpair(AF_INET, SOCK_STREAM, 0, bad), EOPNOTSUPP);
    CHECK("pair-inet-written", bad[0] > sv[1] && bad[1] == bad[0] + 1);
    char buf[8];
    CHECK("shut-wr", shutdown(sv[0], SHUT_WR) == 0 && read(sv[1], buf, 8) == 0);
    struct pollfd p = {sv[1], POLLIN | POLLRDHUP, 0};
    CHECK("rdhup", poll(&p, 1, 0) == 1 && (p.revents & (POLLIN | POLLRDHUP)) ==
                                               (POLLIN | POLLRDHUP));
    CHECK_ERR("write-after-shut", write(sv[0], "x", 1), EPIPE);
    CHECK("sigpipe", pipes == 1);
    CHECK_ERR("nosignal", send(sv[0], "x", 1, MSG_NOSIGNAL), EPIPE);
    CHECK("nosignal-no-sigpipe", pipes == 1);
    CHECK_ERR("shut-bad-how", shutdown(sv[0], 3), EINVAL);
    close(sv[0]);
    close(sv[1]);
}

static int tcp_listener(struct sockaddr_in *a) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof *a;
    if (bind(l, (struct sockaddr *)a, sizeof *a) || listen(l, 8) ||
        getsockname(l, (struct sockaddr *)a, &len))
        return -1;
    return l;
}

static void tcp(void) {
    struct sockaddr_in a;
    int l = tcp_listener(&a);
    CHECK("tcp-listen", l >= 0 && a.sin_port != 0);
    int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK_ERR("tcp-recv-unconnected", recv(c, &a, 1, 0), ENOTCONN);
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    CHECK_ERR("tcp-peer-unconnected", getpeername(c, (struct sockaddr *)&peer, &plen), ENOTCONN);
    int r = connect(c, (struct sockaddr *)&a, sizeof a);
    CHECK("tcp-connect-nonblock", r == 0 || errno == EINPROGRESS);
    struct pollfd p = {c, POLLOUT, 0};
    CHECK("tcp-connected", poll(&p, 1, 5000) == 1 && getint(c, SOL_SOCKET, SO_ERROR) == 0);
    int s = accept4(l, (struct sockaddr *)&peer, &plen, SOCK_NONBLOCK);
    CHECK("tcp-accept4", s >= 0 && (fcntl(s, F_GETFL) & O_NONBLOCK) &&
                             peer.sin_family == AF_INET &&
                             peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    CHECK_ERR("tcp-nothing", recv(s, &a, 1, 0), EAGAIN);
    fcntl(c, F_SETFL, 0);
    fcntl(s, F_SETFL, 0);
    CHECK("tcp-send", send(c, "abcdef", 6, 0) == 6);
    char buf[16] = {0};
    CHECK("tcp-peek", recv(s, buf, 3, MSG_PEEK) == 3 && !memcmp(buf, "abc", 3));
    CHECK("tcp-waitall", recv(s, buf, 6, MSG_WAITALL) == 6 && !memcmp(buf, "abcdef", 6));
    CHECK_ERR("tcp-dontwait", recv(s, buf, 1, MSG_DONTWAIT), EAGAIN);
    CHECK("tcp-nodelay", getint(c, IPPROTO_TCP, TCP_NODELAY) == 0 &&
                             setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0 &&
                             getint(c, IPPROTO_TCP, TCP_NODELAY) == 1);
    /* A receive timeout. */
    struct timeval tv = {0, 50000};
    CHECK("rcvtimeo-set", setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0);
    double t0 = now();
    CHECK_ERR("rcvtimeo", recv(s, buf, 1, 0), EAGAIN);
    CHECK("rcvtimeo-waited", now() - t0 > 0.03);
    struct timeval got;
    socklen_t gl = sizeof got;
    CHECK("rcvtimeo-get", getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &got, &gl) == 0 &&
                              got.tv_sec == 0 && got.tv_usec == 50000);
    /* Linux doubles a buffer size (for bookkeeping). */
    CHECK("rcvbuf-doubled", setsockopt(s, SOL_SOCKET, SO_RCVBUF, &(int){8192}, sizeof(int)) == 0 &&
                                getint(s, SOL_SOCKET, SO_RCVBUF) == 16384);
    close(c);
    CHECK("tcp-eof", recv(s, buf, 1, 0) == 0);
    close(s);
    /* Binding a port in use, then a refused connection. */
    int d = socket(AF_INET, SOCK_STREAM, 0);
    CHECK_ERR("tcp-addr-in-use", bind(d, (struct sockaddr *)&a, sizeof a), EADDRINUSE);
    CHECK_ERR("accept-not-listening", accept(d, 0, 0), EINVAL);
    close(l);
    CHECK_ERR("tcp-refused", connect(d, (struct sockaddr *)&a, sizeof a), ECONNREFUSED);
    close(d);
    int e = socket(AF_INET, SOCK_STREAM, 0);
    CHECK_ERR("tcp-send-unconnected", send(e, "x", 1, MSG_NOSIGNAL), EPIPE);
    CHECK_ERR("bind-short", bind(e, (struct sockaddr *)&a, 4), EINVAL);
    close(e);
}

static void udp(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0), v = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof a;
    bind(u, (struct sockaddr *)&a, sizeof a);
    getsockname(u, (struct sockaddr *)&a, &len);
    CHECK_ERR("udp-no-dest", send(v, "x", 1, 0), EDESTADDRREQ);
    CHECK("udp-sendto", sendto(v, "ping", 4, 0, (struct sockaddr *)&a, sizeof a) == 4);
    char buf[8];
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    struct sockaddr_in vn;
    socklen_t vl = sizeof vn;
    getsockname(v, (struct sockaddr *)&vn, &vl);
    CHECK("udp-recvfrom", recvfrom(u, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl) == 4 &&
                              fl == sizeof from && from.sin_port == vn.sin_port &&
                              !memcmp(buf, "ping", 4));
    CHECK("udp-connect", connect(v, (struct sockaddr *)&a, sizeof a) == 0 &&
                             send(v, "pong", 4, 0) == 4 && recv(u, buf, sizeof buf, 0) == 4);
    close(u);
    close(v);
}

static void rights(void) {
    int sv[2], pp[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pipe(pp);
    char data = 'r';
    struct iovec io = {&data, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    struct msghdr m = {0};
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof u.buf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &pp[1], sizeof(int));
    CHECK("rights-send", sendmsg(sv[0], &m, 0) == 1);
    close(pp[1]);
    struct msghdr r = {0};
    char got;
    struct iovec rio = {&got, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ru;
    r.msg_iov = &rio;
    r.msg_iovlen = 1;
    r.msg_control = ru.buf;
    r.msg_controllen = sizeof ru.buf;
    CHECK("rights-recv", recvmsg(sv[1], &r, MSG_CMSG_CLOEXEC) == 1 && got == 'r');
    struct cmsghdr *rc = CMSG_FIRSTHDR(&r);
    int fd = -1;
    if (rc && rc->cmsg_level == SOL_SOCKET && rc->cmsg_type == SCM_RIGHTS)
        memcpy(&fd, CMSG_DATA(rc), sizeof fd);
    CHECK("rights-fd", fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) && write(fd, "z", 1) == 1);
    char z = 0;
    CHECK("rights-same-pipe", read(pp[0], &z, 1) == 1 && z == 'z');
    close(fd);
    close(pp[0]);
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, on_pipe);
    creation();
    unix_stream();
    unix_dgram();
    pairs();
    tcp();
    udp();
    rights();
    FINISH();
}
