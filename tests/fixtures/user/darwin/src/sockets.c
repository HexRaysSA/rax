// BSD sockets: creation and lookup errors, the address copy-in rules,
// AF_UNIX names, accept and connect (blocking, non-blocking, refused,
// interrupted), socketpair, sending and receiving (flags echoed,
// truncation, timeouts, MSG_WAITALL, partial sends), SIGPIPE, descriptors
// passed with SCM_RIGHTS (installed where the caller cannot see them,
// cut short, peeked), socket options, ioctls, and a blocking receive
// another thread satisfies.
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define MSG_SKIPCFIL 0x40000

// Private interfaces (bsd/sys/socket_private.h).
struct msghdr_x {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    int msg_iovlen;
    void *msg_control;
    socklen_t msg_controllen;
    int msg_flags;
    size_t msg_datalen;
};
ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
int peeloff(int s, sae_associd_t aid);
int socket_delegate(int domain, int type, int protocol, pid_t epid);

static const char *ename(int e) {
    static char b[16];
    switch (e) {
    case 0: return "0";
    case EPERM: return "EPERM";
    case EINTR: return "EINTR";
    case EBADF: return "EBADF";
    case EACCES: return "EACCES";
    case EFAULT: return "EFAULT";
    case ENOENT: return "ENOENT";
    case EINVAL: return "EINVAL";
    case EMFILE: return "EMFILE";
    case ENOTTY: return "ENOTTY";
    case ENXIO: return "ENXIO";
    case EPIPE: return "EPIPE";
    case EDOM: return "EDOM";
    case EAGAIN: return "EAGAIN";
    case EINPROGRESS: return "EINPROGRESS";
    case EALREADY: return "EALREADY";
    case ENOTSOCK: return "ENOTSOCK";
    case EDESTADDRREQ: return "EDESTADDRREQ";
    case EMSGSIZE: return "EMSGSIZE";
    case EPROTOTYPE: return "EPROTOTYPE";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EADDRINUSE: return "EADDRINUSE";
    case ECONNRESET: return "ECONNRESET";
    case EISCONN: return "EISCONN";
    case ENOTCONN: return "ENOTCONN";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}

static long show(const char *what, long r) {
    printf("%s: %ld %s\n", what, r, ename(r < 0 ? errno : 0));
    return r;
}
#define T(what, expr) (errno = 0, show(what, (long)(expr)))

// The lowest free descriptor (the next one socket() would get).
static int next_fd(void) {
    int fd = dup(0);
    close(fd);
    return fd;
}

// How many descriptors are open.
static int open_fds(void) {
    int n = 0;
    for (int fd = 0; fd < 256; fd++)
        n += fcntl(fd, F_GETFD) != -1;
    return n;
}

static struct sockaddr_in loopback(int port) {
    struct sockaddr_in a = {.sin_len = sizeof a, .sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

// A loopback TCP port nothing listens on.
static int closed_port(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loopback(0);
    bind(s, (struct sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    close(s);
    return ntohs(a.sin_port);
}

static struct sockaddr_un unix_addr(const char *path, socklen_t *len) {
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, path);
    *len = (socklen_t)SUN_LEN(&a);
    return a;
}

static void creation(void) {
    int s = T("socket inet stream", socket(AF_INET, SOCK_STREAM, 0));
    printf("  getfl %#x getfd %d\n", fcntl(s, F_GETFL), fcntl(s, F_GETFD));
    close(s);
    T("socket unknown domain", socket(9999, SOCK_STREAM, 0));
    T("socket inet type 99", socket(AF_INET, 99, 0));
    T("socket stream udp", socket(AF_INET, SOCK_STREAM, IPPROTO_UDP));
    T("socket dgram tcp", socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP));
    T("socket type flag", socket(AF_INET, SOCK_STREAM | 0x800, 0));
    T("socket raw", socket(AF_INET, SOCK_RAW, 0));
    s = T("socket icmp dgram", socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
    close(s);
    T("socket unix seqpacket", socket(AF_UNIX, SOCK_SEQPACKET, 0));
    T("socket unix protocol 1", socket(AF_UNIX, SOCK_STREAM, 1));

    int p[2];
    pipe(p);
    struct sockaddr_in a = loopback(0);
    T("bind -1", bind(-1, (struct sockaddr *)&a, sizeof a));
    T("bind pipe", bind(p[0], (struct sockaddr *)&a, sizeof a));
    T("bind unopened", bind(200, (struct sockaddr *)&a, sizeof a));
    close(p[0]);
    close(p[1]);

    // A full table: socket() allocates first, socketpair() creates first.
    struct rlimit old, low;
    getrlimit(RLIMIT_NOFILE, &old);
    low = old;
    low.rlim_cur = (rlim_t)next_fd();
    setrlimit(RLIMIT_NOFILE, &low);
    T("full: socket unknown domain", socket(9999, SOCK_STREAM, 0));
    T("full: socketpair unknown domain", socketpair(9999, SOCK_STREAM, 0, p));
    T("full: socketpair inet", socketpair(AF_INET, SOCK_STREAM, 0, p));
    T("full: socketpair unix", socketpair(AF_UNIX, SOCK_STREAM, 0, p));
    setrlimit(RLIMIT_NOFILE, &old);
}

static void addresses(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loopback(0);
    T("bind NULL", bind(s, NULL, 16));
    unsigned char big[300] = {0};
    memcpy(big, &a, sizeof a);
    int lens[] = {0, 1, 2, 15, 17, 128, 129, 255, 256};
    for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        char what[32];
        snprintf(what, sizeof what, "bind len %d", lens[i]);
        T(what, bind(s, (struct sockaddr *)big, lens[i]));
    }
    T("connect NULL 16", connect(s, NULL, 16));
    T("connect NULL 200", connect(s, NULL, 200));
    T("connect bad 300", connect(s, (struct sockaddr *)1, 300));
    T("connect bad 16", connect(s, (struct sockaddr *)1, 16));
    struct sockaddr_in6 six = {.sin6_len = sizeof six, .sin6_family = AF_INET6};
    T("bind inet6 to inet", bind(s, (struct sockaddr *)&six, sizeof six));
    close(s);

    s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_storage ss;
    socklen_t l = 0;
    T("getsockname len 0", getsockname(s, (struct sockaddr *)&ss, &l));
    printf("  len %u\n", l);
    l = 16;
    T("getsockname NULL 16", getsockname(s, NULL, &l));
    l = 0;
    T("getsockname NULL 0", getsockname(s, NULL, &l));
    printf("  len %u\n", l);
    T("getsockname bad len", getsockname(s, (struct sockaddr *)&ss, (socklen_t *)1));
    T("getpeername unconnected bad len", getpeername(s, (struct sockaddr *)&ss, (socklen_t *)1));
    T("shutdown 3", shutdown(s, 3));
    T("shutdown unconnected", shutdown(s, SHUT_RDWR));
    close(s);
}

static void local_names(void) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_len = 2, .sun_family = AF_UNIX};
    T("unix bind len 2", bind(s, (struct sockaddr *)&a, 2));
    socklen_t l;
    a = unix_addr("s1", &l);
    a.sun_family = AF_INET;
    T("unix bind family inet", bind(s, (struct sockaddr *)&a, l));
    a.sun_family = 0;
    T("unix bind family 0", bind(s, (struct sockaddr *)&a, l));
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    getsockname(s, (struct sockaddr *)&ss, &sl);
    printf("  name len %u family %u path %s\n", sl, ss.ss_family, ((struct sockaddr_un *)&ss)->sun_path);
    T("unix bind again", bind(s, (struct sockaddr *)&a, l));
    close(s);

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    a = unix_addr("s2", &l);
    T("unix bind sizeof form", bind(s, (struct sockaddr *)&a, sizeof a));
    sl = sizeof ss;
    getsockname(s, (struct sockaddr *)&ss, &sl);
    printf("  name len %u\n", sl);
    int t = socket(AF_UNIX, SOCK_STREAM, 0);
    T("unix bind in use", bind(t, (struct sockaddr *)&a, sizeof a));
    close(t);
    close(s);

    // Paths past sun_path's 104 bytes work within 255.
    char longp[160];
    memset(longp, 'p', 150);
    longp[150] = 0;
    unsigned char raw[256] = {0};
    raw[1] = AF_UNIX;
    memcpy(raw + 2, longp, 150);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    T("unix bind long path", bind(s, (struct sockaddr *)raw, 153));
    sl = sizeof raw;
    getsockname(s, (struct sockaddr *)raw, &sl);
    printf("  name len %u\n", sl);
    T("unix listen long path", listen(s, 1));
    t = socket(AF_UNIX, SOCK_STREAM, 0);
    raw[0] = 0;
    T("unix connect long path", connect(t, (struct sockaddr *)raw, 153));
    close(t);
    close(s);
    unlink(longp);

    t = socket(AF_UNIX, SOCK_STREAM, 0);
    a = unix_addr("missing", &l);
    T("unix connect missing", connect(t, (struct sockaddr *)&a, l));
    close(open("plain", O_CREAT | O_WRONLY, 0600));
    a = unix_addr("plain", &l);
    T("unix connect file", connect(t, (struct sockaddr *)&a, l));
    a = unix_addr("s2", &l);
    T("unix connect stale", connect(t, (struct sockaddr *)&a, l));
    close(t);

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    a = unix_addr("d1", &l);
    bind(s, (struct sockaddr *)&a, l);
    t = socket(AF_UNIX, SOCK_STREAM, 0);
    T("unix connect wrong type", connect(t, (struct sockaddr *)&a, l));
    T("unix listen dgram", listen(s, 1));
    T("unix accept dgram", accept(s, NULL, NULL));
    close(t);
    close(s);

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    a = unix_addr("l1", &l);
    bind(s, (struct sockaddr *)&a, l);
    T("unix accept unlistened", accept(s, NULL, NULL));
    listen(s, 1);
    int c1 = socket(AF_UNIX, SOCK_STREAM, 0), c2 = socket(AF_UNIX, SOCK_STREAM, 0);
    T("unix connect backlog 1", connect(c1, (struct sockaddr *)&a, l));
    T("unix connect past backlog", connect(c2, (struct sockaddr *)&a, l));
    close(c1);
    close(c2);
    close(s);
    unlink("s1");
    unlink("s2");
    unlink("plain");
    unlink("d1");
    unlink("l1");
}

static void accepting(void) {
    socklen_t l;
    struct sockaddr_un a = unix_addr("acc", &l);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(s, (struct sockaddr *)&a, l);
    listen(s, 8);

    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    socklen_t len = 77;
    int n = T("accept NULL name", accept(s, NULL, &len));
    printf("  len %u cloexec %d nonblock %d\n", len, fcntl(n, F_GETFD), (fcntl(n, F_GETFL) & O_NONBLOCK) != 0);
    close(n);
    close(c);

    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    struct sockaddr_storage ss;
    T("accept NULL len", accept(s, (struct sockaddr *)&ss, NULL));
    memset(&ss, 0xa5, sizeof ss);
    len = 4;
    n = T("accept len 4", accept(s, (struct sockaddr *)&ss, &len));
    printf("  len %u family %u byte4 %#x\n", len, ss.ss_family, ((unsigned char *)&ss)[4]);
    close(n);
    close(c);

    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    len = 0;
    n = T("accept len 0", accept(s, (struct sockaddr *)&ss, &len));
    printf("  len %u\n", len);
    close(n);
    close(c);

    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    len = 16;
    n = T("accept bad name", accept(s, (struct sockaddr *)1, &len));
    printf("  len %u\n", len);
    close(n);
    close(c);

    // A length that can be read but not written: the call fails and the
    // descriptor stays.
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    socklen_t *ro = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    *ro = sizeof ss;
    mprotect(ro, 4096, PROT_READ);
    int before = open_fds();
    T("accept read-only len", accept(s, (struct sockaddr *)&ss, ro));
    printf("  descriptors %+d\n", open_fds() - before);
    for (int fd = 255; fd > c; fd--)
        if (fcntl(fd, F_GETFD) != -1) {
            close(fd);
            break;
        }
    munmap(ro, 4096);
    close(c);

    fcntl(s, F_SETFL, O_NONBLOCK | O_ASYNC);
    T("accept nonblocking empty", accept(s, NULL, NULL));
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    n = T("accept nonblocking", accept(s, NULL, NULL));
    int fl = fcntl(n, F_GETFL);
    printf("  nonblock %d async %d cloexec %d\n", (fl & O_NONBLOCK) != 0, (fl & O_ASYNC) != 0, fcntl(n, F_GETFD));
    fcntl(n, F_SETFL, 0);
    close(n);
    close(c);
    close(s);
    unlink("acc");
}

static void connecting(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loopback(0);
    bind(s, (struct sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    listen(s, 8);

    int c = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(c, F_SETFL, O_NONBLOCK);
    long r = T("tcp nonblocking connect", connect(c, (struct sockaddr *)&a, sizeof a));
    if (r == 0)
        printf("tcp nonblocking connect: -1 EINPROGRESS\n");
    struct pollfd p = {.fd = c, .events = POLLOUT};
    poll(&p, 1, 1000);
    T("tcp connect again", connect(c, (struct sockaddr *)&a, sizeof a));
    int n = accept(s, NULL, NULL);
    T("tcp connect listener", connect(s, (struct sockaddr *)&a, sizeof a));
    close(n);
    close(c);

    struct sockaddr_in refused = loopback(closed_port());
    c = socket(AF_INET, SOCK_STREAM, 0);
    T("tcp blocking connect refused", connect(c, (struct sockaddr *)&refused, sizeof refused));
    close(c);
    c = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(c, F_SETFL, O_NONBLOCK);
    T("tcp nonblocking connect refused", connect(c, (struct sockaddr *)&refused, sizeof refused));
    p.fd = c;
    poll(&p, 1, 1000);
    int err = -1;
    l = sizeof err;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &l);
    printf("  so_error %s\n", ename(err));
    getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &l);
    printf("  so_error %s\n", ename(err));
    close(c);

    // Blocking TCP connect of a socket already connected.
    c = socket(AF_INET, SOCK_STREAM, 0);
    T("tcp blocking connect", connect(c, (struct sockaddr *)&a, sizeof a));
    T("tcp blocking connect again", connect(c, (struct sockaddr *)&a, sizeof a));
    n = accept(s, NULL, NULL);
    struct sockaddr_in peer;
    l = sizeof peer;
    T("getpeername", getpeername(c, (struct sockaddr *)&peer, &l));
    printf("  len %u same port %d\n", l, peer.sin_port == a.sin_port);
    shutdown(c, SHUT_RDWR);
    T("getpeername after shutdown", getpeername(c, (struct sockaddr *)&peer, &l));
    T("shutdown again", shutdown(c, SHUT_WR));
    close(n);
    close(c);
    close(s);

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    T("udp listen", listen(u, 1));
    T("udp accept", accept(u, NULL, NULL));
    T("udp send unconnected", send(u, "x", 1, 0));
    close(u);
}

static void pairs(void) {
    int sv[2] = {-1, -1};
    T("socketpair inet", socketpair(AF_INET, SOCK_STREAM, 0, sv));
    T("socketpair inet dgram", socketpair(AF_INET, SOCK_DGRAM, 0, sv));
    int expect = next_fd();
    T("socketpair NULL", socketpair(AF_UNIX, SOCK_STREAM, 0, NULL));
    printf("  no leak %d\n", next_fd() == expect);
    T("socketpair unix", socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    printf("  ordered %d\n", sv[0] < sv[1]);
    int v;
    socklen_t l = sizeof v;
    getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &v, &l);
    printf("  sndbuf %d", v);
    getsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &v, &l);
    printf(" rcvbuf %d", v);
    getsockopt(sv[0], SOL_SOCKET, SO_SNDLOWAT, &v, &l);
    printf(" sndlowat %d\n", v);
    write(sv[0], "hello", 5);
    struct stat st;
    fstat(sv[1], &st);
    printf("  fstat mode %o size %lld\n", st.st_mode, (long long)st.st_size);
    int nread = -1;
    ioctl(sv[1], FIONREAD, &nread);
    printf("  fionread %d\n", nread);
    char buf[16];
    T("read", read(sv[1], buf, sizeof buf));

    T("send oob", send(sv[0], "x", 1, MSG_OOB));
    T("send eor", send(sv[0], "x", 1, MSG_EOR));
    T("recv oob", recv(sv[1], buf, 1, MSG_OOB));
    T("recv len 0", recv(sv[1], buf, 0, 0));
    T("recv dontwait", recv(sv[1], buf, 1, MSG_DONTWAIT));
    write(sv[0], "abc", 3);
    struct iovec iov = {buf, sizeof buf};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_namelen = 99, .msg_controllen = 77};
    T("recvmsg peek", recvmsg(sv[1], &m, MSG_PEEK));
    printf("  flags %#x namelen %u controllen %u\n", m.msg_flags, m.msg_namelen, m.msg_controllen);
    T("recvmsg peek dontwait", recvmsg(sv[1], &m, MSG_PEEK | MSG_DONTWAIT));
    printf("  flags %#x\n", m.msg_flags);
    T("recv", recv(sv[1], buf, sizeof buf, 0));
    m.msg_iovlen = 0;
    T("recvmsg iovlen 0", recvmsg(sv[1], &m, 0));

    // Timeouts: a receive and a MSG_WAITALL one that keeps its data.
    struct timeval tv = {0, 60000};
    T("rcvtimeo short", setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, 8));
    struct timeval bad = {0, 1000000};
    T("rcvtimeo usec", setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &bad, sizeof bad));
    T("rcvtimeo", setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv));
    unsigned char got[16];
    socklen_t gl = 8;
    T("get rcvtimeo 8", getsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, got, &gl));
    printf("  len %u\n", gl);
    T("recv timeout", recv(sv[1], buf, 1, 0));
    write(sv[0], "12345", 5);
    T("recv waitall timeout", recv(sv[1], buf, 10, MSG_WAITALL));
    T("recv after", recv(sv[1], buf, 10, 0));
    write(sv[0], "12345", 5);
    shutdown(sv[0], SHUT_WR);
    T("recv waitall eof", recv(sv[1], buf, 10, MSG_WAITALL));
    close(sv[0]);
    close(sv[1]);

    // A send larger than the buffer returns what fit when its timeout
    // passes; MSG_DONTWAIT does not stop a send from waiting.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    T("sndtimeo", setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv));
    char *mb = calloc(1, 1 << 20);
    T("send partial", send(sv[0], mb, 1 << 20, 0));
    T("send full dontwait", send(sv[0], mb, 100, MSG_DONTWAIT));
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    T("send full nonblocking", send(sv[0], mb, 100, 0));
    free(mb);
    close(sv[0]);
    close(sv[1]);

    // Datagrams: truncation, sizes, a closed peer.
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    send(sv[0], "abc", 3, 0);
    iov.iov_len = 2;
    m.msg_iovlen = 1;
    m.msg_name = NULL;
    m.msg_control = NULL;
    T("recvmsg dgram short", recvmsg(sv[1], &m, 0));
    printf("  flags %#x\n", m.msg_flags);
    char dg[4096] = {0};
    T("send dgram 2048", send(sv[0], dg, 2048, 0));
    T("send dgram 2049", send(sv[0], dg, 2049, 0));
    T("recv dgram", recv(sv[1], dg, sizeof dg, 0));
    send(sv[0], "", 0, 0);
    T("recv empty dgram", recv(sv[1], dg, sizeof dg, 0));
    socklen_t fl = 16;
    send(sv[0], "z", 1, 0);
    T("recvfrom bad from", recvfrom(sv[1], dg, sizeof dg, 0, (struct sockaddr *)1, &fl));
    printf("  fromlen %u\n", fl);
    close(sv[1]);
    T("send dgram closed peer", send(sv[0], "x", 1, 0));
    T("send dgram closed peer again", send(sv[0], "x", 1, 0));
    close(sv[0]);

    T("sendmsg -1 NULL", sendmsg(-1, NULL, 0));
    struct msghdr z = {0};
    T("sendmsg -1 iovlen 0", sendmsg(-1, &z, 0));
    T("sendto -1 huge", sendto(-1, buf, (size_t)1 << 63, 0, NULL, 0));
    T("sendto skipcfil", sendto(-1, buf, 1, MSG_SKIPCFIL, NULL, 0));
    T("recvfrom -1 bad len", recvfrom(-1, buf, 1, 0, (struct sockaddr *)buf, (socklen_t *)1));
}

static volatile int pipes;
static void on_pipe(int sig) {
    (void)sig;
    pipes++;
}

static void broken(void) {
    signal(SIGPIPE, on_pipe);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    close(sv[1]);
    struct iovec iov = {"x", 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    pipes = 0;
    T("write broken", write(sv[0], "x", 1));
    T("writev broken", writev(sv[0], &iov, 1));
    T("send broken", send(sv[0], "x", 1, 0));
    T("sendto broken", sendto(sv[0], "x", 1, 0, NULL, 0));
    T("sendmsg broken", sendmsg(sv[0], &m, 0));
    printf("  sigpipes %d\n", pipes);
    pipes = 0;
    T("send nosignal", send(sv[0], "x", 1, MSG_NOSIGNAL));
    // A socket shut down both ways takes no options.
    int one = 1;
    T("set nosigpipe after close", setsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one));
    printf("  sigpipes %d\n", pipes);
    close(sv[0]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    T("set nosigpipe", setsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one));
    close(sv[1]);
    T("write nosigpipe", write(sv[0], "x", 1));
    T("send nosigpipe", send(sv[0], "x", 1, 0));
    T("sendmsg nosigpipe", sendmsg(sv[0], &m, 0));
    int v = 0;
    socklen_t l = sizeof v;
    getsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &v, &l);
    printf("  sigpipes %d so_nosigpipe %d\n", pipes, v);
    close(sv[0]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    T("f_setnosigpipe", fcntl(sv[0], F_SETNOSIGPIPE, 1));
    printf("  getnosigpipe %d\n", fcntl(sv[0], F_GETNOSIGPIPE));
    close(sv[1]);
    T("write f_setnosigpipe", write(sv[0], "x", 1));
    printf("  sigpipes %d\n", pipes);
    close(sv[0]);
    // A datagram socket whose peer is gone gets ECONNRESET, no signal.
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    close(sv[1]);
    T("send dgram gone", send(sv[0], "x", 1, 0));
    printf("  sigpipes %d\n", pipes);
    close(sv[0]);
    signal(SIGPIPE, SIG_DFL);
}

static int send_fds(int s, const int *fds, int n) {
    char cbuf[CMSG_SPACE(sizeof(int) * 8)];
    struct iovec iov = {"f", 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = CMSG_LEN(sizeof(int) * n)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_len = CMSG_LEN(sizeof(int) * n);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(c), fds, sizeof(int) * n);
    return (int)sendmsg(s, &m, 0);
}

static void rights(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int p[2];
    pipe(p);
    write(p[1], "through", 7);

    T("send rights", send_fds(sv[0], &p[0], 1));
    int hole = dup(0);
    int keep = dup(0);
    close(hole);
    char cbuf[CMSG_SPACE(sizeof(int) * 8)];
    char buf[16];
    struct iovec iov = {buf, sizeof buf};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf};
    T("recv rights", recvmsg(sv[1], &m, 0));
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    int got;
    memcpy(&got, CMSG_DATA(c), sizeof got);
    printf("  controllen %u level %d type %d len %u fd in the hole %d cloexec %d\n", m.msg_controllen, c->cmsg_level,
           c->cmsg_type, c->cmsg_len, got == hole, fcntl(got, F_GETFD));
    memset(buf, 0, sizeof buf);
    read(got, buf, 7);
    printf("  read through it: %s\n", buf);
    close(got);
    close(keep);

    int kq = kqueue();
    T("send kqueue", send_fds(sv[0], &kq, 1));
    close(kq);
    int closed = 150;
    T("send closed", send_fds(sv[0], &closed, 1));
    int both[2] = {p[0], p[1]};
    // Two messages, or a length short of the buffer, are refused.
    char two[2 * CMSG_SPACE(sizeof(int))];
    memset(two, 0, sizeof two);
    struct iovec x = {"x", 1};
    struct msghdr bad = {.msg_iov = &x, .msg_iovlen = 1, .msg_control = two, .msg_controllen = sizeof two};
    struct cmsghdr *h = CMSG_FIRSTHDR(&bad);
    h->cmsg_len = CMSG_LEN(sizeof(int));
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(h), &p[0], sizeof(int));
    h = CMSG_NXTHDR(&bad, h);
    h->cmsg_len = CMSG_LEN(sizeof(int));
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(h), &p[1], sizeof(int));
    T("send two messages", sendmsg(sv[0], &bad, 0));
    bad.msg_controllen = 11;
    T("send control 11", sendmsg(sv[0], &bad, 0));
    bad.msg_controllen = 1031;
    T("send control 1031", sendmsg(sv[0], &bad, 0));
    h = CMSG_FIRSTHDR(&bad);
    h->cmsg_type = SCM_CREDS;
    bad.msg_controllen = CMSG_LEN(sizeof(int));
    T("send creds", sendmsg(sv[0], &bad, 0));

    // Two descriptors into room for one: cut short, the other installed
    // unseen; no buffer at all: both installed; a peek makes none.
    T("send two", send_fds(sv[0], both, 2));
    int before = open_fds();
    m.msg_controllen = CMSG_SPACE(sizeof(int));
    T("recv into room for one", recvmsg(sv[1], &m, 0));
    c = CMSG_FIRSTHDR(&m);
    printf("  flags %#x controllen %u cmsg_len %u descriptors %+d\n", m.msg_flags, m.msg_controllen, c->cmsg_len,
           open_fds() - before);
    send_fds(sv[0], both, 2);
    before = open_fds();
    m.msg_control = NULL;
    m.msg_controllen = 55;
    T("recv without control", recvmsg(sv[1], &m, 0));
    printf("  flags %#x controllen %u descriptors %+d\n", m.msg_flags, m.msg_controllen, open_fds() - before);
    send_fds(sv[0], both, 1);
    before = open_fds();
    T("read with rights", read(sv[1], buf, 1));
    printf("  descriptors %+d\n", open_fds() - before);
    send_fds(sv[0], both, 1);
    before = open_fds();
    m.msg_control = cbuf;
    m.msg_controllen = sizeof cbuf;
    T("peek rights", recvmsg(sv[1], &m, MSG_PEEK));
    c = CMSG_FIRSTHDR(&m);
    memcpy(&got, CMSG_DATA(c), sizeof got);
    printf("  slot %d descriptors %+d\n", got, open_fds() - before);
    for (int fd = 255; fd > sv[1]; fd--)
        if (fd != p[0] && fd != p[1])
            close(fd);
    close(sv[0]);
    close(sv[1]);

    // TCP drops control data.
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loopback(0);
    bind(s, (struct sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    listen(s, 1);
    int t = socket(AF_INET, SOCK_STREAM, 0);
    connect(t, (struct sockaddr *)&a, sizeof a);
    int n = accept(s, NULL, NULL);
    T("tcp send rights", send_fds(t, &p[0], 1));
    m.msg_controllen = sizeof cbuf;
    T("tcp recv", recvmsg(n, &m, 0));
    printf("  controllen %u\n", m.msg_controllen);
    close(n);
    close(t);
    close(s);
    close(p[0]);
    close(p[1]);
}

static void options(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    unsigned char v[64];
    memset(v, 0xa5, sizeof v);
    socklen_t l = 2;
    T("get type len 2", getsockopt(s, SOL_SOCKET, SO_TYPE, v, &l));
    printf("  len %u bytes %02x %02x %02x\n", l, v[0], v[1], v[2]);
    l = 0;
    T("get type len 0", getsockopt(s, SOL_SOCKET, SO_TYPE, v, &l));
    printf("  len %u\n", l);
    l = 64;
    T("get type NULL", getsockopt(s, SOL_SOCKET, SO_TYPE, NULL, &l));
    printf("  len %u\n", l);
    l = 4;
    T("get type bad", getsockopt(s, SOL_SOCKET, SO_TYPE, (void *)1, &l));
    int one = 1;
    T("set reuseaddr len 2", setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, 2));
    T("set reuseaddr len 64", setsockopt(s, SOL_SOCKET, SO_REUSEADDR, v, 64));
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    int got = 0;
    l = sizeof got;
    getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &got, &l);
    printf("  reuseaddr %d", got);
    getsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &got, &l);
    printf(" keepalive %d\n", got);
    T("get acceptconn", getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &got, &l));
    T("set type", setsockopt(s, SOL_SOCKET, SO_TYPE, &one, sizeof one));
    T("set unknown", setsockopt(s, SOL_SOCKET, 0x7777, &one, sizeof one));
    T("set NULL 4 on -1", setsockopt(-1, SOL_SOCKET, SO_REUSEADDR, NULL, 4));
    T("tcp nodelay len 2", setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, 2));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    l = sizeof got;
    getsockopt(s, IPPROTO_TCP, TCP_NODELAY, &got, &l);
    printf("  nodelay %d\n", got);
    struct linger lg = {1, 5};
    setsockopt(s, SOL_SOCKET, SO_LINGER_SEC, &lg, sizeof lg);
    l = sizeof lg;
    getsockopt(s, SOL_SOCKET, SO_LINGER, &lg, &l);
    printf("  linger %d %d\n", lg.l_onoff, lg.l_linger);
    T("set sndbuf 0", setsockopt(s, SOL_SOCKET, SO_SNDBUF, &(int){0}, sizeof(int)));
    close(s);

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pid_t pid = -1;
    l = sizeof pid;
    T("peer pid", getsockopt(sv[0], SOL_LOCAL, LOCAL_PEERPID, &pid, &l));
    printf("  own %d\n", pid == getpid());
    struct xucred cr;
    l = sizeof cr;
    T("peer cred", getsockopt(sv[0], SOL_LOCAL, LOCAL_PEERCRED, &cr, &l));
    printf("  len %u uid %d\n", l, cr.cr_uid == geteuid());
    T("set local", setsockopt(sv[0], SOL_LOCAL, LOCAL_PEERPID, &one, sizeof one));
    close(sv[0]);
    close(sv[1]);
    int d[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, d);
    l = sizeof cr;
    T("dgram peer cred", getsockopt(d[0], SOL_LOCAL, LOCAL_PEERCRED, &cr, &l));
    close(d[0]);
    close(d[1]);
}

static void ioctls(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int on = 1;
    T("fionbio", ioctl(s, FIONBIO, &on));
    printf("  getfl nonblock %d\n", (fcntl(s, F_GETFL) & O_NONBLOCK) != 0);
    int own = 1234;
    ioctl(s, FIOSETOWN, &own);
    int back = 777;
    T("fiogetown", ioctl(s, FIOGETOWN, &back));
    printf("  buffer %d\n", back);
    char buf[4096];
    struct ifconf ifc = {.ifc_len = sizeof buf, .ifc_buf = buf};
    T("siocgifconf", ioctl(s, SIOCGIFCONF, &ifc));
    printf("  some %d first lo0 %d\n", ifc.ifc_len > 0, strcmp(((struct ifreq *)buf)->ifr_name, "lo0") == 0);
    ifc.ifc_len = 16;
    T("siocgifconf small", ioctl(s, SIOCGIFCONF, &ifc));
    printf("  len %d\n", ifc.ifc_len);
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (void *)8;
    T("siocgifconf bad buffer", ioctl(s, SIOCGIFCONF, &ifc));
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo0");
    T("siocgifflags lo0", ioctl(s, SIOCGIFFLAGS, &ifr));
    printf("  flags %#x\n", ifr.ifr_flags & 0xffff);
    strcpy(ifr.ifr_name, "nosuch0");
    T("siocgifflags missing", ioctl(s, SIOCGIFFLAGS, &ifr));
    struct winsize ws;
    T("tiocgwinsz", ioctl(s, TIOCGWINSZ, &ws));
    struct if_clonereq cr = {0};
    T("siocifgcloners count", ioctl(s, SIOCIFGCLONERS, &cr));
    printf("  some %d\n", cr.ifcr_total > 0);
    close(s);
}

// Datagrams that arrive on `fd` within a short wait, up to `want`.
static int drain(int fd, int want) {
    int n = 0;
    char buf[64];
    struct pollfd p = {.fd = fd, .events = POLLIN};
    while (n < want && poll(&p, 1, 500) > 0)
        n += recv(fd, buf, sizeof buf, MSG_DONTWAIT) >= 0;
    // Anything more would be an error; look briefly.
    while (poll(&p, 1, 50) > 0 && recv(fd, buf, sizeof buf, MSG_DONTWAIT) >= 0)
        n++;
    return n;
}

static void extended(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loopback(0);
    bind(s, (struct sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    listen(s, 4);
    sa_endpoints_t ep = {.sae_dstaddr = (struct sockaddr *)&a, .sae_dstaddrlen = sizeof a};
    T("connectx -1", connectx(-1, NULL, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL));
    int c = socket(AF_INET, SOCK_STREAM, 0);
    T("connectx no endpoints", connectx(c, NULL, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL));
    sa_endpoints_t none = {0};
    T("connectx no destination", connectx(c, &none, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL));
    sa_endpoints_t shortd = ep;
    shortd.sae_dstaddrlen = 1;
    T("connectx short destination", connectx(c, &shortd, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL));
    struct iovec iov = {"hello", 5};
    size_t len = 99;
    T("connectx iovcnt 0", connectx(c, &ep, SAE_ASSOCID_ANY, 0, &iov, 0, &len, NULL));
    T("connectx no len", connectx(c, &ep, SAE_ASSOCID_ANY, 0, &iov, 1, NULL, NULL));
    sae_connid_t cid = 77;
    T("connectx with data", connectx(c, &ep, SAE_ASSOCID_ANY, 0, &iov, 1, &len, &cid));
    printf("  len %zu cid %u\n", len, cid);
    int n = accept(s, NULL, NULL);
    char buf[16] = {0};
    struct pollfd p = {.fd = n, .events = POLLIN};
    poll(&p, 1, 2000);
    T("peer got", recv(n, buf, sizeof buf, MSG_DONTWAIT));
    T("connectx connected", connectx(c, &ep, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL));
    T("disconnectx bad association", disconnectx(c, 5, SAE_CONNID_ANY));
    T("disconnectx", disconnectx(c, SAE_ASSOCID_ANY, SAE_CONNID_ANY));
    T("disconnectx again", disconnectx(c, SAE_ASSOCID_ALL, SAE_CONNID_ANY));
    close(n);
    close(c);
    close(s);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    T("connectx unix", connectx(sv[0], &ep, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL));
    T("disconnectx unix", disconnectx(sv[0], SAE_ASSOCID_ANY, SAE_CONNID_ANY));
    close(sv[0]);
    close(sv[1]);
    T("peeloff -1", peeloff(-1, 0));
    T("socket_delegate", socket_delegate(AF_INET, SOCK_STREAM, 0, getpid()));
    T("socket_delegate bad domain", socket_delegate(9999, SOCK_STREAM, 0, getpid()));

    // Datagrams in arrays (a local pair queues them at once).
    int dp[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, dp);
    char d40[40], d10[10];
    memset(d40, 'a', sizeof d40);
    memset(d10, 'b', sizeof d10);
    send(dp[1], d40, sizeof d40, 0);
    send(dp[1], d10, sizeof d10, 0);
    char b0[10], b1[12], b2[12];
    struct iovec i0 = {b0, sizeof b0}, i1 = {b1, sizeof b1}, i2 = {b2, sizeof b2};
    struct sockaddr_storage from;
    struct msghdr_x mx[3] = {
        {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &i0, .msg_iovlen = 1},
        {.msg_iov = &i1, .msg_iovlen = 1},
        {.msg_iov = &i2, .msg_iovlen = 1, .msg_datalen = 12345, .msg_namelen = 128},
    };
    T("recvmsg_x cnt 0", recvmsg_x(dp[0], mx, 0, 0));
    T("recvmsg_x peek", recvmsg_x(dp[0], mx, 3, MSG_PEEK));
    T("recvmsg_x", recvmsg_x(dp[0], mx, 3, MSG_DONTWAIT));
    printf("  0: datalen %zu flags %#x namelen %u; 1: datalen %zu; 2: datalen %zu namelen %u\n", mx[0].msg_datalen,
           mx[0].msg_flags, mx[0].msg_namelen, mx[1].msg_datalen, mx[2].msg_datalen, mx[2].msg_namelen);
    send(dp[1], d10, sizeof d10, 0);
    T("recvmsg_x bad array", recvmsg_x(dp[0], (struct msghdr_x *)1, 1, 0));
    T("recvmsg_x after", recvmsg_x(dp[0], mx, 1, MSG_DONTWAIT));
    send(dp[1], d10, sizeof d10, 0);
    mx[0].msg_iovlen = 0;
    T("recvmsg_x iovlen 0", recvmsg_x(dp[0], mx, 1, 0));
    mx[0].msg_iovlen = 1;
    T("recvmsg_x after", recvmsg_x(dp[0], mx, 1, MSG_DONTWAIT));
    // A blocking receive sleeps for the first message.
    struct timeval tv = {0, 50000};
    setsockopt(dp[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    T("recvmsg_x timeout", recvmsg_x(dp[0], mx, 1, 0));
    close(dp[0]);
    close(dp[1]);

    int u = socket(AF_INET, SOCK_DGRAM, 0), v = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ua = loopback(0);
    bind(u, (struct sockaddr *)&ua, sizeof ua);
    l = sizeof ua;
    getsockname(u, (struct sockaddr *)&ua, &l);
    connect(v, (struct sockaddr *)&ua, sizeof ua);
    struct iovec o0 = {"one", 3}, o1 = {"two", 3}, o2 = {"three", 5};
    struct msghdr_x sx[3] = {{.msg_iov = &o0, .msg_iovlen = 1}, {.msg_iov = &o1, .msg_iovlen = 1},
                             {.msg_iov = &o2, .msg_iovlen = 1}};
    T("sendmsg_x skipcfil", sendmsg_x(v, sx, 3, MSG_SKIPCFIL));
    T("sendmsg_x cnt 0", sendmsg_x(v, sx, 0, 0));
    T("sendmsg_x", sendmsg_x(v, sx, 3, 0));
    printf("  received %d\n", drain(u, 3));
    sx[1].msg_iovlen = 0;
    T("sendmsg_x second bad", sendmsg_x(v, sx, 3, 0));
    printf("  received %d\n", drain(u, 3));
    sx[1].msg_iovlen = 1;
    T("sendmsg_x oob", sendmsg_x(v, sx, 3, MSG_OOB));
    int w = socket(AF_INET, SOCK_DGRAM, 0);
    T("sendmsg_x unconnected", sendmsg_x(w, sx, 3, 0));
    close(w);
    close(u);
    close(v);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    T("sendmsg_x stream", sendmsg_x(sv[0], sx, 3, 0));
    char four[4];
    struct iovec f = {four, sizeof four};
    struct msghdr_x one = {.msg_iov = &f, .msg_iovlen = 1};
    T("recvmsg_x stream", recvmsg_x(sv[1], &one, 1, 0));
    printf("  datalen %zu rest %ld\n", one.msg_datalen, recv(sv[1], buf, sizeof buf, MSG_DONTWAIT));
    close(sv[0]);
    close(sv[1]);
}

static void on_alarm(int sig) { (void)sig; }

static void *late_connect(void *arg) {
    usleep(100000);
    socklen_t l;
    struct sockaddr_un a = unix_addr((const char *)arg, &l);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, l);
    return (void *)(long)c;
}

static void *late_write(void *arg) {
    usleep(50000);
    write(*(int *)arg, "late", 4);
    return NULL;
}

static void interruption(void) {
    socklen_t l;
    struct sockaddr_un a = unix_addr("intr", &l);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(s, (struct sockaddr *)&a, l);
    listen(s, 4);
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = {.it_value = {0, 50000}};
    setitimer(ITIMER_REAL, &it, NULL);
    T("accept interrupted", accept(s, NULL, NULL));
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);
    setitimer(ITIMER_REAL, &it, NULL);
    pthread_t th;
    pthread_create(&th, NULL, late_connect, "intr");
    int n = T("accept restarted", accept(s, NULL, NULL) >= 0 ? 0 : -1);
    void *c;
    pthread_join(th, &c);
    (void)n;
    close((int)(long)c);
    close(s);
    unlink("intr");

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);
    setitimer(ITIMER_REAL, &it, NULL);
    char buf[8];
    T("recv interrupted", recv(sv[1], buf, sizeof buf, 0));
    pthread_create(&th, NULL, late_write, &sv[0]);
    T("recv from another thread", recv(sv[1], buf, sizeof buf, 0));
    pthread_join(th, NULL);
    close(sv[0]);
    close(sv[1]);
    signal(SIGALRM, SIG_DFL);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char dir[] = "/tmp/rax-sockets.XXXXXX";
    mkdtemp(dir);
    chdir(dir);
    creation();
    addresses();
    local_names();
    accepting();
    connecting();
    pairs();
    broken();
    rights();
    options();
    ioctls();
    extended();
    interruption();
    chdir("/");
    rmdir(dir);
    return 0;
}
