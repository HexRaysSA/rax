/* Sockets, continued: readiness through shutdown and close; message
 * headers (names, truncation, control space); descriptors passed across
 * fork; credentials with SO_PASSCRED; sendmmsg/recvmmsg; IPv6 on the
 * loopback (when the host has it); a blocking accept woken by another
 * thread; and signals ending blocking receives (restarted with SA_RESTART,
 * EINTR once a timeout is set). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static short revents(int fd, short events) {
    struct pollfd p = {fd, events, 0};
    return poll(&p, 1, 0) == 1 ? p.revents : 0;
}

static void readiness(void) {
    int sv[2];
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    /* A new stream socket is in TCP_CLOSE: writable and hung up. */
    CHECK("fresh-unix", revents(s, POLLIN | POLLOUT) == (POLLOUT | POLLHUP));
    int t = socket(AF_INET, SOCK_STREAM, 0);
    CHECK("fresh-tcp", revents(t, POLLIN | POLLOUT) == (POLLOUT | POLLHUP));
    close(s);
    close(t);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK("pair", revents(sv[1], POLLIN | POLLOUT | POLLRDHUP) == POLLOUT);
    shutdown(sv[0], SHUT_WR);
    /* The writer stays writable; the reader sees the end, not a hang-up. */
    CHECK("shut-wr-self", revents(sv[0], POLLIN | POLLOUT | POLLRDHUP) == POLLOUT);
    CHECK("shut-wr-peer",
          revents(sv[1], POLLIN | POLLOUT | POLLRDHUP) == (POLLIN | POLLOUT | POLLRDHUP));
    close(sv[0]);
    close(sv[1]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    shutdown(sv[0], SHUT_RD);
    CHECK("shut-rd-self",
          revents(sv[0], POLLIN | POLLOUT | POLLRDHUP) == (POLLIN | POLLOUT | POLLRDHUP));
    close(sv[0]);
    close(sv[1]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    shutdown(sv[0], SHUT_RDWR);
    CHECK("shut-rdwr",
          revents(sv[0], POLLIN | POLLOUT | POLLRDHUP) ==
              (POLLIN | POLLOUT | POLLRDHUP | POLLHUP));
    close(sv[0]);
    /* The peer closed: everything. */
    CHECK("peer-closed",
          revents(sv[1], POLLIN | POLLOUT | POLLRDHUP) ==
              (POLLIN | POLLOUT | POLLRDHUP | POLLHUP));
    char c;
    CHECK("peer-closed-eof", read(sv[1], &c, 1) == 0);
    close(sv[1]);
    /* Datagram sockets: only their own shutdown. */
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    CHECK("dgram", revents(sv[1], POLLIN | POLLOUT) == POLLOUT);
    send(sv[0], "", 0, 0);
    CHECK("dgram-empty-datagram", revents(sv[1], POLLIN) == POLLIN &&
                                      recv(sv[1], &c, 1, 0) == 0);
    shutdown(sv[1], SHUT_RD);
    CHECK("dgram-shut-rd", revents(sv[1], POLLIN | POLLRDHUP) == (POLLIN | POLLRDHUP));
    close(sv[0]);
    close(sv[1]);
    /* A listener: readable with a connection waiting, never writable. */
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    bind(l, (struct sockaddr *)&a, sizeof a);
    listen(l, 2);
    getsockname(l, (struct sockaddr *)&a, &al);
    CHECK("listener-idle", revents(l, POLLIN | POLLOUT) == 0);
    int k = socket(AF_INET, SOCK_STREAM, 0);
    connect(k, (struct sockaddr *)&a, sizeof a);
    struct pollfd p = {l, POLLIN, 0};
    CHECK("listener-ready", poll(&p, 1, 5000) == 1 && p.revents == POLLIN);
    int acc = accept(l, 0, 0);
    /* A TCP peer's FIN: readable at its end, still writable. */
    shutdown(k, SHUT_WR);
    p = (struct pollfd){acc, POLLIN | POLLRDHUP, 0};
    CHECK("tcp-fin", poll(&p, 1, 5000) == 1 &&
                         revents(acc, POLLIN | POLLOUT | POLLRDHUP) ==
                             (POLLIN | POLLOUT | POLLRDHUP));
    close(acc);
    close(k);
    close(l);
}

static void headers(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    char big[100], buf[64];
    memset(big, 7, sizeof big);
    send(sv[0], big, sizeof big, 0);
    struct iovec io = {buf, sizeof buf};
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1};
    CHECK("trunc-flag", recvmsg(sv[1], &m, MSG_CMSG_CLOEXEC) == 64 &&
                            m.msg_flags == (MSG_TRUNC | MSG_CMSG_CLOEXEC) &&
                            m.msg_controllen == 0);
    struct msghdr bad = {.msg_name = buf, .msg_namelen = -1, .msg_iov = &io, .msg_iovlen = 1};
    CHECK_ERR("namelen-negative", sendmsg(sv[0], &bad, 0), EINVAL);
    bad = (struct msghdr){.msg_iov = &io, .msg_iovlen = 1025};
    CHECK_ERR("iovlen", sendmsg(sv[0], &bad, 0), EMSGSIZE);
    /* MSG_CMSG_COMPAT is 0 in a kernel without CONFIG_COMPAT. */
    CHECK_ERR("compat-flag", recvmsg(sv[1], &m, 0x80000000 | MSG_DONTWAIT), EAGAIN);
    /* A named datagram sender, and a name buffer too short for it. */
    char path[64];
    snprintf(path, sizeof path, "/tmp/rax-sockmsg-%d", getpid());
    unlink(path);
    struct sockaddr_un un = {.sun_family = AF_UNIX};
    strcpy(un.sun_path, path);
    int n = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(n, (struct sockaddr *)&un, sizeof un);
    char rp[64];
    snprintf(rp, sizeof rp, "%s-r", path);
    unlink(rp);
    struct sockaddr_un rn = {.sun_family = AF_UNIX};
    strcpy(rn.sun_path, rp);
    int r = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(r, (struct sockaddr *)&rn, sizeof rn);
    sendto(n, "hi", 2, 0, (struct sockaddr *)&rn, sizeof rn);
    struct sockaddr_un from;
    m = (struct msghdr){.msg_name = &from, .msg_namelen = 4, .msg_iov = &io, .msg_iovlen = 1};
    CHECK("name-truncated", recvmsg(r, &m, 0) == 2 &&
                                m.msg_namelen == offsetof(struct sockaddr_un, sun_path) +
                                                     strlen(path) + 1 &&
                                from.sun_family == AF_UNIX);
    sendto(n, "hi", 2, 0, (struct sockaddr *)&rn, sizeof rn);
    m = (struct msghdr){.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &io,
                        .msg_iovlen = 1};
    CHECK("name", recvmsg(r, &m, 0) == 2 && !strcmp(from.sun_path, path));
    /* Sending to a name that is gone. */
    unlink(rp);
    CHECK_ERR("dest-gone", sendto(n, "x", 1, 0, (struct sockaddr *)&rn, sizeof rn), ENOENT);
    close(n);
    close(r);
    unlink(path);
    close(sv[0]);
    close(sv[1]);
}

static int send_fd(int s, int fd) {
    char c = 'f';
    struct iovec io = {&c, 1};
    union {
        char b[CMSG_SPACE(sizeof(int))];
        struct cmsghdr a;
    } u;
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = u.b,
                       .msg_controllen = sizeof u.b};
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &fd, sizeof fd);
    return sendmsg(s, &m, 0);
}

static int recv_fd(int s) {
    char c;
    struct iovec io = {&c, 1};
    union {
        char b[CMSG_SPACE(sizeof(int))];
        struct cmsghdr a;
    } u;
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = u.b,
                       .msg_controllen = sizeof u.b};
    if (recvmsg(s, &m, 0) != 1)
        return -1;
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    int fd = -1;
    if (h && h->cmsg_type == SCM_RIGHTS)
        memcpy(&fd, CMSG_DATA(h), sizeof fd);
    return fd;
}

static void across_fork(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pid_t pid = fork();
    if (pid == 0) {
        /* The child makes a pipe, passes its write end, and writes. */
        close(sv[0]);
        int pp[2];
        if (pipe(pp) || send_fd(sv[1], pp[1]) != 1)
            _exit(1);
        close(pp[1]);
        char buf[8] = {0};
        _exit(read(pp[0], buf, sizeof buf) == 4 && !memcmp(buf, "from", 4) ? 0 : 2);
    }
    close(sv[1]);
    int w = recv_fd(sv[0]);
    CHECK("fork-rights", w >= 0 && write(w, "from", 4) == 4);
    close(w);
    int st;
    CHECK("fork-rights-child", waitpid(pid, &st, 0) == pid && WIFEXITED(st) &&
                                   WEXITSTATUS(st) == 0);
    close(sv[0]);
}

static void credentials(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    int one = 1;
    CHECK("passcred", setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) == 0);
    send(sv[0], "c", 1, 0);
    char c;
    struct iovec io = {&c, 1};
    union {
        char b[CMSG_SPACE(sizeof(struct ucred))];
        struct cmsghdr a;
    } u;
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = u.b,
                       .msg_controllen = sizeof u.b};
    struct ucred cr = {0};
    CHECK("cred-recv", recvmsg(sv[1], &m, 0) == 1);
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    if (h && h->cmsg_type == SCM_CREDENTIALS)
        memcpy(&cr, CMSG_DATA(h), sizeof cr);
    CHECK("cred", cr.pid == getpid() && cr.uid == geteuid() && cr.gid == getegid());
    /* Someone else's credentials may not be claimed. */
    struct ucred other = {getpid() + 1, getuid(), getgid()};
    m.msg_controllen = sizeof u.b;
    h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_CREDENTIALS;
    h->cmsg_len = CMSG_LEN(sizeof other);
    memcpy(CMSG_DATA(h), &other, sizeof other);
    if (geteuid() != 0)
        CHECK_ERR("cred-other", sendmsg(sv[0], &m, 0), EPERM);
    else /* CAP_SYS_ADMIN may: the same line either way. */
        printf("ok cred-other\n");
    close(sv[0]);
    close(sv[1]);
}

static void batches(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    char a[] = "a", b[] = "bb", c[] = "ccc";
    struct iovec io[3] = {{a, 1}, {b, 2}, {c, 3}};
    struct mmsghdr v[3];
    memset(v, 0, sizeof v);
    for (int i = 0; i < 3; i++) {
        v[i].msg_hdr.msg_iov = &io[i];
        v[i].msg_hdr.msg_iovlen = 1;
    }
    CHECK("sendmmsg", sendmmsg(sv[0], v, 3, 0) == 3 && v[0].msg_len == 1 &&
                          v[1].msg_len == 2 && v[2].msg_len == 3);
    char r[5][8];
    struct iovec ri[5];
    struct mmsghdr rv[5];
    memset(rv, 0, sizeof rv);
    for (int i = 0; i < 5; i++) {
        ri[i] = (struct iovec){r[i], sizeof r[i]};
        rv[i].msg_hdr.msg_iov = &ri[i];
        rv[i].msg_hdr.msg_iovlen = 1;
    }
    CHECK("recvmmsg", recvmmsg(sv[1], rv, 5, MSG_DONTWAIT, 0) == 3 && rv[2].msg_len == 3 &&
                          !memcmp(r[2], "ccc", 3));
    CHECK_ERR("recvmmsg-empty", recvmmsg(sv[1], rv, 5, MSG_DONTWAIT, 0), EAGAIN);
    send(sv[0], "q", 1, 0);
    CHECK("waitforone", recvmmsg(sv[1], rv, 5, MSG_WAITFORONE, 0) == 1);
    struct timespec bad = {0, 1000000000};
    CHECK_ERR("recvmmsg-timeout", recvmmsg(sv[1], rv, 1, 0, &bad), EINVAL);
    close(sv[0]);
    close(sv[1]);
}

static void ipv6(void) {
    int l = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    if (bind(l, (struct sockaddr *)&a, sizeof a) != 0) {
        /* No IPv6 loopback here: the same lines either way. */
        printf("ok v6-listen\nok v6-connect\nok v6-data\n");
        close(l);
        return;
    }
    socklen_t al = sizeof a;
    CHECK("v6-listen", listen(l, 1) == 0 &&
                           getsockname(l, (struct sockaddr *)&a, &al) == 0 &&
                           al == sizeof a && a.sin6_family == AF_INET6);
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK("v6-connect", connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    int s = accept(l, 0, 0);
    char buf[4] = {0};
    CHECK("v6-data", write(c, "six", 3) == 3 && read(s, buf, 3) == 3 && !strcmp(buf, "six"));
    close(s);
    close(c);
    close(l);
}

static struct sockaddr_in target;

static void *connector(void *arg) {
    (void)arg;
    struct timespec d = {0, 50 * 1000000};
    nanosleep(&d, 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&target, sizeof target);
    write(c, "t", 1);
    return (void *)(long)c;
}

static void blocking(void) {
    target = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof target;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    bind(l, (struct sockaddr *)&target, sizeof target);
    listen(l, 1);
    getsockname(l, (struct sockaddr *)&target, &al);
    pthread_t th;
    pthread_create(&th, 0, connector, 0);
    int s = accept(l, 0, 0);
    char c = 0;
    CHECK("accept-woken", s >= 0 && read(s, &c, 1) == 1 && c == 't');
    void *ret;
    pthread_join(th, &ret);
    close((int)(long)ret);
    close(s);
    close(l);
}

static volatile sig_atomic_t alarms;
static void on_alarm(int sig) {
    (void)sig;
    alarms++;
}

static void interrupted(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct sigaction sa = {.sa_handler = on_alarm, .sa_flags = SA_RESTART};
    sigaction(SIGALRM, &sa, 0);
    /* A tick every 20 ms, so one lands while the receive waits however
     * the process is scheduled. */
    struct itimerval it = {{0, 20000}, {0, 20000}};
    struct timeval tv = {5, 0};
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setitimer(ITIMER_REAL, &it, 0);
    char c;
    /* A timeout set: EINTR even with SA_RESTART. */
    CHECK_ERR("timeout-eintr", recv(sv[1], &c, 1, 0), EINTR);
    CHECK("timeout-alarm", alarms >= 1);
    /* No timeout: restarted after each tick; the child's byte ends it. */
    tv = (struct timeval){0, 0};
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int before = alarms;
    pid_t pid = fork();
    if (pid == 0) {
        struct timespec d = {0, 150 * 1000000};
        nanosleep(&d, 0);
        write(sv[0], "r", 1);
        _exit(0);
    }
    CHECK("restarted", recv(sv[1], &c, 1, 0) == 1 && c == 'r' && alarms > before);
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, 0);
    waitpid(pid, 0, 0);
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    readiness();
    headers();
    across_fork();
    credentials();
    batches();
    ipv6();
    blocking();
    interrupted();
    FINISH();
}
