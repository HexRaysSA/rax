/* A send whose data faults part way (net/unix/af_unix.c, net/ipv4/tcp.c):
 * a Unix stream sends the skbs it copied whole before the fault
 * ((sk_sndbuf >> 1) - 64 bytes each, at most SKB_MAX_HEAD(0) + 32 KiB) and
 * none of the one the fault cut short; a datagram is copied whole, from
 * write() as from sendmsg(); TCP copies whole chunks of at most a page
 * fragment (32 KiB) and the size goal (which follows the peer's window,
 * so only a fault within the first chunk is checked). Nothing sent is
 * EFAULT. The sizes stay within what a nonblocking send queues on any
 * host. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#define PAGE 4096

static char *hole;
static char buf[65536];

/* sendmsg of the `ok` bytes before the hole and 5 in it. */
static long msg(int fd, size_t ok) {
    struct iovec v[2] = {{hole - ok, ok}, {hole, 5}};
    struct msghdr m = {.msg_iov = v, .msg_iovlen = 2};
    return sendmsg(fd, &m, MSG_DONTWAIT);
}

/* Receives until `want` bytes arrived or 5 s passed: the count. */
static long drain(int fd, long want) {
    long n = 0;
    for (int i = 0; i < 500; i++) {
        long r;
        while ((r = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            n += r;
        if (n >= want)
            break;
        nanosleep(&(struct timespec){0, 10000000}, NULL);
    }
    return n;
}

int main(void) {
    char *m = mmap(NULL, 16 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(m, 'x', 16 * PAGE);
    hole = m + 12 * PAGE;
    munmap(hole, 4 * PAGE);

    /* A Unix stream: the first skb faults, so nothing is sent. */
    int sv[2];
    CHECK("stream-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK_ERR("stream-first-skb", msg(sv[0], 5), EFAULT);
    struct iovec two[2] = {{hole - 5, 5}, {hole, 5}};
    CHECK_ERR("stream-writev", writev(sv[0], two, 2), EFAULT);
    CHECK_ERR("stream-sendto", sendto(sv[0], hole - 5, 10, MSG_DONTWAIT, NULL, 0), EFAULT);
    CHECK("stream-nothing-sent", drain(sv[1], 0) == 0);
    /* SO_SNDBUF 4096 is kept as 8192: skbs of 4032 bytes. */
    int size = 4096;
    CHECK("sndbuf", setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof size) == 0);
    CHECK_ERR("skb-less-one", msg(sv[0], 4031), EFAULT);
    CHECK("skb-whole", msg(sv[0], 4032) == 4032 && drain(sv[1], 4032) == 4032);
    CHECK("skb-and-more", msg(sv[0], 5000) == 4032 && drain(sv[1], 4032) == 4032);
    struct iovec across = {hole - 4100, 4105};
    CHECK("one-vector", writev(sv[0], &across, 1) == 4032 && drain(sv[1], 4032) == 4032);
    CHECK("sendto-skb", sendto(sv[0], hole - 4100, 4200, MSG_DONTWAIT, NULL, 0) == 4032 &&
                            drain(sv[1], 4032) == 4032);
    close(sv[0]);
    close(sv[1]);

    /* A datagram faults whole. */
    CHECK("dgram-pair", socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    CHECK_ERR("dgram-sendmsg", msg(sv[0], 5), EFAULT);
    CHECK_ERR("dgram-writev", writev(sv[0], two, 2), EFAULT);
    CHECK("dgram-nothing-sent", drain(sv[1], 0) == 0);
    close(sv[0]);
    close(sv[1]);

    /* TCP: the first copy faults. */
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    CHECK("tcp-listen", bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 1) == 0 &&
                            getsockname(l, (struct sockaddr *)&a, &al) == 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK("tcp-connect", connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    int s = accept(l, NULL, NULL);
    CHECK_ERR("tcp-small", msg(c, 5), EFAULT);
    CHECK_ERR("tcp-first-chunk", msg(c, 20000), EFAULT);
    CHECK("tcp-nothing-sent", drain(s, 0) == 0);
    close(c);
    close(s);
    close(l);
    FINISH();
}
