/* Netlink route sockets (net/netlink/af_netlink.c, net/core/rtnetlink.c).
 * Creation, port IDs (the process's ID, then negative ones), binding;
 * acknowledgements, errors carrying the request (or capped), requests that
 * are not requests, and several messages in one send; link dumps with a
 * loopback, NLMSG_DONE alone, one dump at a time; a link by index and by
 * name; IPv4 addresses with 127.0.0.1/8 at host scope, dumps by family;
 * MSG_PEEK, MSG_TRUNC, timeouts; group membership and the options;
 * NETLINK_PKTINFO; the calls netlink lacks; readiness; a forked child's
 * requests; and musl's getifaddrs and if_nameindex, which ask netlink. Only
 * what holds on every host is checked: the unprivileged view (a container's
 * root lacks CAP_NET_ADMIN), no interface names, counts, or addresses but
 * the loopback's. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define LAST_GROUP 39

static unsigned char buf[65536];

static int nl(void) {
    return socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
}

static struct sockaddr_nl addr_of(unsigned pid, unsigned groups) {
    struct sockaddr_nl a;
    memset(&a, 0, sizeof a);
    a.nl_family = AF_NETLINK;
    a.nl_pid = pid;
    a.nl_groups = groups;
    return a;
}

static struct sockaddr_nl name_of(int fd, int peer) {
    struct sockaddr_nl a;
    socklen_t len = sizeof a;
    memset(&a, 0xff, sizeof a);
    if (peer)
        getpeername(fd, (struct sockaddr *)&a, &len);
    else
        getsockname(fd, (struct sockaddr *)&a, &len);
    return a;
}

/* Sends one message of `type` with `payload`. */
static long request(int fd, int type, int flags, unsigned seq, const void *payload, size_t len) {
    unsigned char m[512];
    struct nlmsghdr *h = (struct nlmsghdr *)m;
    memset(m, 0, sizeof m);
    h->nlmsg_len = NLMSG_LENGTH(len);
    h->nlmsg_type = type;
    h->nlmsg_flags = flags;
    h->nlmsg_seq = seq;
    memcpy(NLMSG_DATA(h), payload, len);
    return send(fd, m, NLMSG_ALIGN(h->nlmsg_len), 0);
}

/* The next datagram, without waiting: its length, or -1. */
static long next(int fd) {
    return recv(fd, buf, sizeof buf, MSG_DONTWAIT);
}

/* The error an acknowledgement in buf carries. */
static int ack_error(void) {
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if (h->nlmsg_type != NLMSG_ERROR)
        return 1;
    return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
}

static struct ifinfomsg ifinfo(int index) {
    struct ifinfomsg i;
    memset(&i, 0, sizeof i);
    i.ifi_index = index;
    return i;
}

/* The attribute of `type` in a message after its fixed header. */
static struct rtattr *attr(struct nlmsghdr *h, size_t fixed, int type) {
    int len = h->nlmsg_len - NLMSG_LENGTH(fixed);
    struct rtattr *a = (struct rtattr *)((char *)NLMSG_DATA(h) + NLMSG_ALIGN(fixed));
    for (; RTA_OK(a, len); a = RTA_NEXT(a, len))
        if (a->rta_type == type)
            return a;
    return NULL;
}

static int lo_index;
static char lo_name[IFNAMSIZ];

static void creation(void) {
    CHECK_ERR("stream-unsupported", socket(AF_NETLINK, SOCK_STREAM, 0), ESOCKTNOSUPPORT);
    CHECK_ERR("protocol-past-max-links", socket(AF_NETLINK, SOCK_RAW, 32), EPROTONOSUPPORT);
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    int v = -1;
    socklen_t len = sizeof v;
    getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &len);
    CHECK("so-type", v == SOCK_DGRAM);
    getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &v, &len);
    CHECK("so-domain", v == AF_NETLINK);
    int sv[2];
    CHECK_ERR("no-socketpair", socketpair(AF_NETLINK, SOCK_RAW, 0, sv), EOPNOTSUPP);
    close(fd);
}

static void ports(void) {
    int a = nl(), b = nl();
    struct sockaddr_nl n = name_of(a, 0);
    CHECK("unbound-name", n.nl_family == AF_NETLINK && n.nl_pid == 0 && n.nl_groups == 0);
    struct sockaddr_nl any = addr_of(0, 0);
    CHECK_ERR("bind-short", bind(a, (struct sockaddr *)&any, 11), EINVAL);
    CHECK("autobind-pid", bind(a, (struct sockaddr *)&any, sizeof any) == 0 &&
                              name_of(a, 0).nl_pid == (unsigned)getpid());
    struct sockaddr_nl mine = addr_of(getpid(), 0);
    CHECK_ERR("port-in-use", bind(b, (struct sockaddr *)&mine, sizeof mine), EADDRINUSE);
    CHECK("autobind-negative", bind(b, (struct sockaddr *)&any, sizeof any) == 0 &&
                                   (int)name_of(b, 0).nl_pid <= -4097);
    struct sockaddr_nl other = addr_of(getpid() + 1, 0);
    CHECK_ERR("rebind-other-port", bind(a, (struct sockaddr *)&other, sizeof other), EINVAL);
    CHECK("rebind-same-port", bind(a, (struct sockaddr *)&mine, sizeof mine) == 0);
    close(a);
    close(b);
}

static void acks(void) {
    int fd = nl();
    CHECK_ERR("empty-send", send(fd, buf, 0, 0), ENODATA);
    struct nlmsghdr noop = {16, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, 0};
    CHECK_ERR("oob-send", send(fd, &noop, 16, MSG_OOB), EOPNOTSUPP);
    request(fd, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 7, NULL, 0);
    struct sockaddr_nl from;
    socklen_t len = sizeof from;
    memset(&from, 0xff, sizeof from);
    long r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &len);
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    CHECK("ack", r == 36 && ack_error() == 0 && h->nlmsg_seq == 7 &&
                     h->nlmsg_flags == NLM_F_CAPPED && h->nlmsg_pid == name_of(fd, 0).nl_pid);
    CHECK("ack-from-kernel", len == sizeof from && from.nl_family == AF_NETLINK &&
                                 from.nl_pid == 0 && from.nl_groups == 0);
    /* Not a request: an acknowledgement only if asked. */
    request(fd, RTM_GETLINK, 0, 8, "", 1);
    CHECK_ERR("no-reply-to-non-request", next(fd), EAGAIN);
    struct ifinfomsg missing = ifinfo(0x7fffffff);
    request(fd, RTM_GETLINK, NLM_F_REQUEST, 9, &missing, sizeof missing);
    r = next(fd);
    CHECK("error-carries-request", r == 36 + (long)sizeof missing && ack_error() == -ENODEV &&
                                       h->nlmsg_flags == 0);
    struct ifinfomsg none = ifinfo(0);
    request(fd, RTM_GETLINK, NLM_F_REQUEST, 10, &none, sizeof none);
    CHECK("getlink-needs-index-or-name", next(fd) > 0 && ack_error() == -EINVAL);
    int on = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof on);
    request(fd, RTM_GETLINK, NLM_F_REQUEST, 11, &missing, sizeof missing);
    r = next(fd);
    CHECK("error-capped", r == 36 && h->nlmsg_flags == NLM_F_CAPPED && ack_error() == -ENODEV);
    request(fd, RTM_MAX + 1, NLM_F_REQUEST, 12, "", 1);
    CHECK("type-past-max", next(fd) > 0 && ack_error() == -EOPNOTSUPP);
    struct ifinfomsg lo = ifinfo(1);
    request(fd, RTM_NEWLINK, NLM_F_REQUEST, 13, &lo, sizeof lo);
    CHECK("change-needs-net-admin", next(fd) > 0 && ack_error() == -EPERM);
    /* Two messages in one send, answered in order. */
    unsigned char two[64];
    memset(two, 0, sizeof two);
    struct nlmsghdr *m1 = (struct nlmsghdr *)two, *m2 = (struct nlmsghdr *)(two + 16);
    m1->nlmsg_len = m2->nlmsg_len = 16;
    m1->nlmsg_type = m2->nlmsg_type = NLMSG_NOOP;
    m1->nlmsg_flags = m2->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    m1->nlmsg_seq = 14;
    m2->nlmsg_seq = 15;
    send(fd, two, 32, 0);
    int s1 = next(fd) > 0 ? (int)h->nlmsg_seq : -1;
    int s2 = next(fd) > 0 ? (int)h->nlmsg_seq : -1;
    CHECK("answered-in-order", s1 == 14 && s2 == 15);
    struct sockaddr_nl peer = addr_of(12345, 0);
    CHECK_ERR("unicast-needs-net-admin",
              sendto(fd, two, 16, 0, (struct sockaddr *)&peer, sizeof peer), EPERM);
    close(fd);
}

static void links(void) {
    int fd = nl();
    unsigned port;
    struct rtgenmsg g = {AF_UNSPEC};
    request(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 3, &g, sizeof g);
    request(fd, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 4, &g, sizeof g);
    port = name_of(fd, 0).nl_pid;
    int busy = 0, multi = 1, done_alone = 0, done_ok = 0, loopback = 0, lo_addr = 0;
    for (;;) {
        long r = next(fd);
        if (r <= 0)
            break;
        int count = 0, done = 0;
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        for (int len = r; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
            count++;
            if (h->nlmsg_seq == 4) {
                busy = h->nlmsg_type == NLMSG_ERROR &&
                       ((struct nlmsgerr *)NLMSG_DATA(h))->error == -EBUSY;
                continue;
            }
            if (!(h->nlmsg_flags & NLM_F_MULTI) || h->nlmsg_seq != 3 || h->nlmsg_pid != port)
                multi = 0;
            if (h->nlmsg_type == NLMSG_DONE) {
                done = 1;
                done_ok = *(int *)NLMSG_DATA(h) == 0;
                continue;
            }
            struct ifinfomsg *i = NLMSG_DATA(h);
            if (h->nlmsg_type != RTM_NEWLINK || !(i->ifi_flags & IFF_LOOPBACK))
                continue;
            loopback = i->ifi_type == ARPHRD_LOOPBACK && (i->ifi_flags & IFF_UP);
            lo_index = i->ifi_index;
            struct rtattr *n = attr(h, sizeof *i, IFLA_IFNAME);
            if (n)
                snprintf(lo_name, sizeof lo_name, "%s", (char *)RTA_DATA(n));
            struct rtattr *a = attr(h, sizeof *i, IFLA_ADDRESS);
            static const unsigned char zero[6];
            lo_addr = a && RTA_PAYLOAD(a) == 6 && !memcmp(RTA_DATA(a), zero, 6) &&
                      attr(h, sizeof *i, IFLA_MTU) && attr(h, sizeof *i, IFLA_STATS64);
        }
        if (done) {
            done_alone = count == 1;
            break;
        }
    }
    CHECK("dump-one-at-a-time", busy);
    CHECK("link-dump-messages", multi);
    CHECK("link-dump-done-alone", done_alone && done_ok);
    CHECK("loopback-link", loopback && lo_index > 0 && lo_name[0]);
    CHECK("loopback-attributes", lo_addr);
    /* The loopback by index, then by name. */
    struct ifinfomsg i = ifinfo(lo_index);
    request(fd, RTM_GETLINK, NLM_F_REQUEST, 5, &i, sizeof i);
    long r = next(fd);
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    CHECK("link-by-index", r > 0 && h->nlmsg_type == RTM_NEWLINK && h->nlmsg_flags == 0 &&
                               ((struct ifinfomsg *)NLMSG_DATA(h))->ifi_index == lo_index);
    unsigned char p[64];
    memset(p, 0, sizeof p);
    struct rtattr *n = (struct rtattr *)(p + sizeof(struct ifinfomsg));
    n->rta_type = IFLA_IFNAME;
    n->rta_len = RTA_LENGTH(strlen(lo_name) + 1);
    strcpy(RTA_DATA(n), lo_name);
    request(fd, RTM_GETLINK, NLM_F_REQUEST, 6, p, sizeof(struct ifinfomsg) + RTA_ALIGN(n->rta_len));
    r = next(fd);
    CHECK("link-by-name", r > 0 && h->nlmsg_type == RTM_NEWLINK &&
                              ((struct ifinfomsg *)NLMSG_DATA(h))->ifi_index == lo_index);
    close(fd);
}

/* Runs an address dump of `family`: whether 127.0.0.1/8 at host scope on
 * the loopback was seen, whether every address was of `family` (or, for
 * AF_UNSPEC, IPv4 before IPv6), and whether NLMSG_DONE came alone. */
static void addresses_of(int fd, int family, int *lo4, int *ordered, int *done_alone) {
    struct rtgenmsg g = {family};
    request(fd, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 20, &g, sizeof g);
    int last = 0;
    *lo4 = 0;
    *ordered = 1;
    *done_alone = 0;
    for (;;) {
        long r = next(fd);
        if (r <= 0)
            return;
        int count = 0;
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        for (int len = r; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
            count++;
            if (h->nlmsg_type == NLMSG_DONE) {
                *done_alone = count == 1;
                return;
            }
            struct ifaddrmsg *a = NLMSG_DATA(h);
            if (family ? a->ifa_family != family : a->ifa_family < last)
                *ordered = 0;
            last = a->ifa_family;
            struct rtattr *l = attr(h, sizeof *a, IFA_LOCAL);
            struct rtattr *label = attr(h, sizeof *a, IFA_LABEL);
            if (a->ifa_family == AF_INET && l && *(uint32_t *)RTA_DATA(l) == htonl(0x7f000001) &&
                a->ifa_prefixlen == 8 && a->ifa_scope == RT_SCOPE_HOST &&
                (int)a->ifa_index == lo_index && label && !strcmp(RTA_DATA(label), lo_name))
                *lo4 = 1;
        }
    }
}

static void addresses(void) {
    int fd = nl(), lo4, ordered, done_alone;
    addresses_of(fd, AF_INET, &lo4, &ordered, &done_alone);
    CHECK("ipv4-loopback-address", lo4);
    CHECK("ipv4-dump-only-ipv4", ordered);
    CHECK("ipv4-dump-done-alone", done_alone);
    addresses_of(fd, AF_INET6, &lo4, &ordered, &done_alone);
    CHECK("ipv6-dump-only-ipv6", ordered);
    addresses_of(fd, AF_UNSPEC, &lo4, &ordered, &done_alone);
    CHECK("all-addresses-ipv4-first", lo4 && ordered);
    close(fd);
}

static void receiving(void) {
    int fd = nl();
    request(fd, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, NULL, 0);
    CHECK("peek-trunc-whole-length", recv(fd, buf, 4, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT) == 36);
    struct iovec v = {buf, 8};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &v;
    m.msg_iovlen = 1;
    CHECK("truncated", recvmsg(fd, &m, MSG_DONTWAIT) == 8 && (m.msg_flags & MSG_TRUNC));
    CHECK_ERR("rest-discarded", next(fd), EAGAIN);
    struct timeval tv = {0, 20000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    CHECK_ERR("receive-timeout", recv(fd, buf, sizeof buf, 0), EAGAIN);
    close(fd);
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    CHECK_ERR("nonblocking", recv(fd, buf, sizeof buf, 0), EAGAIN);
    close(fd);
}

static void options(void) {
    int fd = nl(), v;
    v = RTNLGRP_LINK;
    CHECK("join-link", setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &v, sizeof v) == 0);
    /* Linux 6.19's last group, RTNLGRP_IPV6_ACADDR. */
    v = LAST_GROUP;
    CHECK("join-last", setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &v, sizeof v) == 0);
    v = LAST_GROUP + 1;
    CHECK_ERR("join-past-last", setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &v, sizeof v), EINVAL);
    v = 0;
    CHECK_ERR("join-none", setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &v, sizeof v), EINVAL);
    v = RTNLGRP_IPV4_MROUTE_R;
    CHECK_ERR("join-mroute-r", setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &v, sizeof v), EPERM);
    uint32_t words[4] = {0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa};
    socklen_t len = sizeof words;
    getsockopt(fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, words, &len);
    uint32_t last = 1u << ((LAST_GROUP - 1) % 32);
    CHECK("memberships", len == 8 && words[0] == 1 && words[1] == last && words[2] == 0xaaaaaaaa);
    len = 6;
    words[0] = words[1] = 0xaaaaaaaa;
    getsockopt(fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, words, &len);
    CHECK("memberships-short", len == 8 && words[0] == 1 && words[1] == 0xaaaaaaaa);
    CHECK("name-shows-groups", name_of(fd, 0).nl_groups == 1);
    struct sockaddr_nl a = addr_of(0, 2);
    bind(fd, (struct sockaddr *)&a, sizeof a);
    len = sizeof words;
    getsockopt(fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, words, &len);
    CHECK("bind-replaces-first-groups", words[0] == 2 && words[1] == last);
    v = 5;
    setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &v, sizeof v);
    len = sizeof v;
    v = -1;
    CHECK("flag-as-int", getsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &v, &len) == 0 && v == 1 && len == 4);
    CHECK("short-value-clears", setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &v, 0) == 0 &&
                                    getsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &v, &len) == 0 && v == 0);
    len = 3;
    CHECK_ERR("flag-short-buffer", getsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &v, &len), EINVAL);
    len = sizeof v;
    CHECK_ERR("unknown-option", getsockopt(fd, SOL_NETLINK, 99, &v, &len), ENOPROTOOPT);
    /* NETLINK_PKTINFO: the group a message came to (0, a unicast). */
    v = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_PKTINFO, &v, sizeof v);
    request(fd, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, NULL, 0);
    union {
        struct cmsghdr c;
        char b[64];
    } ctl;
    struct iovec iov = {buf, sizeof buf};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl.b;
    m.msg_controllen = sizeof ctl.b;
    recvmsg(fd, &m, MSG_DONTWAIT);
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    CHECK("pktinfo", c && c->cmsg_level == SOL_NETLINK && c->cmsg_type == NETLINK_PKTINFO &&
                         c->cmsg_len == CMSG_LEN(sizeof(struct nl_pktinfo)) &&
                         ((struct nl_pktinfo *)CMSG_DATA(c))->group == 0 &&
                         !CMSG_NXTHDR(&m, c));
    close(fd);
}

static int readable(int fd) {
    struct pollfd p = {fd, POLLIN | POLLOUT, 0};
    poll(&p, 1, 0);
    return p.revents;
}

static void calls(void) {
    int fd = nl();
    CHECK_ERR("no-listen", listen(fd, 1), EOPNOTSUPP);
    CHECK_ERR("no-accept", accept(fd, NULL, NULL), EOPNOTSUPP);
    CHECK_ERR("no-shutdown", shutdown(fd, SHUT_RDWR), EOPNOTSUPP);
    int n;
    CHECK_ERR("no-fionread", ioctl(fd, FIONREAD, &n), ENOTTY);
    struct sockaddr_nl k = addr_of(0, 0), p = addr_of(5, 0);
    CHECK("connect-kernel", connect(fd, (struct sockaddr *)&k, sizeof k) == 0);
    struct sockaddr_nl peer = name_of(fd, 1);
    CHECK("peer-kernel", peer.nl_family == AF_NETLINK && peer.nl_pid == 0 && peer.nl_groups == 0);
    CHECK_ERR("connect-port-needs-net-admin", connect(fd, (struct sockaddr *)&p, sizeof p), EPERM);
    struct sockaddr u = {AF_UNSPEC};
    CHECK("disconnect", connect(fd, &u, sizeof u) == 0);
    CHECK("writable-not-readable", readable(fd) == POLLOUT);
    request(fd, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, NULL, 0);
    CHECK("readable-with-reply", readable(fd) == (POLLIN | POLLOUT));
    next(fd);
    CHECK("drained", readable(fd) == POLLOUT);
    close(fd);
}

static void forked(void) {
    int fd = nl();
    pid_t c = fork();
    if (c == 0) {
        request(fd, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 100, NULL, 0);
        struct pollfd p = {fd, POLLIN, 0};
        int ok = poll(&p, 1, 1000) == 1 && next(fd) == 36 &&
                 ((struct nlmsghdr *)buf)->nlmsg_seq == 100;
        _exit(ok ? 0 : 1);
    }
    int st = -1;
    waitpid(c, &st, 0);
    CHECK("child-request", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK("parent-queue-empty", readable(fd) == POLLOUT);
    request(fd, NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 200, NULL, 0);
    CHECK("parent-request", next(fd) == 36 && ((struct nlmsghdr *)buf)->nlmsg_seq == 200);
    close(fd);
}

static void libc_view(void) {
    struct ifaddrs *list;
    int lo_packet = 0, lo_inet = 0;
    CHECK("getifaddrs", getifaddrs(&list) == 0);
    for (struct ifaddrs *i = list; i; i = i->ifa_next) {
        if (!i->ifa_addr || strcmp(i->ifa_name, lo_name))
            continue;
        if (i->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *l = (struct sockaddr_ll *)i->ifa_addr;
            lo_packet = l->sll_ifindex == lo_index && l->sll_hatype == ARPHRD_LOOPBACK &&
                        (i->ifa_flags & IFF_LOOPBACK);
        }
        if (i->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in *)i->ifa_addr;
            struct sockaddr_in *m = (struct sockaddr_in *)i->ifa_netmask;
            if (a->sin_addr.s_addr == htonl(0x7f000001) && m && m->sin_addr.s_addr == htonl(0xff000000))
                lo_inet = 1;
        }
    }
    freeifaddrs(list);
    CHECK("getifaddrs-loopback-link", lo_packet);
    CHECK("getifaddrs-loopback-address", lo_inet);
    struct if_nameindex *ni = if_nameindex();
    int found = 0;
    for (struct if_nameindex *p = ni; p && p->if_index; p++)
        if ((int)p->if_index == lo_index && !strcmp(p->if_name, lo_name))
            found = 1;
    if_freenameindex(ni);
    CHECK("if-nameindex-loopback", found);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    creation();
    ports();
    acks();
    links();
    addresses();
    receiving();
    options();
    calls();
    forked();
    libc_view();
    FINISH();
}
