/* Interface requests on sockets (net/socket.c sock_ioctl, net/core/dev_ioctl.c,
 * net/ipv4/devinet.c). SIOCGIFCONF's length and entries (the loopback's
 * 127.0.0.1, whole entries only); a device by name and by index; flags,
 * MTU, metric, map, hardware address (the bytes past it untouched), the
 * name's 16th byte cleared and an alias's ':' kept; IPv4 address, netmask,
 * broadcast, and destination on an IPv4 socket only (ENOTTY elsewhere);
 * unknown devices and requests; changes refused without CAP_NET_ADMIN (a
 * container's root lacks it); the requests on a netlink socket; musl's
 * if_nametoindex and if_indextoname. Only the loopback's values are
 * checked. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include "check.h"

static char lo[IFNAMSIZ];

static struct ifreq named(const char *name) {
    struct ifreq r;
    memset(&r, 0xaa, sizeof r);
    snprintf(r.ifr_name, IFNAMSIZ, "%s", name);
    return r;
}

static void conf(int fd) {
    struct ifconf c = {0};
    c.ifc_buf = NULL;
    CHECK("ifconf-length", ioctl(fd, SIOCGIFCONF, &c) == 0 && c.ifc_len > 0 &&
                               c.ifc_len % (int)sizeof(struct ifreq) == 0);
    int want = c.ifc_len;
    struct ifreq *all = calloc(1, want + sizeof(struct ifreq));
    c.ifc_len = want + sizeof(struct ifreq);
    c.ifc_req = all;
    int found = 0, ok = ioctl(fd, SIOCGIFCONF, &c) == 0 && c.ifc_len == want;
    for (int i = 0; ok && i < want / (int)sizeof(struct ifreq); i++) {
        struct sockaddr_in *a = (struct sockaddr_in *)&all[i].ifr_addr;
        if (a->sin_family != AF_INET)
            ok = 0;
        if (a->sin_addr.s_addr == htonl(0x7f000001) && !found) {
            found = 1;
            snprintf(lo, sizeof lo, "%s", all[i].ifr_name);
        }
    }
    CHECK("ifconf-entries", ok);
    CHECK("ifconf-loopback", found);
    /* Whole entries only. */
    c.ifc_len = sizeof(struct ifreq) + 1;
    CHECK("ifconf-whole-entries", ioctl(fd, SIOCGIFCONF, &c) == 0 &&
                                      c.ifc_len == (int)sizeof(struct ifreq));
    c.ifc_len = -1;
    CHECK("ifconf-negative-length", ioctl(fd, SIOCGIFCONF, &c) == 0 && c.ifc_len == 0);
    free(all);
}

static void devices(int fd, int inet) {
    struct ifreq r = named(lo);
    CHECK("index", ioctl(fd, SIOCGIFINDEX, &r) == 0 && r.ifr_ifindex > 0);
    int index = r.ifr_ifindex;
    unsigned char *raw = (unsigned char *)&r;
    CHECK("index-rest-untouched", raw[20] == 0xaa && raw[39] == 0xaa);
    memset(&r, 0xaa, sizeof r);
    r.ifr_ifindex = index;
    CHECK("name", ioctl(fd, SIOCGIFNAME, &r) == 0 && !strcmp(r.ifr_name, lo));
    r.ifr_ifindex = 0x7fffffff;
    CHECK_ERR("name-no-device", ioctl(fd, SIOCGIFNAME, &r), ENODEV);
    r = named(lo);
    CHECK("flags", ioctl(fd, SIOCGIFFLAGS, &r) == 0 &&
                       (r.ifr_flags & (IFF_UP | IFF_LOOPBACK | IFF_RUNNING)) ==
                           (IFF_UP | IFF_LOOPBACK | IFF_RUNNING) &&
                       raw[18] == 0xaa);
    r = named(lo);
    CHECK("mtu", ioctl(fd, SIOCGIFMTU, &r) == 0 && r.ifr_mtu > 0);
    r = named(lo);
    CHECK("metric", ioctl(fd, SIOCGIFMETRIC, &r) == 0 && r.ifr_metric == 0);
    r = named(lo);
    CHECK("map", ioctl(fd, SIOCGIFMAP, &r) == 0 && r.ifr_map.mem_start == 0 &&
                     r.ifr_map.base_addr == 0 && r.ifr_map.irq == 0 && raw[37] == 0xaa);
    r = named(lo);
    CHECK("hwaddr", ioctl(fd, SIOCGIFHWADDR, &r) == 0 &&
                        r.ifr_hwaddr.sa_family == ARPHRD_LOOPBACK &&
                        !memcmp(r.ifr_hwaddr.sa_data, "\0\0\0\0\0\0", 6) &&
                        raw[24] == 0xaa && raw[31] == 0xaa);
    /* An alias names its device; the 16th byte is cleared. */
    r = named(lo);
    strcat(r.ifr_name, ":7");
    r.ifr_name[15] = 'x';
    CHECK("alias", ioctl(fd, SIOCGIFINDEX, &r) == 0 && r.ifr_ifindex == index &&
                       strchr(r.ifr_name, ':') && r.ifr_name[15] == 0);
    r = named("rax-no-device");
    CHECK_ERR("no-device", ioctl(fd, SIOCGIFMTU, &r), ENODEV);
    r = named(lo);
    CHECK_ERR("slave", ioctl(fd, SIOCGIFSLAVE, &r), EINVAL);
    CHECK_ERR("mem", ioctl(fd, SIOCGIFMEM, &r), ENOTTY);
    r = named(lo);
    r.ifr_mtu = 1280;
    CHECK_ERR("set-mtu-needs-net-admin", ioctl(fd, SIOCSIFMTU, &r), EPERM);
    CHECK_ERR("bad-pointer", ioctl(fd, SIOCGIFINDEX, (void *)8), EFAULT);
    /* The address requests are IPv4's. */
    r = named(lo);
    if (!inet) {
        CHECK_ERR("addr-not-inet", ioctl(fd, SIOCGIFADDR, &r), ENOTTY);
        return;
    }
    struct sockaddr_in *a = (struct sockaddr_in *)&r.ifr_addr;
    CHECK("addr", ioctl(fd, SIOCGIFADDR, &r) == 0 && a->sin_family == AF_INET &&
                      a->sin_addr.s_addr == htonl(0x7f000001) && raw[31] == 0);
    r = named(lo);
    CHECK("netmask", ioctl(fd, SIOCGIFNETMASK, &r) == 0 && a->sin_addr.s_addr == htonl(0xff000000));
    r = named(lo);
    CHECK("dstaddr", ioctl(fd, SIOCGIFDSTADDR, &r) == 0 && a->sin_addr.s_addr == htonl(0x7f000001));
    r = named(lo);
    CHECK("brdaddr", ioctl(fd, SIOCGIFBRDADDR, &r) == 0 && a->sin_addr.s_addr == 0);
    r = named(lo);
    strcat(r.ifr_name, ":7");
    CHECK_ERR("alias-no-address", ioctl(fd, SIOCGIFADDR, &r), EADDRNOTAVAIL);
    r = named("rax-no-device");
    CHECK_ERR("addr-no-device", ioctl(fd, SIOCGIFADDR, &r), ENODEV);
    r = named(lo);
    CHECK_ERR("pflags", ioctl(fd, SIOCGIFPFLAGS, &r), EINVAL);
    r = named(lo);
    CHECK_ERR("set-addr-needs-net-admin", ioctl(fd, SIOCSIFADDR, &r), EPERM);
    CHECK_ERR("set-flags-needs-net-admin", ioctl(fd, SIOCSIFFLAGS, &r), EPERM);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int inet = socket(AF_INET, SOCK_DGRAM, 0);
    conf(inet);
    printf("-- inet\n");
    devices(inet, 1);
    printf("-- unix\n");
    int unix_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    devices(unix_fd, 0);
    printf("-- netlink\n");
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    devices(nl, 0);
    unsigned index = if_nametoindex(lo);
    char name[IF_NAMESIZE];
    CHECK("if-nametoindex", index > 0);
    CHECK("if-indextoname", if_indextoname(index, name) && !strcmp(name, lo));
    CHECK("if-nametoindex-missing", if_nametoindex("rax-no-device") == 0);
    FINISH();
}
