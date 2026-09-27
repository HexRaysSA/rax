// sysctl and sysctlbyname: the metadata nodes (name, next, name2oid,
// oidfmt, oiddescr), the copy-out rules (size queries, short buffers,
// 32-bit buffers for 64-bit values), lookups that miss, reads of
// interior nodes, and writes. Machine values (CPU counts, sizes, the
// model) are not printed: the emulated machine is not the host; their
// sizes, kinds, formats, and OIDs are. Rosetta shows the arm64 kernel's
// machdep subtree, which is not an Intel kernel's: machdep runs on arm64
// only.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

static void oid_print(const int *oid, size_t n) {
    for (size_t i = 0; i < n; i++) printf(i ? ",%d" : "[%d", oid[i]);
    printf("]");
}

// name2oid.
static int lookup(const char *name, int *oid) {
    int q[2] = {0, 3};
    size_t len = CTL_MAXNAME * sizeof(int);
    if (sysctl(q, 2, oid, &len, (void *)name, strlen(name))) return -errno;
    return (int)(len / sizeof(int));
}

static void describe(const char *name) {
    int oid[CTL_MAXNAME];
    int n = lookup(name, oid);
    printf("%s:", name);
    if (n < 0) {
        printf(" name2oid errno %d\n", -n);
        return;
    }
    printf(" ");
    oid_print(oid, (size_t)n);
    int q[CTL_MAXNAME + 2] = {0, 4};
    memcpy(q + 2, oid, (size_t)n * sizeof(int));
    char f[256];
    size_t len = sizeof f;
    if (sysctl(q, (u_int)n + 2, f, &len, 0, 0) == 0) {
        uint32_t kind;
        memcpy(&kind, f, 4);
        printf(" kind %#x fmt \"%s\" (%zu bytes)", kind, f + 4, len);
    } else {
        printf(" oidfmt errno %d", errno);
    }
    q[1] = 5;
    char d[256];
    len = sizeof d;
    if (sysctl(q, (u_int)n + 2, d, &len, 0, 0) == 0)
        printf(" descr \"%s\"", d);
    else
        printf(" oiddescr errno %d", errno);
    q[1] = 1;
    char nm[256];
    len = sizeof nm;
    if (sysctl(q, (u_int)n + 2, nm, &len, 0, 0) == 0)
        printf(" name \"%s\" (%zu)", nm, len);
    else
        printf(" name errno %d", errno);
    // The value's size.
    len = 0;
    int r = sysctl(oid, (u_int)n, NULL, &len, NULL, 0);
    printf(" size %d/%d %zu\n", r, r ? errno : 0, len);
}

// A read of `name` into a buffer of `room` bytes: result, errno, the
// length reported, and how many bytes changed.
static void read_into(const char *name, size_t room) {
    unsigned char b[64];
    memset(b, 0xa5, sizeof b);
    size_t len = room;
    int r = sysctlbyname(name, b, &len, NULL, 0);
    int changed = 0;
    for (size_t i = 0; i < sizeof b; i++) changed += b[i] != 0xa5;
    printf("%s into %zu: %d errno %d len %zu changed %d\n", name, room, r, r ? errno : 0, len, changed);
}

static void name_of(const int *oid, u_int n) {
    int q[CTL_MAXNAME + 2] = {0, 1};
    memcpy(q + 2, oid, n * sizeof(int));
    char nm[256];
    size_t len = sizeof nm;
    oid_print(oid, n);
    if (sysctl(q, n + 2, nm, &len, 0, 0) == 0)
        printf(" is \"%s\"\n", nm);
    else
        printf(" name errno %d\n", errno);
}

static void next_of(const int *oid, u_int n) {
    int q[CTL_MAXNAME + 2] = {0, 2};
    memcpy(q + 2, oid, n * sizeof(int));
    int nx[CTL_MAXNAME];
    size_t len = sizeof nx;
    printf("next of ");
    oid_print(oid, n);
    if (sysctl(q, n + 2, nx, &len, 0, 0) == 0) {
        printf(": ");
        oid_print(nx, len / sizeof(int));
        char nm[256];
        size_t l2 = sizeof nm;
        int q2[CTL_MAXNAME + 2] = {0, 1};
        memcpy(q2 + 2, nx, len);
        if (sysctl(q2, (u_int)(len / sizeof(int)) + 2, nm, &l2, 0, 0) == 0) printf(" %s", nm);
        printf("\n");
    } else {
        printf(": errno %d\n", errno);
    }
}

int main(void) {
    // Metadata of nodes of the machine and of the system.
    const char *names[] = {"hw", "hw.ncpu", "hw.activecpu", "hw.memsize", "hw.pagesize", "hw.pagesize_compat",
                           "hw.physmem", "hw.cachelinesize", "hw.cacheconfig", "hw.cputype", "hw.optional",
                           "hw.optional.floatingpoint", "hw.nperflevels", "hw.perflevel0",
                           "hw.perflevel0.physicalcpu", "hw.perflevel0.name", "hw.machine",
                           "hw.tbfrequency", "kern", "kern.ostype", "kern.osrelease", "kern.maxproc", "kern.hostname",
                           "sysctl", "sysctl.proc_translated", "vm.loadavg", "user.cs_path", "nonexistent",
                           "hw.nonexistent", "hw.ncpu.extra", "kern.ostype.", ""};
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) describe(names[i]);
#if defined(__arm64__)
    describe("machdep");
    describe("machdep.cpu");
    describe("machdep.cpu.brand_string");
#endif

    // Copy-out: size queries, exact, short, and 32-bit buffers.
    read_into("kern.ostype", 64);
    read_into("kern.ostype", 3);
    read_into("kern.ostype", 0);
    read_into("hw.ncpu", 4);
    read_into("hw.ncpu", 8);
    read_into("hw.ncpu", 2);
    read_into("hw.memsize", 8);
    read_into("hw.memsize", 4);
    read_into("hw.pagesize", 8);
    read_into("hw.pagesize", 4);
    read_into("hw.pagesize", 2);
    read_into("hw.cachelinesize", 4);
    read_into("hw.tbfrequency", 4);
    read_into("hw.machine", 64);
    read_into("hw.machine", 2);
    // The process's name: a short buffer gets what fits.
    char pn[64];
    size_t len = sizeof pn;
    printf("kern.procname: %d \"%s\"", sysctlbyname("kern.procname", pn, &len, NULL, 0), pn);
    len = 4;
    memset(pn, 0, sizeof pn);
    printf(" into 4: %d \"%s\" len %zu\n", sysctlbyname("kern.procname", pn, &len, NULL, 0), pn, len);
    len = 0;
    printf("size query of kern.ostype: %d len %zu\n", sysctlbyname("kern.ostype", NULL, &len, NULL, 0), len);
    printf("no length: %d errno %d\n", sysctlbyname("kern.ostype", NULL, NULL, NULL, 0), errno);

    // Numeric names: an interior node, a leaf with more components, and
    // lengths out of range.
    int hw[] = {CTL_HW}, hwncpu[] = {CTL_HW, HW_NCPU, 7}, bad[] = {CTL_HW, 9999};
    int v = 0;
    len = sizeof v;
    errno = 0;
    printf("read hw: %d errno %d\n", sysctl(hw, 1, &v, &len, NULL, 0), errno);
    int hw2[] = {CTL_HW, 101};
    len = sizeof v;
    printf("read hw.optional: %d errno %d\n", sysctl(hw2, 2, &v, &len, NULL, 0), errno);
    len = sizeof v;
    printf("read hw.ncpu.7: %d errno %d\n", sysctl(hwncpu, 3, &v, &len, NULL, 0), errno);
    len = sizeof v;
    printf("read hw.9999: %d errno %d\n", sysctl(bad, 2, &v, &len, NULL, 0), errno);
    int deep[13] = {CTL_KERN, KERN_OSTYPE};
    len = sizeof v;
    printf("13 components: %d errno %d\n", sysctl(deep, 13, &v, &len, NULL, 0), errno);

    // Writes.
    int one = 1;
    printf("write hw.ncpu: %d errno %d\n", sysctlbyname("hw.ncpu", NULL, NULL, &one, sizeof one), errno);
    printf("write kern.ostype: %d errno %d\n", sysctlbyname("kern.ostype", NULL, NULL, "x", 2), errno);
    printf("write nonexistent: %d errno %d\n", sysctlbyname("nonexistent.x", NULL, NULL, &one, sizeof one), errno);

    // Names of OIDs and the walk.
    int n1[] = {CTL_HW, HW_NCPU}, n2[] = {CTL_HW, HW_NCPU, 5}, n3[] = {CTL_HW, 9999}, n4[] = {CTL_KERN, KERN_OSTYPE};
    name_of(n1, 2);
    name_of(n2, 3);
    name_of(n3, 2);
    name_of(n4, 2);
    name_of(hw, 1);
    int w1[] = {CTL_HW}, w2[] = {CTL_HW, HW_NCPU}, w3[] = {CTL_HW, HW_BYTEORDER}, w4[] = {CTL_KERN, KERN_OSTYPE};
    next_of(w1, 1);
    next_of(w2, 2);
    next_of(w3, 2);
    next_of(w4, 2);
    // Every name under hw.perflevel0 and machdep.cpu, in walk order.
    const char *walks[] = {"hw.perflevel0", "machdep.cpu"};
#if defined(__arm64__)
    size_t nwalks = 2;
#else
    size_t nwalks = 1;
#endif
    for (size_t w = 0; w < nwalks; w++) {
        int root[CTL_MAXNAME];
        int rn = lookup(walks[w], root);
        if (rn < 0) {
            printf("walk %s: errno %d\n", walks[w], -rn);
            continue;
        }
        int cur[CTL_MAXNAME];
        memcpy(cur, root, (size_t)rn * sizeof(int));
        int cn = rn;
        printf("walk %s:", walks[w]);
        for (;;) {
            int q[CTL_MAXNAME + 2] = {0, 2};
            memcpy(q + 2, cur, (size_t)cn * sizeof(int));
            int nx[CTL_MAXNAME];
            size_t l = sizeof nx;
            if (sysctl(q, (u_int)cn + 2, nx, &l, 0, 0)) break;
            int nn = (int)(l / sizeof(int));
            if (nn < rn || memcmp(nx, root, (size_t)rn * sizeof(int))) break;
            int q2[CTL_MAXNAME + 2] = {0, 1};
            memcpy(q2 + 2, nx, l);
            char nm[256];
            size_t l2 = sizeof nm;
            if (sysctl(q2, (u_int)nn + 2, nm, &l2, 0, 0) == 0) printf(" %s", strrchr(nm, '.') + 1);
            memcpy(cur, nx, l);
            cn = nn;
        }
        printf("\n");
    }

    // The metadata nodes' own errors.
    int m1[] = {0, 3};
    int out[CTL_MAXNAME];
    len = sizeof out;
    printf("name2oid without a name: %d errno %d\n", sysctl(m1, 2, out, &len, NULL, 0), errno);
    len = 4;
    printf("name2oid, short: %d errno %d len %zu\n", sysctl(m1, 2, out, &len, (void *)"hw.ncpu", 7), errno, len);
    int m2[] = {0, 4};
    len = sizeof out;
    printf("oidfmt of nothing: %d errno %d\n", sysctl(m2, 2, out, &len, NULL, 0), errno);
    int m3[] = {0, 99};
    len = sizeof out;
    printf("sysctl.99: %d errno %d\n", sysctl(m3, 2, out, &len, NULL, 0), errno);
    return 0;
}
