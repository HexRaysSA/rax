// Attribute lists, clones, and table access checks: getattrlistbulk over
// a directory (in pieces, and its errors), setattrlist, fsetattrlist, and
// setattrlistat (dates, Finder info, no-follow; a failed lookup reported
// before a bad attribute list), clonefileat and fclonefileat, exchangedata,
// and accessx_np.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *ename(int e) {
    static char b[16];
    switch (e) {
    case 0: return "0";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EBADF: return "EBADF";
    case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES";
    case EFAULT: return "EFAULT";
    case EEXIST: return "EEXIST";
    case ENOTDIR: return "ENOTDIR";
    case EINVAL: return "EINVAL";
    case ERANGE: return "ERANGE";
    case ENOTSUP: return "ENOTSUP";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ELOOP: return "ELOOP";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}

static long show(const char *what, long r) {
    printf("%s: %ld %s\n", what, r, ename(r < 0 ? errno : 0));
    return r;
}
#define T(what, expr) (errno = 0, show(what, (long)(expr)))

static void make(const char *name, const char *text) {
    int fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    write(fd, text, strlen(text));
    close(fd);
}

static void bulk(void) {
    mkdir("d", 0755);
    make("d/alpha", "a");
    make("d/beta", "bb");
    mkdir("d/gamma", 0755);
    symlink("alpha", "d/delta");
    struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT,
                          .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE};
    int d = open("d", O_RDONLY | O_DIRECTORY);
    char buf[160];
    int total = 0, calls = 0;
    for (;;) {
        memset(buf, 0xa5, sizeof buf);
        int n = getattrlistbulk(d, &al, buf, sizeof buf, 0);
        calls++;
        if (n <= 0) {
            printf("  last call %d %s\n", n, ename(n < 0 ? errno : 0));
            break;
        }
        char *p = buf;
        for (int i = 0; i < n; i++) {
            uint32_t len = *(uint32_t *)p;
            attrreference_t *name = (attrreference_t *)(p + 4 + sizeof(attribute_set_t));
            fsobj_type_t type = *(fsobj_type_t *)(p + 4 + sizeof(attribute_set_t) + sizeof(attrreference_t));
            printf("  entry %s type %u len %u\n", (char *)name + name->attr_dataoffset, type, len);
            p += len;
            total++;
        }
        printf("  after the records: %#x\n", (unsigned char)*p);
    }
    printf("bulk: %d entries in %d calls\n", total, calls);
    lseek(d, 0, SEEK_SET);
    T("bulk rewound", getattrlistbulk(d, &al, buf, sizeof buf, 0));
    struct attrlist bad = al;
    bad.bitmapcount = 3;
    T("bulk bad bitmap count", getattrlistbulk(d, &bad, buf, sizeof buf, 0));
    T("bulk bad list", getattrlistbulk(d, (struct attrlist *)8, buf, sizeof buf, 0));
    lseek(d, 0, SEEK_SET);
    T("bulk bad buffer", getattrlistbulk(d, &al, (void *)8, sizeof buf, 0));
    T("bulk after the bad buffer", getattrlistbulk(d, &al, buf, sizeof buf, 0));
    T("bulk -1", getattrlistbulk(-1, &al, buf, sizeof buf, 0));
    int f = open("d/alpha", O_RDONLY);
    T("bulk on a file", getattrlistbulk(f, &al, buf, sizeof buf, 0));
    close(f);
    close(d);
}

static void setting(void) {
    struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_MODTIME};
    struct timespec t = {1000000000, 5};
    T("set modtime", setattrlist("d/alpha", &al, &t, sizeof t, 0));
    struct stat st;
    stat("d/alpha", &st);
    printf("  mtime %ld.%09ld\n", (long)st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec);
    T("set missing, bad list", setattrlist("d/missing", (struct attrlist *)8, &t, sizeof t, 0));
    T("set bad list", setattrlist("d/alpha", (struct attrlist *)8, &t, sizeof t, 0));
    T("set bad buffer", setattrlist("d/alpha", &al, (void *)8, sizeof t, 0));
    T("set huge buffer", setattrlist("d/alpha", &al, &t, 1 << 20, 0));
    T("set short buffer", setattrlist("d/alpha", &al, &t, 4, 0));
    T("set bad path", setattrlist((char *)8, &al, &t, sizeof t, 0));
    char longp[1100];
    memset(longp, 'x', sizeof longp - 1);
    longp[sizeof longp - 1] = 0;
    T("set long path", setattrlist(longp, &al, &t, sizeof t, 0));
    struct timespec t2 = {1200000000, 0};
    T("set no-follow on a link", setattrlist("d/delta", &al, &t2, sizeof t2, FSOPT_NOFOLLOW));
    lstat("d/delta", &st);
    printf("  link mtime %ld\n", (long)st.st_mtimespec.tv_sec);
    stat("d/alpha", &st);
    printf("  target mtime %ld\n", (long)st.st_mtimespec.tv_sec);

    struct attrlist fi = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_FNDRINFO};
    char info[32] = {0};
    memcpy(info, "TEXTRAXU", 8);
    int fd = open("d/beta", O_RDONLY);
    T("fset finder info", fsetattrlist(fd, &fi, info, sizeof info, 0));
    struct {
        uint32_t len;
        char info[32];
    } __attribute__((packed)) got;
    T("fget finder info", fgetattrlist(fd, &fi, &got, sizeof got, 0));
    printf("  %.8s len %u\n", got.info, got.len);
    T("fset -1", fsetattrlist(-1, &fi, info, sizeof info, 0));
    close(fd);
    int dir = open("d", O_RDONLY | O_DIRECTORY);
    struct timespec t3 = {1300000000, 0};
    T("setat", setattrlistat(dir, "beta", &al, &t3, sizeof t3, 0));
    stat("d/beta", &st);
    printf("  mtime %ld\n", (long)st.st_mtimespec.tv_sec);
    T("setat bad dirfd", setattrlistat(-5, "beta", &al, &t3, sizeof t3, 0));
    close(dir);
}

static void clones(void) {
    T("clone", clonefile("d/beta", "d/beta2", 0));
    struct stat a, b;
    stat("d/beta", &a);
    stat("d/beta2", &b);
    char buf[8] = {0};
    int fd = open("d/beta2", O_RDONLY);
    read(fd, buf, sizeof buf);
    close(fd);
    printf("  content %s other file %d mode %o\n", buf, a.st_ino != b.st_ino, b.st_mode & 07777);
    T("clone onto existing", clonefile("d/beta", "d/beta2", 0));
    T("clone missing", clonefile("d/missing", "d/x", 0));
    T("clone bad flags", clonefile((char *)8, "d/x", 0x100));
    T("clone bad source path", clonefile((char *)8, "d/x", 0));
    T("clone directory", clonefile("d/gamma", "d/gamma2", 0));
    T("clone link itself", clonefile("d/delta", "d/delta2", CLONE_NOFOLLOW));
    struct stat l;
    lstat("d/delta2", &l);
    printf("  is a link %d\n", S_ISLNK(l.st_mode));
    int dir = open("d", O_RDONLY | O_DIRECTORY);
    T("clonefileat", clonefileat(dir, "alpha", dir, "alpha2", 0));
    fd = open("d/alpha", O_RDONLY);
    T("fclonefileat", fclonefileat(fd, dir, "alpha3", 0));
    close(fd);
    fd = open("d/alpha", O_WRONLY);
    T("fclonefileat write-only", fclonefileat(fd, dir, "alpha4", 0));
    close(fd);
    close(dir);
}

static void exchange_and_access(void) {
    T("exchangedata", exchangedata("d/alpha", "d/beta", 0));
    T("exchangedata missing", exchangedata("d/alpha", "d/missing", 0));

    // Two descriptors, the second reusing the first's name, and a third.
    char table[3 * sizeof(struct accessx_descriptor) + 32];
    memset(table, 0, sizeof table);
    struct accessx_descriptor *ad = (struct accessx_descriptor *)table;
    unsigned names = 3 * sizeof(struct accessx_descriptor);
    ad[0].ad_name_offset = names;
    ad[0].ad_flags = R_OK;
    ad[1].ad_name_offset = 0;
    ad[1].ad_flags = X_OK;
    ad[2].ad_name_offset = names + 8;
    ad[2].ad_flags = F_OK;
    strcpy(table + names, "d/beta");
    strcpy(table + names + 8, "d/none");
    int results[4] = {-7, -7, -7, -7};
    T("accessx", accessx_np(ad, sizeof table, results, getuid()));
    printf("  results %d %d %d %d\n", results[0], results[1], results[2], results[3]);
    T("accessx tiny", accessx_np(ad, 4, results, getuid()));
    T("accessx huge", accessx_np(ad, 1 << 20, results, getuid()));
    ad[1].ad_name_offset = 8;
    T("accessx bad offset", accessx_np(ad, sizeof table, results, getuid()));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char dir[] = "/tmp/rax-attrs.XXXXXX";
    mkdtemp(dir);
    chdir(dir);
    bulk();
    setting();
    clones();
    exchange_and_access();
    system("rm -rf d");
    chdir("/");
    rmdir(dir);
    return 0;
}
