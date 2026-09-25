/* Extended attributes: setting, getting, listing, and removing user.*
 * names on files and directories (flags, empty values, buffer sizes);
 * name checks (empty, over-long, a bare prefix, unknown namespaces);
 * trusted.* and security.* for the unprivileged; names on symbolic links,
 * FIFOs, pipes, sockets (sockfs's system.sockprotoname), and eventfds;
 * the l and f forms; the *xattrat calls and their struct xattr_args; and
 * bad pointers and missing paths. Values are small and lists are sorted,
 * so the results do not depend on the file system's limits or order. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <netinet/in.h>
#include <unistd.h>
#include "check.h"

#ifndef SYS_setxattrat
#define SYS_setxattrat 463
#define SYS_getxattrat 464
#define SYS_listxattrat 465
#define SYS_removexattrat 466
#endif
struct xattr_args_ {
    uint64_t value;
    uint32_t size, flags;
};

static char dir[64], file[96], link_[96], fifo[96];

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The names of `path`'s list, sorted and joined with spaces. */
static const char *names(const char *path) {
    static char out[1024];
    char buf[1024], *v[64];
    ssize_t n = listxattr(path, buf, sizeof buf);
    int k = 0;
    for (ssize_t i = 0; i < n && k < 64; i += strlen(buf + i) + 1)
        v[k++] = buf + i;
    qsort(v, k, sizeof *v, cmp);
    out[0] = 0;
    for (int i = 0; i < k; i++) {
        strcat(out, i ? " " : "");
        strcat(out, v[i]);
    }
    return out;
}

static void user_names(void) {
    char buf[64];
    CHECK("set", setxattr(file, "user.a", "hello", 5, 0) == 0);
    CHECK("get", getxattr(file, "user.a", buf, sizeof buf) == 5 && !memcmp(buf, "hello", 5));
    CHECK("get-size", getxattr(file, "user.a", 0, 0) == 5);
    CHECK_ERR("get-small", getxattr(file, "user.a", buf, 2), ERANGE);
    CHECK_ERR("get-missing", getxattr(file, "user.b", buf, sizeof buf), ENODATA);
    CHECK_ERR("create-existing", setxattr(file, "user.a", "x", 1, XATTR_CREATE), EEXIST);
    CHECK_ERR("replace-missing", setxattr(file, "user.b", "x", 1, XATTR_REPLACE), ENODATA);
    CHECK_ERR("bad-flags", setxattr(file, "user.a", "x", 1, 4), EINVAL);
    CHECK("replace", setxattr(file, "user.a", "world!", 6, XATTR_REPLACE) == 0 &&
                         getxattr(file, "user.a", buf, sizeof buf) == 6 && !memcmp(buf, "world!", 6));
    CHECK("empty-value", setxattr(file, "user.e", "", 0, 0) == 0 &&
                             getxattr(file, "user.e", buf, sizeof buf) == 0);
    CHECK("empty-value-no-copy", getxattr(file, "user.e", (char *)8, 10) == 0);
    char name[300];
    memset(name, 'n', sizeof name);
    memcpy(name, "user.", 5);
    name[255] = 0;
    CHECK("longest-name", setxattr(file, name, "L", 1, 0) == 0 && getxattr(file, name, buf, 1) == 1 &&
                              buf[0] == 'L');
    name[255] = 'n';
    name[256] = 0;
    CHECK_ERR("name-too-long", setxattr(file, name, "x", 1, 0), ERANGE);
    CHECK_ERR("name-too-long-get", getxattr(file, name, buf, sizeof buf), ERANGE);
    CHECK_ERR("empty-name", setxattr(file, "", "x", 1, 0), ERANGE);
    CHECK_ERR("bare-prefix", setxattr(file, "user.", "x", 1, 0), EINVAL);
    CHECK_ERR("unknown-space", setxattr(file, "foo.bar", "x", 1, 0), EOPNOTSUPP);
    CHECK_ERR("unknown-space-get", getxattr(file, "foo.bar", buf, sizeof buf), EOPNOTSUPP);
    CHECK_ERR("system-name", setxattr(file, "system.foo", "x", 1, 0), EOPNOTSUPP);
    CHECK_ERR("system-name-get", getxattr(file, "system.foo", buf, sizeof buf), EOPNOTSUPP);
    static char big[65537];
    CHECK_ERR("value-too-big", setxattr(file, "user.big", big, 65537, 0), E2BIG);
    /* The list: every name once, its size, a small buffer. */
    name[255] = 0;
    char want[512];
    snprintf(want, sizeof want, "user.a user.e %s", name);
    CHECK("list", !strcmp(names(file), want));
    CHECK("list-size", listxattr(file, 0, 0) == (ssize_t)(7 + 7 + 256));
    CHECK_ERR("list-small", listxattr(file, buf, 3), ERANGE);
    CHECK("remove", removexattr(file, "user.e") == 0 &&
                        getxattr(file, "user.e", buf, sizeof buf) == -1 && errno == ENODATA);
    CHECK_ERR("remove-missing", removexattr(file, "user.e"), ENODATA);
    removexattr(file, name);
    /* A directory takes them too. */
    CHECK("directory", setxattr(dir, "user.d", "d", 1, 0) == 0 &&
                           getxattr(dir, "user.d", buf, sizeof buf) == 1 && !strcmp(names(dir), "user.d"));
}

static void privileged(void) {
    char buf[16];
    /* Without CAP_SYS_ADMIN (the reference container's root has none):
     * trusted.* cannot be set and reads as missing; security.* cannot be
     * set. */
    int t = setxattr(file, "trusted.t", "x", 1, 0);
    CHECK("trusted-set", (t == 0 && geteuid() == 0) || (t == -1 && errno == EPERM));
    if (t == 0)
        removexattr(file, "trusted.t");
    CHECK_ERR("trusted-get", getxattr(file, "trusted.none", buf, sizeof buf), ENODATA);
    int s = setxattr(file, "security.s", "x", 1, 0);
    CHECK("security-set", (s == 0 && geteuid() == 0) || (s == -1 && errno == EPERM));
    if (s == 0)
        removexattr(file, "security.s");
    CHECK_ERR("security-get", getxattr(file, "security.none", buf, sizeof buf), ENODATA);
    /* A sticky directory: only its owner may set names. */
    int k = setxattr("/tmp", "user.sticky", "x", 1, 0);
    CHECK("sticky", (k == 0 && geteuid() == 0) || (k == -1 && errno == EPERM));
    if (k == 0)
        removexattr("/tmp", "user.sticky");
}

static void other_objects(void) {
    char buf[64];
    /* user.* belongs to regular files and directories only. */
    CHECK_ERR("link-set", lsetxattr(link_, "user.l", "x", 1, 0), EPERM);
    CHECK_ERR("link-get", lgetxattr(link_, "user.l", buf, sizeof buf), ENODATA);
    CHECK("link-list", llistxattr(link_, buf, sizeof buf) == 0);
    CHECK("link-follows", setxattr(link_, "user.via", "v", 1, 0) == 0 &&
                              getxattr(file, "user.via", buf, sizeof buf) == 1);
    removexattr(file, "user.via");
    CHECK_ERR("fifo-set", setxattr(fifo, "user.f", "x", 1, 0), EPERM);
    CHECK_ERR("fifo-get", getxattr(fifo, "user.f", buf, sizeof buf), ENODATA);
    int p[2];
    pipe(p);
    CHECK_ERR("pipe-set", fsetxattr(p[0], "user.p", "x", 1, 0), EPERM);
    CHECK_ERR("pipe-get", fgetxattr(p[0], "user.p", buf, sizeof buf), ENODATA);
    CHECK("pipe-list", flistxattr(p[0], buf, sizeof buf) == 0);
    close(p[0]);
    close(p[1]);
    int ev = eventfd(0, 0);
    CHECK_ERR("eventfd-set", fsetxattr(ev, "user.p", "x", 1, 0), EPERM);
    CHECK_ERR("eventfd-get", fgetxattr(ev, "user.p", buf, sizeof buf), ENODATA);
    /* trusted.* reads as missing without CAP_SYS_ADMIN; with it, the
     * anonymous inode has no handler. Root may or may not have it. */
    int r = fgetxattr(ev, "trusted.x", buf, sizeof buf);
    CHECK("eventfd-trusted", r == -1 && (errno == ENODATA || (geteuid() == 0 && errno == EOPNOTSUPP)));
    close(ev);
    /* A socket's inode names its protocol. */
    int us = socket(AF_UNIX, SOCK_STREAM, 0), ud = socket(AF_UNIX, SOCK_DGRAM, 0);
    int ts = socket(AF_INET, SOCK_STREAM, 0), ds = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK("sock-name", fgetxattr(us, "system.sockprotoname", buf, sizeof buf) == 12 &&
                           !strcmp(buf, "UNIX-STREAM"));
    CHECK("sock-name-dgram", fgetxattr(ud, "system.sockprotoname", buf, sizeof buf) == 5 &&
                                 !strcmp(buf, "UNIX"));
    CHECK("sock-name-tcp", fgetxattr(ts, "system.sockprotoname", buf, sizeof buf) == 4 &&
                               !strcmp(buf, "TCP"));
    CHECK("sock-name-udp", fgetxattr(ds, "system.sockprotoname", buf, sizeof buf) == 4 &&
                               !strcmp(buf, "UDP"));
    CHECK_ERR("sock-name-small", fgetxattr(us, "system.sockprotoname", buf, 3), ERANGE);
    CHECK("sock-list", flistxattr(us, buf, sizeof buf) == 21 && !strcmp(buf, "system.sockprotoname"));
    CHECK_ERR("sock-name-set", fsetxattr(us, "system.sockprotoname", "x", 1, 0), EOPNOTSUPP);
    CHECK_ERR("sock-user", fsetxattr(us, "user.x", "x", 1, 0), EPERM);
    close(us);
    close(ud);
    close(ts);
    close(ds);
}

static void forms(void) {
    char buf[64];
    int fd = open(file, O_RDONLY);
    CHECK("fd-set", fsetxattr(fd, "user.fd", "y", 1, 0) == 0 &&
                        fgetxattr(fd, "user.fd", buf, sizeof buf) == 1 && buf[0] == 'y');
    CHECK("fd-list", flistxattr(fd, buf, sizeof buf) > 0);
    CHECK("fd-remove", fremovexattr(fd, "user.fd") == 0);
    int op = open(file, O_PATH);
    CHECK_ERR("path-only", fgetxattr(op, "user.a", buf, sizeof buf), EBADF);
    CHECK_ERR("path-only-list", flistxattr(op, buf, sizeof buf), EBADF);
    CHECK_ERR("closed", fgetxattr(99, "user.a", buf, sizeof buf), EBADF);
    CHECK_ERR("missing", setxattr("/tmp/rax-none/x", "user.a", "x", 1, 0), ENOENT);
    CHECK_ERR("path-fault", getxattr((char *)8, "user.a", buf, sizeof buf), EFAULT);
    CHECK_ERR("name-fault", setxattr(file, (char *)8, "x", 1, 0), EFAULT);
    CHECK_ERR("value-fault", setxattr(file, "user.a", (char *)8, 1, 0), EFAULT);
    CHECK_ERR("list-fault", listxattr(file, (char *)8, 100), EFAULT);
    /* The *xattrat calls. */
    struct xattr_args_ a = {(uintptr_t) "zz", 2, 0};
    CHECK("setxattrat", syscall(SYS_setxattrat, AT_FDCWD, file, 0, "user.at", &a, sizeof a) == 0);
    CHECK_ERR("setxattrat-small", syscall(SYS_setxattrat, AT_FDCWD, file, 0, "user.at", &a, 8),
              EINVAL);
    CHECK_ERR("setxattrat-huge", syscall(SYS_setxattrat, AT_FDCWD, file, 0, "user.at", &a, 8192),
              E2BIG);
    CHECK_ERR("setxattrat-flags", syscall(SYS_setxattrat, AT_FDCWD, file, 4, "user.at", &a, sizeof a),
              EINVAL);
    struct {
        struct xattr_args_ a;
        uint64_t extra;
    } ext = {{(uintptr_t)buf, sizeof buf, 0}, 1};
    CHECK_ERR("getxattrat-trailing", syscall(SYS_getxattrat, AT_FDCWD, file, 0, "user.at", &ext, sizeof ext),
              E2BIG);
    ext.extra = 0;
    CHECK("getxattrat-longer", syscall(SYS_getxattrat, AT_FDCWD, file, 0, "user.at", &ext, sizeof ext) == 2);
    a.value = (uintptr_t)buf;
    a.size = sizeof buf;
    CHECK("getxattrat", syscall(SYS_getxattrat, AT_FDCWD, file, 0, "user.at", &a, sizeof a) == 2 &&
                            !memcmp(buf, "zz", 2));
    a.flags = 1;
    CHECK_ERR("getxattrat-flags", syscall(SYS_getxattrat, AT_FDCWD, file, 0, "user.at", &a, sizeof a),
              EINVAL);
    a.flags = 0;
    CHECK("getxattrat-fd", syscall(SYS_getxattrat, fd, "", AT_EMPTY_PATH, "user.at", &a, sizeof a) == 2);
    CHECK("getxattrat-null-path", syscall(SYS_getxattrat, fd, 0, AT_EMPTY_PATH, "user.at", &a, sizeof a) == 2);
    CHECK_ERR("getxattrat-cwd", syscall(SYS_getxattrat, AT_FDCWD, "", AT_EMPTY_PATH, "user.none", &a, sizeof a),
              ENODATA);
    CHECK("listxattrat", syscall(SYS_listxattrat, fd, "", AT_EMPTY_PATH, buf, sizeof buf) > 0);
    CHECK_ERR("listxattrat-cwd", syscall(SYS_listxattrat, AT_FDCWD, "", AT_EMPTY_PATH, buf, sizeof buf),
              EBADF);
    CHECK_ERR("listxattrat-empty", syscall(SYS_listxattrat, AT_FDCWD, "", 0, buf, sizeof buf), ENOENT);
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    CHECK("removexattrat", syscall(SYS_removexattrat, dfd, "f", 0, "user.at") == 0);
    CHECK_ERR("removexattrat-again", syscall(SYS_removexattrat, dfd, "f", 0, "user.at"), ENODATA);
    CHECK_ERR("lsetxattrat", syscall(SYS_setxattrat, dfd, "l", AT_SYMLINK_NOFOLLOW, "user.at", &a, sizeof a),
              EPERM);
    close(dfd);
    close(op);
    close(fd);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    snprintf(dir, sizeof dir, "/tmp/rax-xattr-%d", getpid());
    snprintf(file, sizeof file, "%s/f", dir);
    snprintf(link_, sizeof link_, "%s/l", dir);
    snprintf(fifo, sizeof fifo, "%s/p", dir);
    mkdir(dir, 0755);
    close(open(file, O_CREAT | O_WRONLY, 0644));
    symlink(file, link_);
    mkfifo(fifo, 0644);
    user_names();
    privileged();
    other_objects();
    forms();
    removexattr(file, "user.a");
    unlink(file);
    unlink(link_);
    unlink(fifo);
    rmdir(dir);
    FINISH();
}
