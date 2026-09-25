/* mknod and file times: mknod's type checks, each node type it makes (a
 * regular file, a FIFO, a socket, a device when privileged) with the umask
 * applied, and its name checks; utimensat's order of checks, its null
 * paths and descriptors, UTIME_OMIT, AT_SYMLINK_NOFOLLOW, and a file the
 * caller may not read; the older utimes, futimesat, and utime (the raw
 * x86-64 calls where they exist); and new files' modes under umask 0. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "check.h"

static char dir[64];

static const char *at(const char *name) {
    static char path[4][128];
    static int n;
    char *p = path[n++ % 4];
    snprintf(p, 128, "%s/%s", dir, name);
    return p;
}

static mode_t mode_of(const char *p) {
    struct stat st;
    return lstat(p, &st) == 0 ? st.st_mode : 0;
}

static void nodes(void) {
    CHECK_ERR("dir", mknod(at("d"), S_IFDIR | 0755, 0), EPERM);
    CHECK_ERR("bad-type", mknod(at("b"), 0170000 | 0644, 0), EINVAL);
    CHECK("regular", mknod(at("r"), 0666, 0) == 0 && mode_of(at("r")) == (S_IFREG | 0644));
    CHECK_ERR("exists", mknod(at("r"), S_IFREG | 0644, 0), EEXIST);
    CHECK_ERR("exists-slash", mknod(at("r/"), S_IFIFO | 0644, 0), EEXIST);
    CHECK_ERR("new-slash", mknod(at("n/"), S_IFIFO | 0644, 0), ENOENT);
    CHECK_ERR("no-parent", mknod(at("none/x"), S_IFIFO | 0644, 0), ENOENT);
    CHECK_ERR("parent-file", mknod(at("r/x"), S_IFIFO | 0644, 0), ENOTDIR);
    CHECK_ERR("fault", mknod((char *)8, S_IFIFO, 0), EFAULT);
    symlink(at("r"), at("l"));
    CHECK_ERR("exists-link", mknod(at("l"), S_IFIFO | 0644, 0), EEXIST);
    CHECK("fifo", mknod(at("f"), S_IFIFO | 0666, 0) == 0 && mode_of(at("f")) == (S_IFIFO | 0644));
    int r = open(at("f"), O_RDONLY | O_NONBLOCK);
    int w = open(at("f"), O_WRONLY | O_NONBLOCK);
    char c = 0;
    CHECK("fifo-works", r >= 0 && w >= 0 && write(w, "z", 1) == 1 && read(r, &c, 1) == 1 && c == 'z');
    close(r);
    close(w);
    CHECK("socket", mknod(at("s"), S_IFSOCK | 0640, 0) == 0 && mode_of(at("s")) == (S_IFSOCK | 0640));
    CHECK("mknodat", mknodat(open(dir, O_RDONLY | O_DIRECTORY), "f2", S_IFIFO | 0600, 0) == 0 &&
                         mode_of(at("f2")) == (S_IFIFO | 0600));
    mode_t old = umask(077);
    CHECK("umask", mknod(at("f3"), S_IFIFO | 0666, 0) == 0 && mode_of(at("f3")) == (S_IFIFO | 0600));
    umask(old);
    /* A device needs CAP_MKNOD. */
    int d = mknod(at("c"), S_IFCHR | 0600, makedev(1, 3));
    struct stat st;
    CHECK("device", geteuid() == 0 ? d == 0 && lstat(at("c"), &st) == 0 && S_ISCHR(st.st_mode) &&
                                         major(st.st_rdev) == 1 && minor(st.st_rdev) == 3
                                   : d == -1 && errno == EPERM);
    CHECK_ERR("device-no-dir", mknod(at("none/c"), S_IFBLK | 0600, makedev(8, 0)), ENOENT);
}

static int times_are(const char *p, long as, long an, long ms, long mn) {
    struct stat st;
    return lstat(p, &st) == 0 && st.st_atim.tv_sec == as && st.st_atim.tv_nsec == an &&
           st.st_mtim.tv_sec == ms && st.st_mtim.tv_nsec == mn;
}

static void times(void) {
    char f[128];
    snprintf(f, sizeof f, "%s", at("t"));
    close(open(f, O_CREAT | O_WRONLY, 0644));
    struct timespec ts[2] = {{100, 5}, {200, 6}};
    CHECK("utimensat", utimensat(AT_FDCWD, f, ts, 0) == 0 && times_are(f, 100, 5, 200, 6));
    ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = 300;
    CHECK("omit", utimensat(AT_FDCWD, f, ts, 0) == 0 && times_are(f, 100, 5, 300, 6));
    ts[1].tv_nsec = UTIME_OMIT;
    CHECK("omit-both", utimensat(AT_FDCWD, at("none"), ts, 0) == 0);
    ts[0].tv_nsec = 1000000000;
    CHECK_ERR("path-first", utimensat(AT_FDCWD, at("none"), ts, 0), ENOENT);
    CHECK_ERR("bad-nsec", utimensat(AT_FDCWD, f, ts, 0), EINVAL);
    ts[0].tv_nsec = 0;
    ts[1].tv_nsec = 0;
    CHECK_ERR("bad-flags", utimensat(AT_FDCWD, f, ts, 0x2), EINVAL);
    CHECK_ERR("null-path", utimensat(AT_FDCWD, 0, ts, 0), EFAULT);
    int fd = open(f, O_RDONLY);
    CHECK_ERR("fd-flags", utimensat(fd, 0, ts, AT_SYMLINK_NOFOLLOW), EINVAL);
    ts[0].tv_sec = 7;
    ts[1].tv_sec = 8;
    CHECK("fd", utimensat(fd, 0, ts, 0) == 0 && times_are(f, 7, 0, 8, 0));
    int op = open(f, O_PATH);
    CHECK_ERR("fd-path-only", utimensat(op, 0, ts, 0), EBADF);
    ts[0].tv_sec = 9;
    CHECK("empty-path", utimensat(op, "", ts, AT_EMPTY_PATH) == 0 && times_are(f, 9, 0, 8, 0));
    int p[2];
    pipe(p);
    CHECK("pipe", utimensat(p[0], 0, 0, 0) == 0);
    int ev = eventfd(0, 0);
    CHECK_ERR("eventfd", utimensat(ev, 0, 0, 0), EOPNOTSUPP);
    /* The link itself, not its target. */
    ts[0].tv_sec = 50;
    ts[1].tv_sec = 60;
    CHECK("nofollow", utimensat(AT_FDCWD, at("l"), ts, AT_SYMLINK_NOFOLLOW) == 0 &&
                          times_are(at("l"), 50, 0, 60, 0) && !times_are(at("r"), 50, 0, 60, 0));
    /* The owner may set the times of a file it cannot read. */
    chmod(f, 0200);
    ts[1].tv_sec = 61;
    CHECK("write-only", utimensat(AT_FDCWD, f, ts, 0) == 0 && times_are(f, 50, 0, 61, 0));
    chmod(f, 0644);
    /* Through a /proc/self/fd link. */
    char proc[64];
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    ts[1].tv_sec = 62;
    CHECK("proc-link", utimensat(AT_FDCWD, proc, ts, 0) == 0 && times_are(f, 50, 0, 62, 0));
    time_t before = time(0);
    struct stat st;
    CHECK("now", utimensat(AT_FDCWD, f, 0, 0) == 0 && stat(f, &st) == 0 && st.st_mtime >= before);
    /* The C library's utimes and utime. */
    struct timeval tv[2] = {{100, 5}, {200, 7}};
    CHECK("utimes", utimes(f, tv) == 0 && times_are(f, 100, 5000, 200, 7000));
    struct utimbuf ub = {300, 400};
    CHECK("utime", utime(f, &ub) == 0 && times_are(f, 300, 0, 400, 0));
#ifdef SYS_utimes
    /* The system calls themselves (x86-64). */
    tv[1].tv_usec = 1000000;
    CHECK_ERR("raw-utimes-usec", syscall(SYS_utimes, f, tv), EINVAL);
    tv[1].tv_usec = -1;
    CHECK_ERR("raw-utimes-negative", syscall(SYS_utimes, f, tv), EINVAL);
    tv[1].tv_usec = 9;
    CHECK("raw-utimes", syscall(SYS_utimes, f, tv) == 0 && times_are(f, 100, 5000, 200, 9000));
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
    tv[0].tv_sec = 11;
    CHECK("raw-futimesat", syscall(SYS_futimesat, dirfd, "t", tv) == 0 &&
                               times_are(f, 11, 5000, 200, 9000));
    tv[0].tv_sec = 12;
    CHECK("raw-futimesat-fd", syscall(SYS_futimesat, fd, 0, tv) == 0 &&
                                  times_are(f, 12, 5000, 200, 9000));
    ub.actime = 13;
    CHECK("raw-utime", syscall(SYS_utime, f, &ub) == 0 && times_are(f, 13, 0, 400, 0));
    CHECK_ERR("raw-utime-fault", syscall(SYS_utime, f, (void *)8), EFAULT);
    CHECK_ERR("raw-utime-missing", syscall(SYS_utime, at("none"), &ub), ENOENT);
    close(dirfd);
#else
    CHECK("raw-utimes-usec", 1);
    CHECK("raw-utimes-negative", 1);
    CHECK("raw-utimes", 1);
    CHECK("raw-futimesat", 1);
    CHECK("raw-futimesat-fd", 1);
    CHECK("raw-utime", 1);
    CHECK("raw-utime-fault", 1);
    CHECK("raw-utime-missing", 1);
#endif
    close(fd);
    close(op);
    close(ev);
    close(p[0]);
    close(p[1]);
}

/* The umask alone decides what a new file's mode loses. */
static void masks(void) {
    umask(0);
    int fd = open(at("m1"), O_CREAT | O_WRONLY, 0777);
    close(fd);
    CHECK("umask0-open", mode_of(at("m1")) == (S_IFREG | 0777));
    CHECK("umask0-mkdir", mkdir(at("m2"), 0777) == 0 && mode_of(at("m2")) == (S_IFDIR | 0777));
    CHECK("umask0-mknod", mknod(at("m3"), S_IFIFO | 0666, 0) == 0 &&
                              mode_of(at("m3")) == (S_IFIFO | 0666));
    chmod(at("m1"), 0600);
    close(open(at("m1"), O_CREAT | O_WRONLY, 0777));
    CHECK("umask0-existing", mode_of(at("m1")) == (S_IFREG | 0600));
    umask(022);
    unlink(at("m1"));
    rmdir(at("m2"));
    unlink(at("m3"));
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    umask(022);
    snprintf(dir, sizeof dir, "/tmp/rax-nodes-%d", getpid());
    mkdir(dir, 0755);
    nodes();
    times();
    masks();
    const char *names[] = {"r", "l", "f", "s", "f2", "f3", "c", "t"};
    for (unsigned i = 0; i < sizeof names / sizeof *names; i++)
        unlink(at(names[i]));
    rmdir(dir);
    FINISH();
}
