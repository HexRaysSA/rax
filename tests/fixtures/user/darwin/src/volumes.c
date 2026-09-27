// Volumes: statfs, fstatfs, and getfsstat, and fsgetpath, the path of a
// file system object named by its volume and object ID (a file, a
// directory, the root, a system file behind a firmlink), with and
// without FSOPT_NOFIRMLINKPATH, and the argument checks.
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYS_fsgetpath_ext 217
#define FSOPT_NOFIRMLINKPATH 0x80

static void look(const char *what, const char *path, uint32_t options) {
    struct stat st;
    struct statfs sfs;
    stat(path, &st);
    statfs(path, &sfs);
    char buf[PATH_MAX], real[PATH_MAX];
    memset(buf, 0x55, sizeof buf);
    ssize_t n = syscall(SYS_fsgetpath_ext, buf, sizeof buf, &sfs.f_fsid, (uint64_t)st.st_ino, options);
    realpath(path, real);
    printf("%s: %zd errno=%d len ok=%d realpath=%d name ok=%d\n", what, n, n < 0 ? errno : 0,
           n > 0 && (size_t)n == strlen(buf) + 1, n > 0 && strcmp(buf, real) == 0,
           n > 0 && strcmp(strrchr(buf, '/'), strrchr(real, '/')) == 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char dir[] = "/tmp/rax-fsgetpath-XXXXXX";
    mkdtemp(dir);
    char file[PATH_MAX];
    snprintf(file, sizeof file, "%s/a file", dir);
    close(open(file, O_CREAT | O_WRONLY, 0600));
    look("file", file, 0);
    look("directory", dir, 0);
    look("root", "/", 0);
    look("system file", "/usr/bin/true", 0);
    look("system file nofirmlink", "/usr/bin/true", FSOPT_NOFIRMLINKPATH);

    struct stat st;
    struct statfs sfs;
    stat(file, &st);
    statfs(file, &sfs);
    char buf[PATH_MAX];
    errno = 0;
    printf("libc: %d\n", fsgetpath(buf, sizeof buf, &sfs.f_fsid, st.st_ino) > 0);
    errno = 0;
    printf("size 0: %zd errno=%d\n", fsgetpath(buf, 0, &sfs.f_fsid, st.st_ino), errno);
    errno = 0;
    printf("size 8193: %zd errno=%d\n", fsgetpath(buf, 8193, &sfs.f_fsid, st.st_ino), errno);
    errno = 0;
    printf("too small: %zd errno=%d\n", fsgetpath(buf, 5, &sfs.f_fsid, st.st_ino), errno);
    errno = 0;
    printf("bad fsid: %zd errno=%d\n", fsgetpath(buf, sizeof buf, (fsid_t *)8, st.st_ino), errno);
    errno = 0;
    printf("bad options: %zd errno=%d\n",
           (ssize_t)syscall(SYS_fsgetpath_ext, buf, sizeof buf, &sfs.f_fsid, (uint64_t)st.st_ino, 1), errno);
    fsid_t none = {{0x7fffffff, 0}};
    errno = 0;
    printf("no volume: %zd errno=%d\n", fsgetpath(buf, sizeof buf, &none, st.st_ino), errno);
    unlink(file);
    errno = 0;
    printf("removed file: %zd errno=%d\n", fsgetpath(buf, sizeof buf, &sfs.f_fsid, st.st_ino), errno);
    rmdir(dir);

    struct statfs root, froot;
    statfs("/", &root);
    int fd = open("/", O_RDONLY);
    fstatfs(fd, &froot);
    close(fd);
    printf("statfs /: %s type=%s same as fstatfs=%d\n", root.f_mntonname, root.f_fstypename,
           memcmp(&root.f_fsid, &froot.f_fsid, sizeof root.f_fsid) == 0);
    errno = 0;
    printf("statfs missing: %d errno=%d\n", statfs("/nonexistent/x", &root), errno);
    errno = 0;
    printf("statfs fault: %d errno=%d\n", statfs("/", (struct statfs *)8), errno);
    int n = getfsstat(NULL, 0, MNT_NOWAIT);
    struct statfs *all = calloc((size_t)n, sizeof *all);
    int m = getfsstat(all, n * (int)sizeof *all, MNT_NOWAIT);
    int listed = 0;
    for (int i = 0; i < m; i++) {
        listed |= strcmp(all[i].f_mntonname, "/") == 0;
    }
    printf("getfsstat: some=%d all copied=%d one=%d small=%d root listed=%d\n", n > 0, m == n,
           getfsstat(all, sizeof *all, MNT_NOWAIT), getfsstat(all, sizeof *all - 1, MNT_NOWAIT) == n,
           listed);
    return 0;
}
