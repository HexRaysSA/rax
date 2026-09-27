// Extended attributes: setting (create and replace), getting (the length,
// a short buffer, a size of 0), listing, removing, on a path, through a
// descriptor, on a symbolic link itself, the resource fork at an offset,
// and the checks in XNU's order (options, the path, the name, protected
// names, the value).
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/xattr.h>
#include <unistd.h>

static void show(const char *what, long r) { printf("%s: %ld errno=%d\n", what, r, r < 0 ? errno : 0); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char dir[] = "/tmp/rax-xattr-XXXXXX";
    mkdtemp(dir);
    char file[256], link[256];
    snprintf(file, sizeof file, "%s/f", dir);
    snprintf(link, sizeof link, "%s/l", dir);
    close(open(file, O_CREAT | O_WRONLY, 0600));
    symlink(file, link);

    errno = 0;
    show("set", setxattr(file, "user.one", "value1", 6, 0, 0));
    errno = 0;
    show("set create again", setxattr(file, "user.one", "x", 1, 0, XATTR_CREATE));
    errno = 0;
    show("set replace missing", setxattr(file, "user.two", "x", 1, 0, XATTR_REPLACE));
    show("set two", setxattr(file, "user.two", "22", 2, 0, 0));
    char buf[64];
    memset(buf, 0, sizeof buf);
    errno = 0;
    show("get length", getxattr(file, "user.one", NULL, 0, 0, 0));
    errno = 0;
    show("get", getxattr(file, "user.one", buf, sizeof buf, 0, 0));
    printf("value: %s\n", buf);
    errno = 0;
    show("get short", getxattr(file, "user.one", buf, 3, 0, 0));
    errno = 0;
    show("get size 0", getxattr(file, "user.one", buf, 0, 0, 0));
    errno = 0;
    show("get missing", getxattr(file, "user.none", buf, sizeof buf, 0, 0));
    errno = 0;
    show("list length", listxattr(file, NULL, 0, 0));
    memset(buf, 0, sizeof buf);
    long n = listxattr(file, buf, sizeof buf, 0);
    printf("list: %ld [", n);
    for (long i = 0; i < n; i++) {
        putchar(buf[i] ? buf[i] : '|');
    }
    printf("]\n");
    errno = 0;
    show("list short", listxattr(file, buf, 4, 0));

    // Through a descriptor.
    int fd = open(file, O_RDONLY);
    errno = 0;
    show("fget", fgetxattr(fd, "user.two", buf, sizeof buf, 0, 0));
    errno = 0;
    show("fget size 0", fgetxattr(fd, "user.two", buf, 0, 0, 0));
    errno = 0;
    show("fset", fsetxattr(fd, "user.three", "3", 1, 0, 0));
    errno = 0;
    show("flist", flistxattr(fd, buf, sizeof buf, 0));
    errno = 0;
    show("fremove", fremovexattr(fd, "user.three", 0));
    errno = 0;
    show("fget nofollow", fgetxattr(fd, "user.two", buf, sizeof buf, 0, XATTR_NOFOLLOW));
    int kq = kqueue();
    errno = 0;
    show("fget kqueue", fgetxattr(kq, "user.two", buf, sizeof buf, 0, 0));
    errno = 0;
    show("fget bad fd", fgetxattr(99, "user.two", buf, sizeof buf, 0, 0));
    int p[2];
    pipe(p);
    errno = 0;
    show("fget pipe", fgetxattr(p[0], "user.two", buf, sizeof buf, 0, 0));

    // The link itself.
    errno = 0;
    show("get through link", getxattr(link, "user.one", buf, sizeof buf, 0, 0));
    errno = 0;
    show("get link nofollow", getxattr(link, "user.one", buf, sizeof buf, 0, XATTR_NOFOLLOW));
    errno = 0;
    show("set link nofollow", setxattr(link, "user.onlink", "L", 1, 0, XATTR_NOFOLLOW));
    errno = 0;
    show("list link nofollow", listxattr(link, buf, sizeof buf, XATTR_NOFOLLOW));

    // The resource fork, read at an offset.
    char fork[100];
    for (int i = 0; i < 100; i++) {
        fork[i] = (char)('a' + i % 26);
    }
    errno = 0;
    show("set resource fork", setxattr(file, XATTR_RESOURCEFORK_NAME, fork, sizeof fork, 0, 0));
    memset(buf, 0, sizeof buf);
    errno = 0;
    show("get resource fork at 30", getxattr(file, XATTR_RESOURCEFORK_NAME, buf, 5, 30, 0));
    printf("fork bytes: %.5s\n", buf);

    // The checks, in order.
    char longname[200];
    memset(longname, 'n', sizeof longname - 1);
    longname[sizeof longname - 1] = 0;
    errno = 0;
    show("bad options", getxattr(file, "user.one", buf, sizeof buf, 0, XATTR_NOSECURITY));
    errno = 0;
    show("missing path", getxattr("/nonexistent/x", "user.one", buf, sizeof buf, 0, 0));
    errno = 0;
    show("missing path, bad name", getxattr("/nonexistent/x", (const char *)8, buf, sizeof buf, 0, 0));
    errno = 0;
    show("bad name", getxattr(file, (const char *)8, buf, sizeof buf, 0, 0));
    errno = 0;
    show("long name", getxattr(file, longname, buf, sizeof buf, 0, 0));
    errno = 0;
    show("bad buffer", getxattr(file, "user.one", (void *)8, sizeof buf, 0, 0));
    errno = 0;
    show("set protected", setxattr(file, "com.apple.system.x", "1", 1, 0, 0));
    errno = 0;
    show("set protected, missing path", setxattr("/nonexistent/x", "com.apple.system.x", "1", 1, 0, 0));
    errno = 0;
    show("set value NULL", setxattr(file, "user.x", NULL, 4, 0, 0));
    errno = 0;
    show("set bad value", setxattr(file, "user.x", (void *)8, 4, 0, 0));
    errno = 0;
    show("set bad value, missing path", setxattr("/nonexistent/x", "user.x", (void *)8, 4, 0, 0));
    errno = 0;
    show("remove protected", removexattr(file, "com.apple.system.x", 0));
    errno = 0;
    show("remove missing", removexattr(file, "user.none", 0));
    show("remove", removexattr(file, "user.one", 0));
    errno = 0;
    show("empty name", setxattr(file, "", "1", 1, 0, 0));

    unlink(link);
    unlink(file);
    rmdir(dir);
    return 0;
}
