#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int fd = open("data", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || symlink("data", "link")) return 2;
    char bytes[] = {'g', 'u', 'a', 'r', 'd'};
    if (listxattr(".", NULL, 0, 0) ||
        listxattr("link", bytes, sizeof(bytes), 0) ||
        listxattr("link", bytes, sizeof(bytes), XATTR_NOFOLLOW) ||
        flistxattr(fd, bytes, sizeof(bytes), 0) ||
        bytes[0] != 'g' || bytes[4] != 'd') return 3;
    if (listxattr("link", NULL, 0, XATTR_NOFOLLOW_ANY) != -1 || errno != ELOOP ||
        flistxattr(fd, NULL, 0, XATTR_NOFOLLOW) != -1 || errno != EINVAL) return 4;
    if (unlink("data") || flistxattr(fd, NULL, 0, 0) ||
        listxattr("link", NULL, 0, 0) != -1 || errno != ENOENT ||
        listxattr("link", NULL, 0, XATTR_NOFOLLOW)) return 5;
    if (close(fd) || flistxattr(fd, NULL, 0, 0) != -1 || errno != EBADF ||
        unlink("link") || chdir("/") || rmdir(argv[1])) return 6;
    puts("empty private xattr lists leave the output buffer untouched");
    return 0;
}
