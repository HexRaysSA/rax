#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int file = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (file < 0 || link("file", "alias") || symlink("file", "link") ||
        mkdir("dir", 0700)) return 2;

    const char name[] = "org.rax.test";
    const char value[] = {'A', 0, 'Z'};
    char buffer[64] = {0};
    if (getxattr("file", name, NULL, 0, 0, 0) != -1 || errno != ENOATTR ||
        fsetxattr(file, name, value, sizeof value, 0, XATTR_REPLACE) != -1 ||
        errno != ENOATTR ||
        fsetxattr(file, name, value, sizeof value, 0, XATTR_CREATE | XATTR_REPLACE) != -1 ||
        errno != EINVAL || fsetxattr(file, name, value, sizeof value, 0, XATTR_CREATE) ||
        fsetxattr(file, name, value, sizeof value, 0, XATTR_CREATE) != -1 || errno != EEXIST)
        return 3;
    if (fgetxattr(file, name, buffer, 2, 0, 0) != -1 || errno != ERANGE ||
        getxattr("file", name, buffer, 0, 0, 0) != -1 || errno != ERANGE ||
        fgetxattr(file, name, buffer, 0, 0, 0) != sizeof value ||
        fgetxattr(file, name, buffer, sizeof buffer, 1, 0) != -1 || errno != EINVAL ||
        fgetxattr(file, name, NULL, 0, 1, 0) != sizeof value ||
        getxattr("alias", name, buffer, sizeof buffer, 0, 0) != sizeof value ||
        memcmp(buffer, value, sizeof value)) return 4;
    if (flistxattr(file, NULL, 0, 0) != sizeof name ||
        flistxattr(file, buffer, sizeof name - 1, 0) != -1 || errno != ERANGE ||
        flistxattr(file, buffer, sizeof buffer, 0) != sizeof name ||
        memcmp(buffer, name, sizeof name)) return 5;

    if (getxattr("link", name, NULL, 0, 0, XATTR_NOFOLLOW) != -1 || errno != ENOATTR ||
        setxattr("link", name, "L", 1, 0, XATTR_NOFOLLOW) ||
        getxattr("link", name, buffer, sizeof buffer, 0, XATTR_NOFOLLOW) != 1 ||
        buffer[0] != 'L' || getxattr("link", name, buffer, sizeof buffer, 0, 0) != sizeof value ||
        memcmp(buffer, value, sizeof value) || setxattr("dir", name, NULL, 0, 0, 0) ||
        getxattr("dir", name, buffer, sizeof buffer, 0, 0) != 0) return 6;
    if (fchmod(file, 0400) || fgetxattr(file, name, NULL, 0, 0, 0) != sizeof value ||
        fremovexattr(file, name, 0) != -1 || errno != EACCES || fchmod(file, 0200) ||
        flistxattr(file, NULL, 0, 0) != -1 || errno != EACCES ||
        fsetxattr(file, name, value, sizeof value, 0, XATTR_REPLACE) || fchmod(file, 0600))
        return 7;

    const char finder[] = "com.apple.FinderInfo";
    const char fork[] = "com.apple.ResourceFork";
    const char finder_data[32] = {1, 2, 3};
    const char finder_empty[32] = {0};
    const char fork_data[] = {0, 0, 'A', 0, 'Z'};
    if (fsetxattr(file, finder, finder_data, 3, 0, 0) != -1 || errno != ERANGE ||
        fsetxattr(file, finder, finder_data, sizeof finder_data, 0, 0) ||
        fgetxattr(file, finder, NULL, 0, 0, 0) != sizeof finder_data ||
        fsetxattr(file, finder, finder_empty, sizeof finder_empty, 0, XATTR_CREATE) != -1 ||
        errno != EEXIST || fsetxattr(file, finder, finder_empty, sizeof finder_empty, 0, XATTR_REPLACE) ||
        fgetxattr(file, finder, NULL, 0, 0, 0) != -1 || errno != ENOATTR ||
        fsetxattr(file, fork, NULL, 0, 2, 0) ||
        fgetxattr(file, fork, NULL, 0, 0, 0) != -1 || errno != ENOATTR ||
        fsetxattr(file, fork, value, sizeof value, 2, XATTR_CREATE) ||
        fgetxattr(file, fork, buffer, sizeof buffer, 0, 0) != sizeof fork_data ||
        memcmp(buffer, fork_data, sizeof fork_data) ||
        fgetxattr(file, fork, buffer, 1, 4, 0) != 1 || buffer[0] != 'Z' ||
        fgetxattr(file, fork, buffer, sizeof buffer, 8, 0) != 0 ||
        fsetxattr(file, fork, NULL, 0, 9, XATTR_REPLACE) ||
        fgetxattr(file, fork, NULL, 0, 0, 0) != sizeof fork_data ||
        setxattr("dir", fork, value, sizeof value, 0, 0) != -1 || errno != EPERM)
        return 8;
    if (fsetxattr(file, "com.apple.system.rax", value, sizeof value, 0, 0) != -1 ||
        errno != EPERM || unlink("link") || unlink("alias") || unlink("file") ||
        fgetxattr(file, name, buffer, sizeof buffer, 0, 0) != sizeof value ||
        memcmp(buffer, value, sizeof value) || fremovexattr(file, name, 0) ||
        fremovexattr(file, name, 0) != -1 || errno != ENOATTR ||
        close(file) || rmdir("dir") || chdir("/") || rmdir(argv[1])) return 9;
    puts("private extended attributes are shared by inode and retained after unlink");
    return 0;
}
