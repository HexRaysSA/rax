#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void result(const char *label, ssize_t status) {
    printf("%s status=%zd errno=%d\n", label, status, status < 0 ? errno : 0);
}

int main(int argc, char **argv) {
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    /* The closed personality starts as virtual root. Exercise ordinary mode
       checks under an unprivileged identity on both sides. */
    int started_as_root = geteuid() == 0;
    if (started_as_root && (chmod(".", 0777) || setgid(65534) || setuid(65534))) return 7;
    const char name[] = "user.private";
    const unsigned char data[] = { 'R', 0, 0xff };
    unsigned char buffer[32] = {0};
    int file = open("original", O_CREAT | O_RDWR, 0600);
    if (file < 0 || link("original", "alias") || symlink("original", "symbol")) return 2;
    int reference = open("original", O_PATH);
    if (reference < 0) return 3;

    result("missing", fgetxattr(file, name, NULL, 0));
    result("replace missing", fsetxattr(file, name, data, sizeof(data), XATTR_REPLACE));
    result("both flags on missing", fsetxattr(file, name, data, sizeof(data),
                                             XATTR_CREATE | XATTR_REPLACE));
    result("set", fsetxattr(file, name, data, sizeof(data), XATTR_CREATE));
    result("both flags on existing", fsetxattr(file, name, data, sizeof(data),
                                              XATTR_CREATE | XATTR_REPLACE));
    result("size via hard link", getxattr("alias", name, NULL, 0));
    result("short buffer", getxattr("alias", name, buffer, 1));
    result("follow symlink", getxattr("symbol", name, buffer, sizeof(buffer)));
    printf("binary value=%d\n", memcmp(buffer, data, sizeof(data)) == 0);
    result("get on symlink", lgetxattr("symbol", name, buffer, sizeof(buffer)));
    result("set on symlink", lsetxattr("symbol", name, data, sizeof(data), 0));
    result("path-only descriptor", fgetxattr(reference, name, NULL, 0));
    result("list size", flistxattr(file, NULL, 0));
    result("list short buffer", flistxattr(file, (char *)buffer, 1));
    result("list names", flistxattr(file, (char *)buffer, sizeof(buffer)));
    printf("listed name=%d\n", memcmp(buffer, name, sizeof(name)) == 0);
    if (fchmod(file, 0400)) return 4;
    result("set on read-only inode", fsetxattr(file, name, "X", 1, XATTR_REPLACE));
    if (fchmod(file, 0200)) return 5;
    result("get on write-only inode", fgetxattr(file, name, NULL, 0));
    result("list on write-only inode", flistxattr(file, NULL, 0));
    if (fchmod(file, 0600) || unlink("original") || unlink("alias")) return 6;
    result("retained after unlink", fgetxattr(file, name, NULL, 0));
    result("replace with empty value", fsetxattr(file, name, NULL, 0, XATTR_REPLACE));
    result("read empty value", fgetxattr(file, name, NULL, 0));
    result("remove", fremovexattr(file, name));
    result("remove again", fremovexattr(file, name));
    result("list after removal", flistxattr(file, NULL, 0));
    if (mkdir("directory", 0700)) return 8;
    result("set on directory", setxattr("directory", name, data, sizeof(data), 0));
    result("get on directory", getxattr("directory", name, NULL, 0));
    result("remove from directory", removexattr("directory", name));
    return close(reference) || close(file) || unlink("symbol") || rmdir("directory") ||
           chdir("/") || (!started_as_root && rmdir(argv[1]));
}
