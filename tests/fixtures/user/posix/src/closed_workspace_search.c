#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    if (mkdir("search", 0700) || mkdir("search/deeper", 0700) ||
        symlink("search", "alias")) return 2;
    int initial = open("search/data", O_CREAT | O_RDWR, 0600);
    if (initial < 0 || write(initial, "x", 1) != 1 || close(initial) ||
        symlink("data", "search/relative") || symlink("absent", "search/dangling") ||
        chmod("search", 0100)) return 3;

    if (open("search", O_DIRECTORY) != -1 || errno != EACCES ||
        open("search", O_SEARCH | O_RDWR) != -1 || errno != EINVAL ||
        open("search/data", O_SEARCH) != -1 || errno != ENOTDIR ||
        open("alias", O_SEARCH | O_NOFOLLOW_ANY) != -1 || errno != ELOOP) return 4;
    int directory = open("alias", O_SEARCH | O_CLOEXEC);
    if (directory < 0 || fcntl(directory, F_GETFL) != O_EXEC ||
        fcntl(directory, F_GETFD) != FD_CLOEXEC) return 5;
    char byte;
    if (read(directory, &byte, 1) != -1 || errno != EBADF ||
        pread(directory, &byte, 1, 0) != -1 || errno != EBADF ||
        write(directory, "x", 1) != -1 || errno != EBADF) return 6;

    if (fchmod(directory, 0) || open("search/data", O_RDONLY) != -1 ||
        errno != EACCES || fchdir(directory) != -1 || errno != EACCES) return 7;
    int data = openat(directory, "data", O_RDONLY);
    struct stat status;
    if (data < 0 || read(data, &byte, 1) != 1 || byte != 'x' ||
        close(data) || fstatat(directory, "data", &status, 0) || status.st_size != 1) return 8;
    if (openat(directory, "relative", O_RDONLY) != -1 || errno != EACCES ||
        openat(directory, "missing", O_RDONLY | O_NOFOLLOW_ANY) != -1 || errno != ENOENT)
        return 9;

    if (openat(directory, "unwritable", O_CREAT | O_EXCL | O_RDWR, 0600) != -1 ||
        errno != EACCES || fchmod(directory, 0200)) return 10;
    int direct = openat(directory, "direct", O_CREAT | O_EXCL | O_RDWR, 0600);
    int nested = openat(directory, "deeper/nested", O_CREAT | O_RDWR, 0600);
    if (direct < 0 || nested < 0 || fstat(direct, &status) ||
        (status.st_mode & 0777) != 0600 || close(direct) || close(nested)) return 11;
    if (openat(directory, "direct", O_CREAT | O_EXCL | O_RDWR, 0600) != -1 ||
        errno != EEXIST ||
        openat(directory, "dangling", O_CREAT | O_RDWR, 0600) != -1 ||
        errno != EACCES ||
        openat(directory, "missing/child", O_CREAT | O_RDWR, 0600) != -1 ||
        errno != ENOENT ||
        openat(directory, "trailing/", O_CREAT | O_RDWR, 0600) != -1 ||
        errno != ENOENT ||
        open("search/no-grant", O_CREAT | O_RDWR, 0600) != -1 ||
        errno != EACCES) return 12;

    if (fchmod(directory, 0700) || close(directory) || unlink("search/relative") ||
        unlink("search/dangling") || unlink("search/data") || unlink("search/direct") ||
        unlink("search/deeper/nested") || rmdir("search/deeper") || unlink("alias") ||
        rmdir("search") || chdir("/") || rmdir(argv[1])) return 13;
    puts("search descriptors authorize the first relative traversal");
    return 0;
}
