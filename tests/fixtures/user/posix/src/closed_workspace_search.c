#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    if (mkdir("search", 0700) || symlink("search", "alias")) return 2;
    int initial = open("search/data", O_CREAT | O_RDWR, 0600);
    if (initial < 0 || write(initial, "x", 1) != 1 || close(initial) ||
        symlink("data", "search/relative") || chmod("search", 0100)) return 3;

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

    if (fchmod(directory, 0700) || close(directory) || unlink("search/relative") ||
        unlink("search/data") || unlink("alias") || rmdir("search") ||
        chdir("/") || rmdir(argv[1])) return 10;
    puts("search descriptors authorize the first relative traversal");
    return 0;
}
