#define _DARWIN_C_SOURCE 1
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#define atime_of(st) ((st).st_atimespec)
#define mtime_of(st) ((st).st_mtimespec)
#else
#define atime_of(st) ((st).st_atim)
#define mtime_of(st) ((st).st_mtim)
#endif

static int equal_time(struct timespec actual, struct timespec expected)
{
    return actual.tv_sec == expected.tv_sec && actual.tv_nsec == expected.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int dir = open(".", O_RDONLY | O_DIRECTORY);
    int fd = open("file", O_CREAT | O_RDWR, 0600);
    if (dir < 0 || fd < 0 || link("file", "alias") || symlink("file", "symbol")) return 2;

    struct stat original, alias, symbol;
    if (fchmodat(dir, "alias", 0641, 0) || fstat(fd, &original) ||
        fstatat(dir, "alias", &alias, 0) || (original.st_mode & 07777) != 0641 ||
        alias.st_mode != original.st_mode || alias.st_ino != original.st_ino) return 3;
    if (chmod("symbol", 0604) || fstat(fd, &original) ||
        (original.st_mode & 07777) != 0604) return 4;

    const struct timespec exact[2] = {{1200000001, 123456019}, {1200000002, 989898037}};
    if (utimensat(dir, "alias", exact, 0) || fstat(fd, &original) ||
        !equal_time(atime_of(original), exact[0]) ||
        !equal_time(mtime_of(original), exact[1])) return 5;
#if defined(__APPLE__)
    if (original.st_birthtimespec.tv_sec != exact[1].tv_sec ||
        fchmodat(dir, "symbol", 0620, AT_SYMLINK_NOFOLLOW) ||
        lstat("symbol", &symbol) || (symbol.st_mode & 07777) != 0620) return 6;
#endif

    const struct timespec link_times[2] = {{1200000011, 117}, {1200000012, 221}};
    if (utimensat(dir, "symbol", link_times, AT_SYMLINK_NOFOLLOW) ||
        lstat("symbol", &symbol) || !equal_time(atime_of(symbol), link_times[0]) ||
        !equal_time(mtime_of(symbol), link_times[1]) || fstat(fd, &original) ||
        !equal_time(mtime_of(original), exact[1])) return 7;

    const struct timespec leave_access[2] = {{0, UTIME_OMIT}, {1200000021, 3003}};
    if (unlink("alias") || unlink("file") || fchmod(fd, 0644) ||
        futimens(fd, leave_access) || fstat(fd, &original) || original.st_nlink != 0 ||
        (original.st_mode & 07777) != 0644 || !equal_time(atime_of(original), exact[0]) ||
        !equal_time(mtime_of(original), leave_access[1])) return 8;

    const struct timeval microseconds[2] = {{1200000031, 171}, {1200000032, 777}};
    if (futimes(fd, microseconds) || fstat(fd, &original) ||
        !equal_time(atime_of(original), (struct timespec){1200000031, 171000}) ||
        !equal_time(mtime_of(original), (struct timespec){1200000032, 777000})) return 9;

    const struct timespec noncanonical[2] = {{1200000041, 1000000000}, {1200000043, -3}};
#if defined(__APPLE__)
    if (futimens(fd, noncanonical) || fstat(fd, &alias) ||
        !equal_time(atime_of(alias), (struct timespec){1200000042, 0}) ||
        !equal_time(mtime_of(alias), (struct timespec){1200000042, 999999997})) return 10;
#else
    if (futimens(fd, noncanonical) != -1 || errno != EINVAL || fstat(fd, &alias) ||
        !equal_time(atime_of(alias), atime_of(original)) ||
        !equal_time(mtime_of(alias), mtime_of(original))) return 10;
#endif

    if (fchmod(dir, 0750) || utimensat(dir, ".", exact, 0) || fstat(dir, &alias) ||
        (alias.st_mode & 07777) != 0750 || !equal_time(mtime_of(alias), exact[1])) return 11;
    if (close(fd) || close(dir) || unlink("symbol") || chdir("/") || rmdir(argv[1])) return 12;
    puts("modes and exact timestamps follow inode identity");
    return 0;
}
