#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int checked(int value, const char *operation) {
    if (value < 0) {
        perror(operation);
        exit(2);
    }
    return value;
}

static void report(const char *operation, long result) {
    printf("%s ret=%ld errno=%d\n", operation, result, result < 0 ? errno : 0);
}

static void check_link(int root, const char *path) {
    char buffer[32] = {0};
    ssize_t count = readlinkat(root, path, buffer, 3);
    report("truncated link length", count);
    printf("truncated target=%.*s\n", count > 0 ? (int)count : 0, buffer);
    report("zero length readlink", readlinkat(root, path, buffer, 0));
    int fd = openat(root, path, O_RDONLY | O_NOFOLLOW);
    report("nofollow open", fd < 0 ? fd : 0);
    if (fd >= 0) checked(close(fd), "close unexpected nofollow fd");
    fd = openat(root, path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    report("exclusive create at link", fd < 0 ? fd : 0);
    if (fd >= 0) checked(close(fd), "close unexpected exclusive fd");

    struct stat info;
    checked(fstatat(root, path, &info, AT_SYMLINK_NOFOLLOW), "lstat workspace link");
    printf("initial link mode=%o size=%lld nlink=%u\n", (unsigned)info.st_mode,
           (long long)info.st_size, (unsigned)info.st_nlink);

    checked(mkdirat(root, "moved", 0700), "mkdir moved");
    fd = checked(openat(root, path, O_RDONLY |
#if defined(__APPLE__)
                       O_SYMLINK
#else
                       O_PATH | O_NOFOLLOW
#endif
                       ), "open link itself");
    checked(renameat(root, path, root, "moved/link"), "rename link itself");
    struct stat moved;
    checked(fstatat(root, "moved/link", &moved, AT_SYMLINK_NOFOLLOW), "lstat moved link");
    printf("rename preserves link identity=%d\n", moved.st_ino == info.st_ino);
    checked(unlinkat(root, "moved/link", 0), "unlink moved link");
#if defined(__APPLE__)
    report("read retained link descriptor", read(fd, buffer, sizeof(buffer)));
#else
    memset(buffer, 0, sizeof(buffer));
    report("read retained link descriptor", readlinkat(fd, "", buffer, sizeof(buffer)));
    printf("retained target=%s\n", buffer);
#endif
    checked(fstat(fd, &moved), "stat retained link");
    printf("retained inode=%d nlink=%u\n", moved.st_ino == info.st_ino, (unsigned)moved.st_nlink);
    checked(close(fd), "close link");
    checked(unlinkat(root, "moved", AT_REMOVEDIR), "remove moved");
}

static void check_resolve(int root, const char *base) {
    checked(mkdirat(root, "nested", 0700), "mkdir nested");
    checked(symlinkat("../target", root, "nested/link"), "create dangling relative link");
    int fd = checked(openat(root, "nested/link", O_CREAT | O_WRONLY, 0600), "create link target");
    checked((int)write(fd, "R", 1), "write link target");
    checked(close(fd), "close link target");
    char absolute[1024];
    if ((size_t)snprintf(absolute, sizeof(absolute), "%s/target", base) >= sizeof(absolute)) exit(3);
    checked(symlinkat(absolute, root, "absolute"), "create absolute workspace link");
    fd = checked(openat(root, "absolute", O_RDONLY), "open absolute link");
    char byte;
    if (read(fd, &byte, 1) != 1) exit(4);
    printf("absolute link observes relative create=%c\n", byte);
    checked(close(fd), "close absolute target");

    checked(symlinkat("loop-b", root, "loop-a"), "create loop-a");
    checked(symlinkat("loop-a", root, "loop-b"), "create loop-b");
    fd = openat(root, "loop-a", O_RDONLY);
    report("symlink cycle", fd < 0 ? fd : 0);
    if (fd >= 0) checked(close(fd), "close unexpected cyclic fd");
    checked(symlinkat("\377", root, "raw"), "create non-UTF-8 target");
    checked((int)readlinkat(root, "raw", &byte, 1), "read non-UTF-8 target");
    printf("raw target byte=%u\n", (unsigned)(unsigned char)byte);

    DIR *stream = fdopendir(checked(dup(root), "duplicate directory"));
    if (!stream) exit(5);
    struct dirent *entry;
    while ((entry = readdir(stream)) && strcmp(entry->d_name, "absolute") != 0) {}
    printf("directory reports symlink=%d\n", entry && entry->d_type == DT_LNK);
    checked(closedir(stream), "close directory stream");

    check_link(root, "nested/link");
    for (const char **name = (const char *[]){"target", "absolute", "loop-a", "loop-b", "raw", NULL};
         *name; ++name) checked(unlinkat(root, *name, 0), "unlink fixture entry");
    checked(unlinkat(root, "nested", AT_REMOVEDIR), "remove nested");
}

static void check_directory_slash(int root) {
    checked(mkdirat(root, "directory", 0700), "mkdir directory target");
    checked(symlinkat("directory", root, "dir-link"), "symlink to directory");
    report("unlink trailing directory link", unlinkat(root, "dir-link/", 0));
    report("rename trailing directory link", renameat(root, "dir-link/", root, "renamed"));
    struct stat info;
    printf("renamed target exists=%d link identity retained=%d\n",
           fstatat(root, "renamed", &info, 0) == 0,
           fstatat(root, "dir-link", &info, AT_SYMLINK_NOFOLLOW) == 0);
    checked(unlinkat(root, "dir-link", 0), "remove dangling or directory link");
    if (unlinkat(root, "renamed", AT_REMOVEDIR) != 0 && errno != ENOENT) exit(6);
    if (unlinkat(root, "directory", AT_REMOVEDIR) != 0 && errno != ENOENT) exit(7);

    int empty = symlinkat("", root, "empty-link");
    report("empty target", empty);
    if (empty == 0) checked(unlinkat(root, "empty-link", 0), "remove empty link");
}

static void check_follow_limit(int root) {
    const unsigned limit =
#if defined(__APPLE__)
        32;
#else
        40;
#endif
    checked(close(checked(openat(root, "end", O_CREAT | O_WRONLY, 0600), "create chain target")),
            "close chain target");
    char link[16];
    char previous[16] = "end";
    for (unsigned n = 1; n <= limit + 1; ++n) {
        snprintf(link, sizeof(link), "chain-%u", n);
        checked(symlinkat(previous, root, link), "create link in chain");
        memcpy(previous, link, strlen(link) + 1);
        if (n >= limit) {
            struct stat info;
            int status = fstatat(root, link, &info, 0);
            report(n == limit ? "last followed link" : "first excess link", status);
        }
    }
    for (unsigned n = 1; n <= limit + 1; ++n) {
        snprintf(link, sizeof(link), "chain-%u", n);
        checked(unlinkat(root, link, 0), "remove link in chain");
    }
    checked(unlinkat(root, "end", 0), "remove chain target");
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    umask(0077);
    checked(mkdir(argv[1], 0700), "mkdir control");
    int root = checked(open(argv[1], O_RDONLY | O_DIRECTORY), "open control");
    check_resolve(root, argv[1]);
    check_directory_slash(root);
    check_follow_limit(root);
    checked(close(root), "close control");
    checked(rmdir(argv[1]), "remove control");
    return 0;
}
