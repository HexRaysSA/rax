#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static void result(const char *label, long value) {
    printf("%s status=%ld errno=%d\n", label, value, value < 0 ? errno : 0);
}

int main(int argc, char **argv) {
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int file = open("original", O_CREAT | O_RDWR, 0600);
    if (file < 0 || mkdir("directory", 0700)) return 2;
    result("create hard link", linkat(AT_FDCWD, "original", AT_FDCWD, "alias", 0));
    int alias = open("alias", O_RDWR);
    if (alias < 0 || pwrite(alias, "R", 1, 0) != 1) return 7;
    char byte;
    if (pread(file, &byte, 1, 0) != 1) return 8;
    struct stat original_stat, alias_stat;
    if (fstat(file, &original_stat) || fstat(alias, &alias_stat) || close(alias)) return 9;
    printf("shared bytes=%c inode=%d link count=%lu\n", byte,
           original_stat.st_ino == alias_stat.st_ino, (unsigned long)alias_stat.st_nlink);
    result("create symlink source", symlink("original", "symlink"));
    result("link target with follow", linkat(AT_FDCWD, "symlink", AT_FDCWD, "follow", AT_SYMLINK_FOLLOW));
    result("link symlink with no follow", linkat(AT_FDCWD, "symlink", AT_FDCWD, "nofollow", 0));
    struct stat stat;
    if (lstat("nofollow", &stat) == 0)
        printf("nofollow is link=%d nlink=%lu\n", S_ISLNK(stat.st_mode), (unsigned long)stat.st_nlink);
    result("link directory", linkat(AT_FDCWD, "directory", AT_FDCWD, "dirlink", 0));
    result("link duplicate", linkat(AT_FDCWD, "original", AT_FDCWD, "alias", 0));
    result("link to missing destination with slash", linkat(AT_FDCWD, "original", AT_FDCWD, "missing/", 0));
    result("link to existing destination with slash", linkat(AT_FDCWD, "original", AT_FDCWD, "alias/", 0));
    result("link file path with trailing slash", linkat(AT_FDCWD, "original/", AT_FDCWD, "other", 0));
    result("rename to same inode", rename("original", "alias"));
    printf("rename kept names=%d\n", access("original", F_OK) == 0 && access("alias", F_OK) == 0);
#if defined(__APPLE__)
    result("rename exclusive to same inode", renameatx_np(AT_FDCWD, "original", AT_FDCWD, "alias", RENAME_EXCL));
    result("rename exchange with same inode", renameatx_np(AT_FDCWD, "original", AT_FDCWD, "alias", RENAME_SWAP));
#else
    result("rename exclusive to same inode", renameat2(AT_FDCWD, "original", AT_FDCWD, "alias", RENAME_NOREPLACE));
    result("rename exchange with same inode", renameat2(AT_FDCWD, "original", AT_FDCWD, "alias", RENAME_EXCHANGE));
#endif
    char path[2048];
#if defined(__APPLE__)
    if (fcntl(file, F_GETPATH, path)) return 3;
#else
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", file);
    ssize_t size = readlink(proc, path, sizeof(path) - 1);
    if (size < 0) return 3;
    path[size] = '\0';
#endif
    printf("retained descriptor path=%s\n", strrchr(path, '/') + 1);
    if (unlink("original") || fstat(file, &stat)) return 4;
    printf("retained fd after unlink nlink=%lu\n", (unsigned long)stat.st_nlink);
    if (unlink("alias") || unlink("follow") || fstat(file, &stat)) return 5;
    printf("retained fd after last unlink nlink=%lu\n", (unsigned long)stat.st_nlink);
    close(file);
    if (unlink("symlink") || unlink("nofollow") || rmdir("directory") || chdir("/") || rmdir(argv[1])) return 6;
    return 0;
}
