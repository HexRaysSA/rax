#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXPECT(test)                                                          \
    do {                                                                      \
        if (!(test)) {                                                        \
            fprintf(stderr, "%u: %s (errno=%d)\n", __LINE__, #test, errno);      \
            return 1;                                                         \
        }                                                                     \
    } while (0)

int main(int argc, char **argv) {
    EXPECT(argc == 2);
    const char *base = argv[1];
    umask(0027);
    EXPECT(mkdir(base, 0770) == 0);
    int parent = open(base, O_RDONLY | O_DIRECTORY);
    EXPECT(parent >= 0);
    struct stat parent_stat, child_stat, file_stat;
    EXPECT(fstat(parent, &parent_stat) == 0);
    EXPECT(S_ISDIR(parent_stat.st_mode) && (parent_stat.st_mode & 0777) == 0750);
    EXPECT(mkdirat(parent, "child/", 0777) == 0);
    EXPECT(mkdirat(parent, "child", 0777) == -1 && errno == EEXIST);
    EXPECT(mkdirat(parent, "missing/child", 0700) == -1 && errno == ENOENT);
    EXPECT(fstatat(parent, "child", &child_stat, 0) == 0);
    EXPECT(S_ISDIR(child_stat.st_mode) && (child_stat.st_mode & 0777) == 0750);
    EXPECT(child_stat.st_ino != parent_stat.st_ino);
    EXPECT(child_stat.st_uid == geteuid());
#ifdef __APPLE__
    EXPECT(child_stat.st_gid == parent_stat.st_gid);
#else
    EXPECT(child_stat.st_gid == getegid());
#endif
    int child = openat(parent, "child", O_RDONLY | O_DIRECTORY);
    EXPECT(child >= 0);
    EXPECT(fchdir(child) == 0);
    int file = open("data", O_CREAT | O_EXCL | O_RDWR, 0666);
    EXPECT(file >= 0);
    EXPECT(write(file, "test", 4) == 4);
    char bytes[4] = {0};
    EXPECT(pread(file, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes));
    EXPECT(memcmp(bytes, "test", sizeof(bytes)) == 0);
    EXPECT(fstatat(child, "data", &file_stat, 0) == 0);
    EXPECT(S_ISREG(file_stat.st_mode) && (file_stat.st_mode & 0777) == 0640);
    EXPECT(file_stat.st_uid == child_stat.st_uid && file_stat.st_gid == child_stat.st_gid);
    EXPECT(close(file) == 0);
    EXPECT(close(child) == 0);
    DIR *directory = fdopendir(dup(parent));
    EXPECT(directory != NULL);
    int found = 0;
    errno = 0;
    for (struct dirent *entry; (entry = readdir(directory)) != NULL;) {
        if (strcmp(entry->d_name, "child") == 0) {
            EXPECT(entry->d_type == DT_DIR);
            found++;
        }
    }
    EXPECT(found == 1 && errno == 0);
    EXPECT(mkdirat(parent, "late-child", 0755) == 0);
    rewinddir(directory);
    found = 0;
    errno = 0;
    for (struct dirent *entry; (entry = readdir(directory)) != NULL;) {
        if (strcmp(entry->d_name, "late-child") == 0) {
            EXPECT(entry->d_type == DT_DIR);
            found++;
        }
    }
    EXPECT(found == 1 && errno == 0);
    EXPECT(closedir(directory) == 0);
    EXPECT(unlinkat(parent, "child", AT_REMOVEDIR) == -1 && errno == ENOTEMPTY);
    EXPECT(unlink("data") == 0);
    EXPECT(access("data", F_OK) == -1 && errno == ENOENT);
    child = openat(parent, "child", O_RDONLY | O_DIRECTORY);
    EXPECT(child >= 0);
    EXPECT(unlinkat(parent, "child", AT_REMOVEDIR) == 0);
    EXPECT(fchdir(child) == 0);
    char cwd[4096];
    EXPECT(getcwd(cwd, sizeof(cwd)) == NULL && errno == ENOENT);
    EXPECT(mkdirat(parent, "child", 0755) == 0);
    EXPECT(mkdir("orphan", 0700) == -1 && errno == ENOENT);
    EXPECT(mkdirat(child, "orphan", 0700) == -1 && errno == ENOENT);
    struct stat removed_stat, fresh_stat;
    EXPECT(fstat(child, &removed_stat) == 0);
    EXPECT(fstatat(parent, "child", &fresh_stat, 0) == 0);
    EXPECT(removed_stat.st_ino == child_stat.st_ino && fresh_stat.st_ino != child_stat.st_ino);
    EXPECT(fstatat(child, ".", &removed_stat, 0) == 0 && removed_stat.st_ino == child_stat.st_ino);
    EXPECT(fstatat(child, "..", &removed_stat, 0) == 0 && removed_stat.st_ino == parent_stat.st_ino);
    directory = fdopendir(child);
    EXPECT(directory != NULL);
    errno = 0;
    EXPECT(readdir(directory) == NULL && errno == 0);
    EXPECT(closedir(directory) == 0);
    EXPECT(chdir("..") == 0);
    EXPECT(unlinkat(parent, "child", AT_REMOVEDIR) == 0);
    EXPECT(unlinkat(parent, "late-child", AT_REMOVEDIR) == 0);
    EXPECT(close(parent) == 0);
    EXPECT(chdir("/") == 0);
    EXPECT(rmdir(base) == 0);
    puts("directory creation, listing, removal, and retained handles: correct");
    return 0;
}
