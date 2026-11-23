#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>

static void require(int result, const char *label) {
    if (result) {
        perror(label);
        exit(1);
    }
}

static int report(int result) {
    return result == -1 ? errno : 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    require(mkdir(argv[1], 0700), "mkdir");
    require(chdir(argv[1]), "chdir");
    umask(077);
    int dir = open(".", O_RDONLY | O_DIRECTORY);
    int file = open("source", O_CREAT | O_EXCL | O_RDWR, 0640);
    require(dir < 0 || file < 0, "open");
    require(fchmod(file, 0640), "mode");
    require(write(file, "before", 6) != 6, "write");
    require(fsetxattr(file, "user.rax.clone", "value", 5, 0, 0), "set xattr");

    require(fsetxattr(file, "com.apple.ResourceFork", "fork", 4, 0, 0), "set resource fork");
    struct timeval times[2] = {{1000000000, 123456}, {1000000010, 654321}};
    require(futimes(file, times), "futimes");
    struct stat original, copy;
    require(fstat(file, &original), "fstat");
    printf("path=%d\n", report(clonefileat(dir, "source", dir, "copy", 0)));
    if (stat("copy", &copy) == 0) {
        char value[8] = {0};
        char content[8] = {0};
        int cloned = open("copy", O_RDWR);
        require(cloned < 0 || read(cloned, content, sizeof(content)) != 6, "read copy");
        ssize_t length = fgetxattr(cloned, "user.rax.clone", value, sizeof(value), 0, 0);
        printf("distinct=%d contents=%s xattr=%ld:%s mode=%o match-times=%d%d%d\n",
               original.st_ino != copy.st_ino, content, (long)length, value,
               copy.st_mode & 07777,
               original.st_atimespec.tv_sec == copy.st_atimespec.tv_sec,
               original.st_mtimespec.tv_sec == copy.st_mtimespec.tv_sec,
               original.st_birthtimespec.tv_sec == copy.st_birthtimespec.tv_sec);

        char fork[8] = {0};
        ssize_t fork_length = fgetxattr(cloned, "com.apple.ResourceFork", fork, sizeof(fork), 0, 0);
        require(fsetxattr(cloned, "user.rax.clone", "other", 5, 0, 0), "replace copy xattr");
        memset(value, 0, sizeof(value));
        require(fgetxattr(file, "user.rax.clone", value, sizeof(value), 0, 0) != 5, "source xattr");
        require(pwrite(cloned, "copy!!", 6, 0) != 6, "write copy");
        memset(content, 0, sizeof(content));
        require(pread(file, content, sizeof(content), 0) != 6, "source after writing copy");
        printf("fork=%ld:%s independent=%s:%s\n", (long)fork_length, fork, content, value);
        require(close(cloned), "close cloned");
    }
    printf("existing=%d\n", report(clonefileat(dir, "source", dir, "copy", 0)));
    require(symlink("source", "alias"), "source link");
    printf("follow-source=%d\n", report(clonefileat(dir, "alias", dir, "follow", 0)));
    printf("clone-symlink=%d\n", report(clonefileat(dir, "alias", dir, "link-copy", CLONE_NOFOLLOW)));

    require(lstat("link-copy", &copy), "stat cloned symlink");
    char target[16] = {0};
    ssize_t target_length = readlink("link-copy", target, sizeof(target) - 1);
    printf("symlink=%d:%ld:%s\n", S_ISLNK(copy.st_mode), (long)target_length, target);
    require(symlink("missing-target", "destination-link"), "destination link");
    printf("dangling-destination=%d\n", report(clonefileat(dir, "source", dir, "destination-link", 0)));
    printf("dangling-nofollow=%d\n", report(clonefileat(dir, "source", dir, "destination-link", CLONE_NOFOLLOW)));
    printf("nofollow-any=%d\n", report(clonefileat(dir, "alias", dir, "any-copy", CLONE_NOFOLLOW_ANY)));
    printf("bad-flags=%d\n", report(clonefileat(dir, "source", dir, "any-copy", 0x80000000u)));
    int write_only = open("source", O_WRONLY);
    require(write_only < 0, "open write-only");
    printf("write-only=%d\n", report(fclonefileat(write_only, dir, "fd-clone", 0)));
    require(close(write_only), "close write-only");
    require(pwrite(file, "after!", 6, 0) != 6 || unlink("source"), "replace and unlink");
    printf("detached-fd=%d\n", report(fclonefileat(file, dir, "fd-clone", 0)));
    if (stat("fd-clone", &copy) == 0) {
        char content[8] = {0};
        int cloned = open("fd-clone", O_RDONLY);
        require(cloned < 0 || read(cloned, content, sizeof(content)) != 6, "read fd clone");
        printf("after-unlink=%s\n", content);
        require(close(cloned), "close fd clone");
    }
    require(close(file) || close(dir), "close");
    return 0;
}
