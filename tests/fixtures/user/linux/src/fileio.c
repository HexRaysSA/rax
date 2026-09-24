/* File, directory, pipe, and descriptor semantics. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "check.h"

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    char dir[] = "/tmp/rax-fixture-XXXXXX";
    CHECK("mkdtemp", mkdtemp(dir) != NULL);
    CHECK("chdir", chdir(dir) == 0);
    char cwd[4096];
    CHECK("getcwd", getcwd(cwd, sizeof cwd) != NULL);
    CHECK("getcwd-basename", strcmp(basename(cwd), basename(dir)) == 0);
    umask(022);

    int fd = open("a.txt", O_CREAT | O_EXCL | O_WRONLY, 0666);
    CHECK("open-create", fd >= 0);
    CHECK("write", write(fd, "hello world\n", 12) == 12);
    CHECK_ERR("read-on-wronly", read(fd, cwd, 1), EBADF);
    CHECK("close", close(fd) == 0);
    CHECK_ERR("close-again", close(fd), EBADF);
    CHECK_ERR("open-excl-exists", open("a.txt", O_CREAT | O_EXCL | O_WRONLY, 0666), EEXIST);

    struct stat st;
    CHECK("stat", stat("a.txt", &st) == 0);
    CHECK("stat-size", st.st_size == 12);
    CHECK("stat-regular", S_ISREG(st.st_mode));
    CHECK("stat-mode-umask", (st.st_mode & 0777) == 0644);
    CHECK("stat-nlink", st.st_nlink == 1);

    char buf[64] = {0};
    fd = open("a.txt", O_RDONLY);
    CHECK("open-rdonly", fd >= 0);
    CHECK("read-5", read(fd, buf, 5) == 5 && memcmp(buf, "hello", 5) == 0);
    CHECK("lseek-cur", lseek(fd, 0, SEEK_CUR) == 5);
    CHECK("pread", pread(fd, buf, 5, 6) == 5 && memcmp(buf, "world", 5) == 0);
    CHECK("pread-keeps-offset", lseek(fd, 0, SEEK_CUR) == 5);
    CHECK("lseek-end", lseek(fd, 0, SEEK_END) == 12);
    CHECK("read-eof", read(fd, buf, sizeof buf) == 0);
    CHECK_ERR("lseek-negative", lseek(fd, -1, SEEK_SET), EINVAL);
    CHECK_ERR("write-on-rdonly", write(fd, "x", 1), EBADF);
    struct stat fst;
    CHECK("fstat", fstat(fd, &fst) == 0 && fst.st_ino == st.st_ino);
    close(fd);

    fd = open("a.txt", O_WRONLY | O_APPEND);
    CHECK("append-open", fd >= 0);
    lseek(fd, 0, SEEK_SET);
    CHECK("append-write", write(fd, "tail\n", 5) == 5);
    CHECK("append-at-end", fstat(fd, &st) == 0 && st.st_size == 17);
    CHECK("ftruncate", ftruncate(fd, 4) == 0 && fstat(fd, &st) == 0 && st.st_size == 4);
    close(fd);

    CHECK_ERR("access-missing", access("b.txt", F_OK), ENOENT);
    CHECK("rename", rename("a.txt", "b.txt") == 0);
    CHECK("access-renamed", access("b.txt", R_OK | W_OK) == 0);
    CHECK("link", link("b.txt", "c.txt") == 0);
    CHECK("link-count", stat("b.txt", &st) == 0 && st.st_nlink == 2);
    CHECK("symlink", symlink("b.txt", "d.lnk") == 0);
    ssize_t n = readlink("d.lnk", buf, sizeof buf);
    CHECK("readlink", n == 5 && memcmp(buf, "b.txt", 5) == 0);
    CHECK("lstat-link", lstat("d.lnk", &st) == 0 && S_ISLNK(st.st_mode));
    CHECK("stat-follows", stat("d.lnk", &st) == 0 && S_ISREG(st.st_mode));
    CHECK_ERR("readlink-not-link", readlink("b.txt", buf, sizeof buf), EINVAL);
    CHECK_ERR("open-directory-on-file", open("b.txt", O_RDONLY | O_DIRECTORY), ENOTDIR);
    CHECK_ERR("open-nofollow-link", open("d.lnk", O_RDONLY | O_NOFOLLOW), ELOOP);

    CHECK("mkdir", mkdir("sub", 0755) == 0);
    CHECK_ERR("mkdir-exists", mkdir("sub", 0755), EEXIST);
    CHECK("create-in-sub", close(open("sub/f", O_CREAT | O_WRONLY, 0600)) == 0);
    CHECK_ERR("rmdir-nonempty", rmdir("sub"), ENOTEMPTY);
    CHECK_ERR("unlink-dir", unlink("sub"), EISDIR);

    DIR *d = opendir(".");
    CHECK("opendir", d != NULL);
    char *names[16];
    int count = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) && count < 16)
        names[count++] = strdup(e->d_name);
    if (d)
        closedir(d);
    qsort(names, count, sizeof names[0], cmp);
    printf("entries:");
    for (int i = 0; i < count; i++)
        printf(" %s", names[i]);
    printf("\n");

    int dfd = open("sub", O_RDONLY | O_DIRECTORY);
    CHECK("openat-dirfd", dfd >= 0 && faccessat(dfd, "f", F_OK, 0) == 0);
    CHECK("fstatat-dirfd", fstatat(dfd, "f", &st, 0) == 0 && (st.st_mode & 0777) == 0600);
    CHECK("unlinkat", unlinkat(dfd, "f", 0) == 0);
    close(dfd);
    CHECK("rmdir", rmdir("sub") == 0);

    int p[2];
    CHECK("pipe", pipe(p) == 0);
    CHECK("pipe-write", write(p[1], "abc", 3) == 3);
    CHECK("pipe-read", read(p[0], buf, sizeof buf) == 3 && memcmp(buf, "abc", 3) == 0);
    close(p[1]);
    CHECK("pipe-eof", read(p[0], buf, sizeof buf) == 0);
    close(p[0]);
    CHECK("pipe2-cloexec", pipe2(p, O_CLOEXEC) == 0 && fcntl(p[0], F_GETFD) == FD_CLOEXEC);
    CHECK("dup2", dup2(p[0], 20) == 20 && fcntl(20, F_GETFD) == 0);
    CHECK("fcntl-dupfd", fcntl(p[1], F_DUPFD, 30) >= 30);
    CHECK("fcntl-getfl", (fcntl(p[1], F_GETFL) & O_ACCMODE) == O_WRONLY);
    CHECK("fcntl-setfl-nonblock", fcntl(p[0], F_SETFL, O_NONBLOCK) == 0);
    CHECK_ERR("read-nonblock-empty", read(p[0], buf, 1), EAGAIN);
    CHECK_ERR("dup3-same", dup3(p[0], p[0], 0), EINVAL);

    CHECK("unlink-c", unlink("c.txt") == 0);
    CHECK("unlink-b", unlink("b.txt") == 0);
    CHECK("unlink-d", unlink("d.lnk") == 0);
    CHECK_ERR("unlink-missing", unlink("b.txt"), ENOENT);
    CHECK("chdir-back", chdir("/") == 0);
    CHECK("rmdir-tmp", rmdir(dir) == 0);
    FINISH();
}
