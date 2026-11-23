#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static const char name[] = "com.apple.ResourceFork";
static const char path[] = "file/..namedfork/rsrc";

static void result(const char *label, ssize_t status) {
    printf("%s status=%zd errno=%d\n", label, status, status < 0 ? errno : 0);
}

static void bytes(const char *label, ssize_t size, const unsigned char *value) {
    result(label, size);
    if (size <= 0) return;
    for (ssize_t index = 0; index < size; ++index) printf("%02x", value[index]);
    putchar('\n');
}

int main(int argc, char **argv) {
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int base = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (base < 0 || write(base, "data", 4) != 4) return 2;
    struct stat base_stat, fork_stat;
    result("absent path", stat(path, &fork_stat));
    int fork = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fork < 0) {
        result("create fork", -1);
        return 3;
    }
    result("empty path", stat(path, &fork_stat));
    result("empty attribute", fgetxattr(base, name, NULL, 0, 0, 0));
    result("sparse stream write", pwrite(fork, "rs", 2, 2));
    unsigned char value[16] = {0};
    bytes("stream through attribute", fgetxattr(base, name, value, sizeof(value), 0, 0), value);
    if (fstat(base, &base_stat) || fstat(fork, &fork_stat)) return 4;
    printf("same inode=%d mode=%d data size=%lld fork size=%lld\n",
           base_stat.st_ino == fork_stat.st_ino, base_stat.st_mode == fork_stat.st_mode,
           (long long)base_stat.st_size, (long long)fork_stat.st_size);
    char full_path[1024];
    if (fcntl(fork, F_GETPATH, full_path) < 0) return 5;
    printf("descriptor fork path=%d\n", strstr(full_path, "/file/..namedfork/rsrc") != NULL);
    result("attribute rewrite", fsetxattr(base, name, "Q", 1, 1, 0));
    result("seek from fork end", lseek(fork, -3, SEEK_END));
    int dup_fd = dup(fork);
    if (dup_fd < 0) return 6;
    bytes("duplicate cursor", read(dup_fd, value, 1), value);
    bytes("shared cursor", read(fork, value, sizeof(value)), value);
    if (link("file", "hard") || symlink("file", "link")) return 7;
    result("hardlink fork", stat("hard/..namedfork/rsrc", &fork_stat));
    result("follow symlink fork", stat("link/..namedfork/rsrc", &fork_stat));
    result("no follow symlink fork", lstat("link/..namedfork/rsrc", &fork_stat));
    result("trailing slash", stat("file/..namedfork/rsrc/", &fork_stat));
    result("directory fork", stat("./..namedfork/rsrc", &fork_stat));
    result("attribute on fork descriptor", fgetxattr(fork, name, NULL, 0, 0, 0));
    result("access fork path", access(path, R_OK));
    result("chmod fork path", chmod(path, 0644));
    result("chmod fork descriptor", fchmod(fork, 0644));
    result("set xattr on fork path", setxattr(path, "com.example.metadata", "x", 1, 0, 0));
    result("unlink fork path", unlink(path));
    result("fsync fork", fsync(fork));
    result("remove while open", fremovexattr(base, name, 0));
    void *mapping = mmap(NULL, 4, PROT_READ, MAP_PRIVATE, fork, 0);
    if (mapping == MAP_FAILED) {
        result("map fork", -1);
        return 9;
    }
    bytes("mapped fork", 4, mapping);
    if (munmap(mapping, 4)) return 10;
    result("resize fork", ftruncate(fork, 6));
    bytes("extended attribute", fgetxattr(base, name, value, sizeof(value), 0, 0), value);
    result("zero fork", ftruncate(fork, 0));
    result("zero attribute", fgetxattr(base, name, NULL, 0, 0, 0));
    result("write after zero", pwrite(fork, "again", 5, 0));
    bytes("rewritten attribute", fgetxattr(base, name, value, sizeof(value), 0, 0), value);
    if (close(dup_fd) || close(fork)) return 8;
    result("remove after close", fremovexattr(base, name, 0));
    result("removed path", stat(path, &fork_stat));
    return close(base) || unlink("link") || unlink("hard") ||
           unlink("file") || chdir("/") || rmdir(argv[1]);
}
