#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(__APPLE__)
enum { NATIVE_RENAME_EXCLUSIVE = RENAME_EXCL, NATIVE_RENAME_EXCHANGE = RENAME_SWAP };
#else
enum { NATIVE_RENAME_EXCLUSIVE = 1, NATIVE_RENAME_EXCHANGE = 2 };
#endif

static int rename_with_flags(int fromfd, const char *from, int tofd, const char *to, unsigned flags) {
#if defined(__APPLE__)
    return renameatx_np(fromfd, from, tofd, to, flags);
#elif defined(__linux__)
    return (int)syscall(SYS_renameat2, fromfd, from, tofd, to, flags);
#endif
}

static int checked(int rc, const char *operation) {
    if (rc < 0) { perror(operation); _exit(2); }
    return rc;
}

static void result(const char *operation, int rc) {
    printf("%s status=%d errno=%d\n", operation, rc >= 0 ? 0 : -1, rc >= 0 ? 0 : errno);
}

static void write_file(int parent, const char *name, char contents) {
    int file = checked(openat(parent, name, O_WRONLY | O_CREAT | O_EXCL, 0600), "open file for write");
    if (write(file, &contents, 1) != 1) _exit(3);
    checked(close(file), "close write file");
}

static char first_byte(int fd) {
    char byte;
    if (pread(fd, &byte, 1, 0) != 1) _exit(4);
    return byte;
}

static void check_exchange(int root) {
    const unsigned exchange = NATIVE_RENAME_EXCHANGE;
    checked(mkdirat(root, "left", 0700), "mkdir left");
    checked(mkdirat(root, "right", 0700), "mkdir right");
    int left = checked(openat(root, "left", O_RDONLY | O_DIRECTORY), "open left");
    int right = checked(openat(root, "right", O_RDONLY | O_DIRECTORY), "open right");
    checked(mkdirat(left, "subdir", 0700), "mkdir exchange subdir");
    int subdir = checked(openat(left, "subdir", O_RDONLY | O_DIRECTORY), "open exchange subdir");
    write_file(right, "payload", 'X');
    write_file(subdir, "nested", 'N');

    result("exchange missing target", rename_with_flags(left, "subdir", right, "missing", exchange));
    result("exchange missing source", rename_with_flags(right, "missing", left, "subdir", exchange));
    result("exchange self", rename_with_flags(left, "subdir", left, "subdir", exchange));
    result("exchange ancestor", rename_with_flags(root, "left", left, "subdir", exchange));
    result("exchange inverse ancestor", rename_with_flags(left, "subdir", root, "left", exchange));
    result("exchange with incompatible flags",
           rename_with_flags(left, "subdir", right, "payload", exchange | NATIVE_RENAME_EXCLUSIVE));
    checked(rename_with_flags(left, "subdir", right, "payload", exchange), "exchange file and directory");

    struct stat retained, moved, parent, right_info, left_info;
    checked(fstat(subdir, &retained), "stat retained exchange directory");
    checked(fstatat(right, "payload", &moved, 0), "stat exchange directory by new name");
    checked(fstatat(subdir, "..", &parent, 0), "stat new exchange parent through descriptor");
    checked(fstat(right, &right_info), "stat right");
    checked(fstat(left, &left_info), "stat left");
    printf("exchange retains directory=%d changes parent=%d left links=%lu right links=%lu\n",
           retained.st_ino == moved.st_ino, parent.st_ino == right_info.st_ino,
           (unsigned long)left_info.st_nlink, (unsigned long)right_info.st_nlink);
    int file = checked(openat(left, "subdir", O_RDONLY), "open moved exchange file");
    int nested = checked(openat(right, "payload/nested", O_RDONLY), "open moved nested file");
    printf("exchange retains contents file=%c nested=%c\n", first_byte(file), first_byte(nested));
    checked(close(file), "close moved exchange file");
    checked(close(nested), "close moved nested file");
    checked(unlinkat(left, "subdir", 0), "unlink moved exchange file");
    checked(unlinkat(subdir, "nested", 0), "unlink moved nested file");
    checked(unlinkat(right, "payload", AT_REMOVEDIR), "remove moved exchange directory");
    checked(close(subdir), "close exchange directory");
    checked(close(left), "close left");
    checked(close(right), "close right");
    checked(unlinkat(root, "left", AT_REMOVEDIR), "remove left");
    checked(unlinkat(root, "right", AT_REMOVEDIR), "remove right");
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    checked(mkdir(argv[1], 0700), "mkdir control");
    int root = checked(open(argv[1], O_RDONLY | O_DIRECTORY), "open control");
    checked(mkdirat(root, "source", 0700), "mkdir source");
    checked(mkdirat(root, "target", 0700), "mkdir target");
    int source = checked(openat(root, "source", O_RDONLY | O_DIRECTORY), "open source");
    int target = checked(openat(root, "target", O_RDONLY | O_DIRECTORY), "open target");
    checked(mkdirat(source, "descendant", 0700), "mkdir descendant");
    int descendant = checked(openat(source, "descendant", O_RDONLY | O_DIRECTORY), "open descendant");
    write_file(descendant, "data", 'D');
    result("cycle", renameat(root, "source", descendant, "loop"));
    result("replace nonempty", renameat(root, "target", root, "source"));
    result("directory to self", renameat(root, "source", root, "source"));
    result("exclusive to existing target", rename_with_flags(root, "source", root, "target", NATIVE_RENAME_EXCLUSIVE));
    result("exclusive to self", rename_with_flags(root, "source", root, "source", NATIVE_RENAME_EXCLUSIVE));
    checked(fchdir(descendant), "chdir descendant");
    checked(renameat(root, "source", root, "target"), "replace empty target");
    char path[4096];
    char *cwd = getcwd(path, sizeof(path));
    size_t length = cwd ? strlen(cwd) : 0;
    static const char ending[] = "/target/descendant";
    printf("cwd tracks ancestor move=%d\n", length >= sizeof(ending) - 1 &&
           strcmp(cwd + length - (sizeof(ending) - 1), ending) == 0);

    struct stat old, replacement, fresh, by_parent;
    checked(fstat(target, &old), "stat replaced target");
    checked(fstat(source, &replacement), "stat retained source");
    checked(fstatat(root, "target", &fresh, 0), "stat replacement name");
    checked(fstatat(descendant, "..", &by_parent, 0), "stat moved parent from descriptor");
    printf("retained fd and new name refer to source=%d\n",
           old.st_ino != fresh.st_ino && replacement.st_ino == fresh.st_ino &&
           by_parent.st_ino == fresh.st_ino);
    result("old source name", fstatat(root, "source", &old, 0));
    result("old target cannot create", mkdirat(target, "detached", 0700));
    int data = checked(open("data", O_RDONLY), "open relative file after move");
    write_file(descendant, "replaced", 'R');
    int replaced = checked(openat(descendant, "replaced", O_RDONLY), "open replaced file");
    checked(renameat(descendant, "data", descendant, "replaced"), "replace file");
    int named = checked(open("replaced", O_RDONLY), "open replacement by name");
    printf("file after replace old descriptor=%c direct source=%c by name=%c\n",
           first_byte(replaced), first_byte(data), first_byte(named));
    result("old file name", fstatat(descendant, "data", &old, 0));
    checked(rename_with_flags(descendant, "replaced", root, "moved-file", NATIVE_RENAME_EXCLUSIVE), "cross-directory rename");
    int moved = checked(openat(root, "moved-file", O_RDONLY), "open file after cross-directory move");
    printf("cross-directory file contents=%c\n", first_byte(moved));
    checked(close(moved), "close moved file");
    checked(close(named), "close named");
    checked(close(replaced), "close replaced");
    checked(close(data), "close data");
    checked(unlinkat(root, "moved-file", 0), "unlink replacement");
    checked(fchdir(root), "return to root");
    checked(close(descendant), "close descendant");
    checked(close(source), "close source");
    checked(close(target), "close target");
    checked(unlinkat(root, "target/descendant", AT_REMOVEDIR), "remove descendant");
    checked(unlinkat(root, "target", AT_REMOVEDIR), "remove target");
    check_exchange(root);
    checked(close(root), "close root");
    checked(chdir("/"), "chdir /");
    checked(rmdir(argv[1]), "remove control");
    return 0;
}
