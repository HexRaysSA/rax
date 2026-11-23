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

static int rename_exclusive(int fromfd, const char *from, int tofd, const char *to) {
#if defined(__APPLE__)
    return renameatx_np(fromfd, from, tofd, to, RENAME_EXCL);
#elif defined(__linux__)
    return (int)syscall(SYS_renameat2, fromfd, from, tofd, to, 1u);
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
    result("exclusive to existing target", rename_exclusive(root, "source", root, "target"));
    result("exclusive to self", rename_exclusive(root, "source", root, "source"));
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
    checked(rename_exclusive(descendant, "replaced", root, "moved-file"), "cross-directory rename");
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
    checked(close(root), "close root");
    checked(chdir("/"), "chdir /");
    checked(rmdir(argv[1]), "remove control");
    return 0;
}
