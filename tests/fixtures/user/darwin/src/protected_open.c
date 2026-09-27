// The data-protection opens: open_dprotected_np and openat_dprotected_np
// create a file in a protection class (read back with
// F_GETPROTECTIONCLASS), refuse raw and authenticated opens for writing,
// and openat_authenticated_np authenticates an open against a descriptor
// (which a plain file does not satisfy). The raw calls show the kernel's
// own checks, which the library wrappers otherwise make first; as for a
// plain open, the flags are checked before the path is read.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef F_GETPROTECTIONCLASS
#define F_GETPROTECTIONCLASS 63
#endif

int open_dprotected_np(const char *, int, int, int, ...);
int openat_dprotected_np(int, const char *, int, int, int, ...);
int openat_authenticated_np(int, const char *, int, int);
int __open_dprotected_np(const char *, int, int, int, int);
int __openat_dprotected_np(int, const char *, int, int, int, int, int);

// An open's result: a descriptor (its protection class and mode) or the
// error; the descriptor is closed.
static void report(const char *what, int fd) {
    if (fd < 0) {
        printf("%s: -1 errno=%d\n", what, errno);
        return;
    }
    struct stat st;
    fstat(fd, &st);
    int class = fcntl(fd, F_GETPROTECTIONCLASS);
    printf("%s: fd class=%d mode=%o accmode=%d\n", what, class, st.st_mode & 07777, fcntl(fd, F_GETFL) & O_ACCMODE);
    close(fd);
}

int main(void) {
    char dir[] = "/tmp/rax_dprot.XXXXXX";
    if (!mkdtemp(dir)) return 1;
    char a[64], b[64];
    snprintf(a, sizeof a, "%s/a", dir);
    snprintf(b, sizeof b, "%s/b", dir);
    umask(022);

    report("create in class 3", open_dprotected_np(a, O_CREAT | O_EXCL | O_RDWR, 3, 0, 0666));
    report("reopen, class ignored", open_dprotected_np(a, O_RDONLY, 1, 0));
    report("exclusive again", open_dprotected_np(a, O_CREAT | O_EXCL | O_RDWR, 3, 0, 0600));
    report("create in the default class", open_dprotected_np(b, O_CREAT | O_WRONLY, -1, 0, 0640));
    unlink(b);
    report("create in class 99", open_dprotected_np(b, O_CREAT | O_WRONLY, 99, 0, 0600));
    unlink(b);
    report("missing", open_dprotected_np(b, O_RDONLY, 3, 0));
    report("raw, read-only", open_dprotected_np(a, O_RDONLY, 0, O_DP_GETRAWENCRYPTED));
    report("raw, for writing", open_dprotected_np(a, O_RDWR, 0, O_DP_GETRAWENCRYPTED));
    report("authenticate", open_dprotected_np(a, O_RDONLY, 0, O_DP_AUTHENTICATE));
    report("raw call, authenticate", __open_dprotected_np(a, O_RDONLY, 0, O_DP_AUTHENTICATE, 0));
    report("raw call, both access modes", __open_dprotected_np(a, O_ACCMODE, 0, 0, 0));
    report("raw call, NULL path", __open_dprotected_np(NULL, O_RDONLY, 0, 0, 0));
    report("raw call, NULL path and authenticate", __open_dprotected_np(NULL, O_RDONLY, 0, O_DP_AUTHENTICATE, 0));

    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    report("at a directory", openat_dprotected_np(dfd, "a", O_RDONLY, 0, 0));
    report("at a directory, create", openat_dprotected_np(dfd, "c", O_CREAT | O_RDWR, 2, 0, 0600));
    report("at a file", openat_dprotected_np(open(a, O_RDONLY), "a", O_RDONLY, 0, 0));
    report("at a bad descriptor", openat_dprotected_np(99, "a", O_RDONLY, 0, 0));

    int authfd = open(a, O_RDONLY);
    report("authenticated by the file", openat_authenticated_np(dfd, "a", O_RDONLY, authfd));
    report("authenticated by nothing", openat_authenticated_np(dfd, "a", O_RDONLY, -1));
    report("authenticated by a bad descriptor", openat_authenticated_np(dfd, "a", O_RDONLY, 99));
    int p[2];
    pipe(p);
    report("authenticated by a pipe", openat_authenticated_np(dfd, "a", O_RDONLY, p[0]));
    report("authenticated for writing", openat_authenticated_np(dfd, "a", O_RDWR, authfd));
    report("authenticated, create", openat_authenticated_np(dfd, "a", O_RDONLY | O_CREAT, authfd));
    report("raw call, authenticated create",
           __openat_dprotected_np(dfd, "a", O_RDONLY | O_CREAT, 0, O_DP_AUTHENTICATE, 0, authfd));
    report("raw call, authenticated by a bad descriptor, NULL path",
           __openat_dprotected_np(dfd, NULL, O_RDONLY, 0, O_DP_AUTHENTICATE, 0, 99));
    report("raw call, authenticated by a pipe, NULL path",
           __openat_dprotected_np(dfd, NULL, O_RDONLY, 0, O_DP_AUTHENTICATE, 0, p[0]));

    // Plain opens: the flags before the path, the path before the directory.
    report("open(NULL, O_ACCMODE)", open(NULL, O_ACCMODE));
    report("open(NULL)", open(NULL, O_RDONLY));
    report("openat(bad, NULL)", openat(99, NULL, O_RDONLY));
    report("openat(bad, \"x\", O_ACCMODE)", openat(99, "x", O_ACCMODE));
    report("openat(bad, \"x\", O_EXEC | O_RDWR)", openat(99, "x", O_EXEC | O_RDWR));
    report("openat(bad, \"x\")", openat(99, "x", O_RDONLY));

    unlink(a);
    char c[64];
    snprintf(c, sizeof c, "%s/c", dir);
    unlink(c);
    rmdir(dir);
    return 0;
}
