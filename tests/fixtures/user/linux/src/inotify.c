/* inotify (fs/notify/inotify/inotify_user.c, fs/notify/fsnotify.c, and
 * the VFS's fsnotify hooks). The calls and their checks in order; the
 * events each file call reports and their order, printed as the kernel
 * queues them (a directory before the file itself; names only for entry
 * changes; IN_ISDIR; cookies compared, not printed); a file watching
 * itself through removal and renames; merging; one-shot, IN_EXCL_UNLINK,
 * and IN_MASK_ADD watches; closes at the last reference (a duplicate, a
 * mapping, a forked child, an exit without close); what a forked and an
 * executed child do; an executable opened by exec; waiting readers, woken
 * by a child or ended by a signal. Watched files live in a new directory
 * under /tmp. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static char dir[64];
static char path_buf[4][160];
static char *self_path;

/* Path `name` in the test directory (four rotating buffers). */
static const char *at(const char *name) {
    static int n;
    char *p = path_buf[n++ % 4];
    snprintf(p, sizeof path_buf[0], "%s/%s", dir, name);
    return p;
}

static const char *const names[] = {
    "ACCESS", "MODIFY", "ATTRIB", "CLOSE_WRITE", "CLOSE_NOWRITE", "OPEN", "MOVED_FROM",
    "MOVED_TO", "CREATE", "DELETE", "DELETE_SELF", "MOVE_SELF", "0x1000", "UNMOUNT",
    "Q_OVERFLOW", "IGNORED",
};

static void show_mask(uint32_t m) {
    int first = 1;
    for (int i = 0; i < 16; i++)
        if (m & (1u << i)) {
            printf("%s%s", first ? "" : "|", names[i]);
            first = 0;
        }
    if (m & IN_ISDIR)
        printf("%sISDIR", first ? "" : "|");
    if (m & ~(0xffffu | IN_ISDIR))
        printf("|0x%x", m & ~(0xffffu | IN_ISDIR));
}

static uint32_t last_cookie;

/* Prints what `fd` holds (non-blocking), one line an event. Cookies are
 * printed as "cookie" when not zero, "same" when equal to the last one. */
static void drain(int fd, const char *tag) {
    char buf[8192] __attribute__((aligned(8)));
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0)
            break;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *e = (struct inotify_event *)p;
            printf("%s: wd=%d ", tag, e->wd);
            show_mask(e->mask);
            if (e->len)
                printf(" %s", e->name);
            if (e->cookie) {
                printf(e->cookie == last_cookie ? " same" : " cookie");
                last_cookie = e->cookie;
            }
            printf("\n");
            p += sizeof *e + e->len;
        }
    }
    fflush(stdout);
}

static int create(const char *name) {
    return open(at(name), O_CREAT | O_WRONLY, 0644);
}

static void calls_and_checks(void) {
    CHECK_ERR("init-flags", inotify_init1(1), EINVAL);
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    CHECK("init", fd >= 0);
    CHECK("init-cloexec", fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK("init-flags-shown", (fcntl(fd, F_GETFL) & (O_NONBLOCK | O_ACCMODE)) == O_NONBLOCK);
    CHECK_ERR("mask-zero", inotify_add_watch(fd, dir, 0), EINVAL);
    CHECK_ERR("mask-unknown", inotify_add_watch(fd, dir, 0x08000000), EINVAL);
    CHECK_ERR("fd-bad", inotify_add_watch(-1, "/nonexistent", IN_OPEN), EBADF);
    CHECK_ERR("add-and-create", inotify_add_watch(fd, "/nonexistent", IN_OPEN | IN_MASK_ADD | IN_MASK_CREATE),
              EINVAL);
    CHECK_ERR("fd-not-inotify", inotify_add_watch(1, "/nonexistent", IN_OPEN), EINVAL);
    CHECK_ERR("path-fault", inotify_add_watch(fd, (char *)8, IN_OPEN), EFAULT);
    CHECK_ERR("path-missing", inotify_add_watch(fd, at("none"), IN_OPEN), ENOENT);
    close(create("f"));
    CHECK_ERR("only-dir", inotify_add_watch(fd, at("f"), IN_OPEN | IN_ONLYDIR), ENOTDIR);
    CHECK("wd-first", inotify_add_watch(fd, dir, IN_ALL_EVENTS) == 1);
    CHECK("wd-same-inode", inotify_add_watch(fd, dir, IN_ATTRIB) == 1);
    CHECK_ERR("mask-create", inotify_add_watch(fd, dir, IN_ATTRIB | IN_MASK_CREATE), EEXIST);
    CHECK("wd-isdir-only", inotify_add_watch(fd, at("f"), IN_ISDIR) == 2);
    CHECK("rm", inotify_rm_watch(fd, 2) == 0);
    CHECK_ERR("rm-again", inotify_rm_watch(fd, 2), EINVAL);
    CHECK_ERR("rm-not-inotify", inotify_rm_watch(1, 1), EINVAL);
    CHECK("wd-not-reused", inotify_add_watch(fd, at("f"), IN_OPEN) == 3);
    drain(fd, "rm");
    CHECK_ERR("read-empty", read(fd, &(char[64]){0}, 64), EAGAIN);
    close(open(at("f"), O_RDONLY));
    int n = -1;
    CHECK("fionread", ioctl(fd, FIONREAD, &n) == 0 && n == 16);
    CHECK_ERR("read-small", read(fd, &(char[15]){0}, 15), EINVAL);
    struct pollfd p = {fd, POLLIN, 0};
    CHECK("poll", poll(&p, 1, 0) == 1 && p.revents == POLLIN);
    drain(fd, "open");
    CHECK("poll-empty", poll(&p, 1, 0) == 0);
    /* fdinfo: the newest watch first. */
    char info[64], text[1024] = {0};
    snprintf(info, sizeof info, "/proc/self/fdinfo/%d", fd);
    int i = open(info, O_RDONLY);
    read(i, text, sizeof text - 1);
    close(i);
    char *w3 = strstr(text, "inotify wd:3 "), *w1 = strstr(text, "inotify wd:1 ");
    CHECK("fdinfo-order", w3 && w1 && w3 < w1);
    CHECK("fdinfo-masks", w3 && strstr(w3, " mask:20 ignored_mask:0") && w1 &&
                              strstr(w1, " mask:4 ignored_mask:0"));
    /* readv reads each vector in turn. */
    int f = create("v");
    close(f);
    f = create("v");
    char a[40], b[40];
    struct iovec iov[2] = {{a, 16}, {b, 40}};
    inotify_add_watch(fd, at("v"), IN_OPEN | IN_CLOSE);
    close(f);
    f = open(at("v"), O_RDONLY);
    close(f);
    CHECK("readv", readv(fd, iov, 2) == 48);
    drain(fd, "readv");
    /* INOTIFY_IOC_SETNEXTWD (CONFIG_CHECKPOINT_RESTORE). */
    CHECK_ERR("setnextwd-zero", ioctl(fd, 0x40044900, 0), EINVAL);
    CHECK("setnextwd", ioctl(fd, 0x40044900, 9) == 0 && inotify_add_watch(fd, at("f"), IN_OPEN) == 3 &&
                           inotify_add_watch(fd, dir, IN_OPEN) == 1);
    close(create("n"));
    CHECK("setnextwd-used", inotify_add_watch(fd, at("n"), IN_OPEN) == 9);
    unlink(at("n"));
    drain(fd, "setnextwd");
    /* noop_llseek: the position stays 0. */
    CHECK("seek", lseek(fd, 1, SEEK_SET) == 0);
    close(fd);
}

static void file_calls(void) {
    int fd = inotify_init1(IN_NONBLOCK);
    inotify_add_watch(fd, dir, IN_ALL_EVENTS);
    char buf[16] = "abcdef";
    int f = create("g");
    write(f, buf, 3);
    write(f, buf, 3);
    close(f);
    drain(fd, "create");
    f = open(at("g"), O_RDONLY);
    CHECK("read", read(f, buf, 16) == 6);
    CHECK("read-eof", read(f, buf, 16) == 0);
    fchmod(f, 0600);
    struct iovec iov = {buf, 16};
    CHECK("readv-eof", readv(f, &iov, 1) == 0);
    pread(f, buf, 16, 100);
    close(f);
    drain(fd, "read");
    f = open(at("g"), O_WRONLY | O_TRUNC);
    ftruncate(f, 10);
    fallocate(f, 0, 0, 20);
    pwrite(f, buf, 0, 0);
    close(f);
    drain(fd, "truncate");
    mkdir(at("s"), 0755);
    int d = open(at("s"), O_RDONLY | O_DIRECTORY);
    char ents[1024];
    syscall(SYS_getdents64, d, ents, sizeof ents);
    syscall(SYS_getdents64, d, ents, sizeof ents);
    close(d);
    drain(fd, "dir");
    rename(at("g"), at("h"));
    link(at("h"), at("l"));
    chmod(at("h"), 0640);
    CHECK("chown-nothing", chown(at("h"), -1, -1) == 0);
    struct timespec omit_a[2] = {{0, UTIME_OMIT}, {0, 5}}, omit_m[2] = {{0, 5}, {0, UTIME_OMIT}};
    struct timespec both_omit[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    utimensat(AT_FDCWD, at("h"), omit_a, 0);
    utimensat(AT_FDCWD, at("h"), omit_m, 0);
    utimensat(AT_FDCWD, at("h"), both_omit, 0);
    utimensat(AT_FDCWD, at("h"), NULL, 0);
    truncate(at("h"), 3);
    symlink("h", at("sym"));
    mkfifo(at("p"), 0600);
    unlink(at("l"));
    unlink(at("sym"));
    rmdir(at("s"));
    chmod(dir, 0700);
    drain(fd, "names");
    /* A FIFO's reads and writes are not its directory's business. */
    int r = open(at("p"), O_RDONLY | O_NONBLOCK), w = open(at("p"), O_WRONLY);
    write(w, buf, 1);
    read(r, buf, 1);
    close(w);
    close(r);
    unlink(at("p"));
    unlink(at("h"));
    drain(fd, "fifo");
    close(fd);
}

static void self_watch(void) {
    int fd = inotify_init1(IN_NONBLOCK);
    close(create("f2"));
    inotify_add_watch(fd, dir, IN_ALL_EVENTS);
    inotify_add_watch(fd, at("f2"), IN_ALL_EVENTS);
    int f = open(at("f2"), O_RDWR);
    write(f, "x", 1);
    drain(fd, "self-open");
    unlink(at("f2"));
    drain(fd, "self-unlink-open");
    close(f);
    drain(fd, "self-close");
    close(create("g2"));
    close(create("t2"));
    drain(fd, "self-made");
    inotify_add_watch(fd, at("g2"), IN_ALL_EVENTS);
    inotify_add_watch(fd, at("t2"), IN_ALL_EVENTS);
    rename(at("g2"), at("k2"));
    drain(fd, "self-rename");
    rename(at("k2"), at("t2"));
    drain(fd, "self-rename-over");
    unlink(at("t2"));
    drain(fd, "self-unlink");
    close(fd);
}

static void flags(void) {
    int fd = inotify_init1(IN_NONBLOCK);
    close(create("o"));
    inotify_add_watch(fd, at("o"), IN_OPEN | IN_ONESHOT);
    close(open(at("o"), O_RDONLY));
    close(open(at("o"), O_RDONLY));
    drain(fd, "oneshot");
    inotify_add_watch(fd, at("o"), IN_OPEN);
    inotify_add_watch(fd, at("o"), IN_CLOSE_NOWRITE | IN_MASK_ADD);
    close(open(at("o"), O_RDONLY));
    drain(fd, "mask-add");
    close(fd);
    for (int excl = 0; excl < 2; excl++) {
        fd = inotify_init1(IN_NONBLOCK);
        inotify_add_watch(fd, dir, IN_MODIFY | IN_DELETE | IN_CLOSE | (excl ? IN_EXCL_UNLINK : 0));
        int t = create("u");
        unlink(at("u"));
        write(t, "x", 1);
        close(t);
        drain(fd, excl ? "excl-unlink" : "no-excl-unlink");
        close(fd);
    }
    unlink(at("o"));
}

static void closes(void) {
    int fd = inotify_init1(IN_NONBLOCK);
    int f = create("c");
    write(f, "0123456789", 10);
    close(f);
    inotify_add_watch(fd, at("c"), IN_CLOSE | IN_OPEN);
    int a = open(at("c"), O_RDONLY), b = dup(a);
    close(a);
    drain(fd, "dup-first");
    close(b);
    drain(fd, "dup-last");
    a = open(at("c"), O_RDONLY);
    void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, a, 0);
    close(a);
    drain(fd, "mapped-closed");
    munmap(m, 4096);
    drain(fd, "unmapped");
    /* A forked child shares the description: the last holder closes. The
     * child exits only once the parent has closed its copy and looked. */
    a = open(at("c"), O_WRONLY);
    int go[2];
    pipe(go);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        char c;
        read(go[0], &c, 1);
        _exit(0);
    }
    close(a);
    drain(fd, "fork-parent-closed");
    write(go[1], "x", 1);
    waitpid(p, NULL, 0);
    close(go[0]);
    close(go[1]);
    drain(fd, "fork-child-exited");
    /* A child that exits without closing. */
    fflush(stdout);
    p = fork();
    if (p == 0) {
        open(at("c"), O_RDONLY);
        _exit(0);
    }
    waitpid(p, NULL, 0);
    drain(fd, "exit-without-close");
    unlink(at("c"));
    close(fd);
}

static void children(void) {
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    inotify_add_watch(fd, dir, IN_ALL_EVENTS);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        int f = create("child");
        write(f, "x", 1);
        close(f);
        _exit(0);
    }
    waitpid(p, NULL, 0);
    drain(fd, "forked-child");
    fflush(stdout);
    p = fork();
    if (p == 0) {
        char *argv[] = {self_path, "writer", dir, NULL};
        execv(self_path, argv);
        _exit(127);
    }
    int st;
    waitpid(p, &st, 0);
    CHECK("exec-child", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    drain(fd, "exec-child");
    unlink(at("child"));
    unlink(at("written"));
    drain(fd, "children-cleanup");
    close(fd);
}

/* The executed child of `children`. */
static int writer(const char *d) {
    char p[160];
    snprintf(p, sizeof p, "%s/written", d);
    int f = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(f, "y", 1);
    close(f);
    return 0;
}

static void executable(void) {
    /* A copy of this program, watched, then run, in a directory under
     * /tmp: /dev/shm is mounted noexec. */
    char xdir[64] = "/tmp/inotify-exec.XXXXXX", prog[96];
    if (!mkdtemp(xdir)) {
        printf("FAIL mkdtemp: %s\n", strerror(errno));
        return;
    }
    snprintf(prog, sizeof prog, "%s/prog", xdir);
    int src = open(self_path, O_RDONLY), dst = open(prog, O_CREAT | O_WRONLY, 0755);
    char b[65536];
    ssize_t n;
    while ((n = read(src, b, sizeof b)) > 0)
        write(dst, b, n);
    close(src);
    close(dst);
    int fd = inotify_init1(IN_NONBLOCK);
    inotify_add_watch(fd, prog, IN_OPEN | IN_CLOSE);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        char *argv[] = {"prog", "exit", NULL};
        execv(prog, argv);
        _exit(127);
    }
    int st;
    waitpid(p, &st, 0);
    CHECK("exec-ran", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    drain(fd, "exec");
    unlink(prog);
    rmdir(xdir);
    close(fd);
}

static void on_signal(int s) {
    (void)s;
}

static void waiting(void) {
    int fd = inotify_init1(0);
    inotify_add_watch(fd, dir, IN_CREATE);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        usleep(30000);
        close(create("late"));
        _exit(0);
    }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf);
    CHECK("woken-by-child", n > 0 && ((struct inotify_event *)buf)->mask == IN_CREATE &&
                                strcmp(((struct inotify_event *)buf)->name, "late") == 0);
    waitpid(p, NULL, 0);
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
    CHECK_ERR("interrupted", read(fd, buf, sizeof buf), EINTR);
    unlink(at("late"));
    close(fd);
}

int main(int argc, char **argv) {
    self_path = argv[0];
    if (argc > 2 && strcmp(argv[1], "writer") == 0)
        return writer(argv[2]);
    if (argc > 1 && strcmp(argv[1], "exit") == 0)
        return 0;
    /* tmpfs when there is one: an overlayfs file hands a mapping its
     * backing file, so the mapping would not hold it. */
    strcpy(dir, access("/dev/shm", W_OK) == 0 ? "/dev/shm/inotify.XXXXXX" : "/tmp/inotify.XXXXXX");
    if (!mkdtemp(dir)) {
        printf("FAIL mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    char *real = realpath(argv[0], NULL);
    if (real)
        self_path = real;
    calls_and_checks();
    file_calls();
    self_watch();
    flags();
    closes();
    children();
    executable();
    waiting();
    unlink(at("f"));
    unlink(at("v"));
    CHECK("cleanup", rmdir(dir) == 0);
    FINISH();
}
