// Descriptor flags: close-on-exec and close-on-fork as open, fcntl
// (F_GETFD, F_SETFD, F_DUPFD_CLOEXEC, F_DUPFD_CLOFORK), kqueue, pipe2,
// dup3, and proc_pidfdinfo set and report them, and which descriptors a
// forked child, an exec'd image, and a spawned child keep (with which
// flags). pipe2 and dup3 check their flags and descriptors as the kernel
// does.
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_CLOFORK
#define O_CLOFORK 0x08000000
#endif
#ifndef FD_CLOFORK
#define FD_CLOFORK 2
#endif
#ifndef F_DUPFD_CLOFORK
#define F_DUPFD_CLOFORK 115
#endif
#ifndef PROC_FP_CLFORK
#define PROC_FP_CLFORK 8
#endif

extern char **environ;
int pipe2(int[2], int);
int dup3(int, int, int);

// The descriptors the tests keep: plain, close-on-exec, close-on-fork, and
// both, at fixed numbers.
enum { PLAIN = 20, CLOEXEC_FD = 21, CLOFORK_FD = 22, BOTH_FD = 23 };

static void report(const char *who) {
    printf("%s:", who);
    for (int fd = PLAIN; fd <= BOTH_FD; fd++) {
        int f = fcntl(fd, F_GETFD);
        if (f < 0)
            printf(" %d closed", fd);
        else
            printf(" %d fd=%d", fd, f);
    }
    printf("\n");
}

static void show(const char *what, int r) { printf("%s: %d errno=%d\n", what, r, r < 0 ? errno : 0); }

static void flags_of(const char *what, int fd) {
    printf("%s: F_GETFD=%d nonblock=%d", what, fcntl(fd, F_GETFD), (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
    struct vnode_fdinfo vi;
    struct pipe_fdinfo pi;
    int n = proc_pidfdinfo(getpid(), fd, PROC_PIDFDPIPEINFO, &pi, sizeof pi);
    if (n == sizeof pi) {
        printf(" status=%#x", pi.pfi.fi_status & (PROC_FP_CLEXEC | PROC_FP_CLFORK));
    } else if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEINFO, &vi, sizeof vi) == sizeof vi) {
        printf(" status=%#x", vi.pfi.fi_status & (PROC_FP_CLEXEC | PROC_FP_CLFORK));
    }
    printf("\n");
}

static void pipe2_case(const char *what, int flags) {
    int p[2] = {-1, -1};
    int r = pipe2(p, flags);
    if (r) {
        printf("pipe2 %s: -1 errno=%d untouched=%d\n", what, errno, p[0] == -1 && p[1] == -1);
        return;
    }
    printf("pipe2 %s: 0 ordered=%d\n", what, p[1] == p[0] + 1);
    flags_of(" read end", p[0]);
    flags_of(" write end", p[1]);
    close(p[0]);
    close(p[1]);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2) {
        report(argv[1]);
        return 0;
    }

    // Setting and reading the flags.
    int fd = open("/dev/null", O_RDONLY | O_CLOFORK);
    flags_of("open O_CLOFORK", fd);
    close(fd);
    fd = open("/dev/null", O_RDONLY | O_CLOFORK | O_CLOEXEC);
    flags_of("open O_CLOFORK|O_CLOEXEC", fd);
    for (int v = 0; v <= 7; v++) {
        int r = fcntl(fd, F_SETFD, v);
        printf("F_SETFD %d: %d then F_GETFD=%d\n", v, r, fcntl(fd, F_GETFD));
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC | FD_CLOFORK);
    int d = fcntl(fd, F_DUPFD_CLOFORK, 30);
    printf("F_DUPFD_CLOFORK: %s F_GETFD=%d\n", d >= 30 ? ">=30" : "?", fcntl(d, F_GETFD));
    close(d);
    d = fcntl(fd, F_DUPFD_CLOEXEC, 30);
    printf("F_DUPFD_CLOEXEC: %s F_GETFD=%d\n", d >= 30 ? ">=30" : "?", fcntl(d, F_GETFD));
    close(d);
    d = fcntl(fd, F_DUPFD, 30);
    printf("F_DUPFD: F_GETFD=%d\n", fcntl(d, F_GETFD));
    close(d);
    show("F_DUPFD_CLOFORK below 0", fcntl(fd, F_DUPFD_CLOFORK, -1));
    d = dup(fd);
    printf("dup: F_GETFD=%d\n", fcntl(d, F_GETFD));
    close(d);
    close(fd);
    // A kqueue's status flags are set, but the kqueue refuses them.
    int kq = kqueue();
    printf("kqueue: F_GETFD=%d F_GETFL=%d\n", fcntl(kq, F_GETFD), fcntl(kq, F_GETFL));
    int setfl[] = {O_NONBLOCK, 0, O_APPEND | O_NONBLOCK, O_ASYNC};
    for (unsigned i = 0; i < 4; i++) {
        int r = fcntl(kq, F_SETFL, setfl[i]);
        printf(" F_SETFL %#x: %d errno=%d then F_GETFL=%d\n", setfl[i], r, r < 0 ? errno : 0, fcntl(kq, F_GETFL));
    }
    close(kq);

    // pipe2.
    pipe2_case("0", 0);
    pipe2_case("O_CLOEXEC", O_CLOEXEC);
    pipe2_case("O_CLOFORK", O_CLOFORK);
    pipe2_case("O_NONBLOCK", O_NONBLOCK);
    pipe2_case("all", O_CLOEXEC | O_CLOFORK | O_NONBLOCK);
    pipe2_case("O_APPEND", O_APPEND);
    pipe2_case("O_RDWR", O_RDWR);
    pipe2_case("O_CLOEXEC|1", O_CLOEXEC | 1);
    pipe2_case("-1", -1);
    pid_t pid = fork();
    if (pid == 0) {
        pipe2(NULL, 0);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    // The library stores the descriptors through the NULL array. (rax-user
    // reports a death by a core-dumping signal N as exit status 128 + N.)
    int sig = WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status) > 128 ? WEXITSTATUS(status) - 128 : 0;
    printf("pipe2(NULL): killed by signal %d\n", sig);

    // dup3.
    fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int flags3[] = {0, O_CLOEXEC, O_CLOFORK, O_CLOEXEC | O_CLOFORK};
    for (unsigned i = 0; i < 4; i++) {
        int r = dup3(fd, 40, flags3[i]);
        printf("dup3 flags %#x: %d F_GETFD=%d\n", flags3[i], r, fcntl(40, F_GETFD));
    }
    show("dup3 onto itself", dup3(fd, fd, 0));
    show("dup3 onto itself, bad flags", dup3(fd, fd, O_NONBLOCK));
    show("dup3 O_NONBLOCK", dup3(fd, 41, O_NONBLOCK));
    show("dup3 O_RDWR", dup3(fd, 41, O_RDWR));
    show("dup3 -1 flags", dup3(fd, 41, -1));
    show("dup3 bad source", dup3(99, 41, 0));
    show("dup3 bad source, bad flags", dup3(99, 41, O_NONBLOCK));
    show("dup3 bad source onto itself", dup3(99, 99, 0));
    show("dup3 onto -1", dup3(fd, -1, 0));
    show("dup3 onto -1, bad flags", dup3(fd, -1, O_NONBLOCK));
    show("dup3 onto a huge number", dup3(fd, 1 << 20, 0));
    fcntl(41, F_GETFD);
    printf("41 open: %d\n", fcntl(41, F_GETFD) >= 0);
    close(40);
    close(fd);

    // What children and new images keep.
    int base = open("/dev/null", O_RDONLY);
    dup2(base, PLAIN);
    dup3(base, CLOEXEC_FD, O_CLOEXEC);
    dup3(base, CLOFORK_FD, O_CLOFORK);
    dup3(base, BOTH_FD, O_CLOEXEC | O_CLOFORK);
    close(base);
    report("parent");
    pid = fork();
    if (pid == 0) {
        report("forked child");
        _exit(0);
    }
    waitpid(pid, &status, 0);
    char self[4096];
    uint32_t size = sizeof self;
    _NSGetExecutablePath(self, &size);
    char *spawned[] = {self, "spawned child", NULL};
    posix_spawn(&pid, self, NULL, NULL, spawned, environ);
    waitpid(pid, &status, 0);
    char *execd[] = {self, "exec'd image", NULL};
    execve(self, execd, environ);
    return 1;
}
