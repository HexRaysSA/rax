/* File locks (fs/locks.c). flock locks belong to the open file description:
 * shared by dup and fork, conflicting between descriptions, released with
 * the description's last descriptor, and a conversion that would wait loses
 * the old lock. POSIX record locks belong to the process: split by partial
 * unlocks, reported to other processes by F_GETLK with the owner's PID and
 * the lock's range, shared for reading, not inherited, released by closing
 * any descriptor of the file but not by munmap. A waiting lock call sleeps
 * until the lock is released, or a signal interrupts it (EINTR without
 * SA_RESTART). Other processes are forked children. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

static char path[64];

static int setlk(int fd, int cmd, int type, off_t start, off_t len) {
    struct flock fl = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    return fcntl(fd, cmd, &fl);
}

/* What another process finds with F_GETLK for a `type` lock on start..len. */
static struct flock probe(int type, off_t start, off_t len) {
    int p[2];
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    pipe(p);
    pid_t c = fork();
    if (c == 0) {
        int fd = open(path, O_RDWR);
        fl.l_type = type;
        fl.l_whence = SEEK_SET;
        fl.l_start = start;
        fl.l_len = len;
        if (fcntl(fd, F_GETLK, &fl) != 0)
            fl.l_type = -1;
        write(p[1], &fl, sizeof fl);
        _exit(0);
    }
    close(p[1]);
    read(p[0], &fl, sizeof fl);
    close(p[0]);
    waitpid(c, 0, 0);
    return fl;
}

/* Whether another process could lock all of start..len for writing. */
static int free_for_others(off_t start, off_t len) {
    return probe(F_WRLCK, start, len).l_type == F_UNLCK;
}

/* Runs `fn` in a child; its exit status. */
static int in_child(int (*fn)(int), int arg) {
    pid_t c = fork();
    if (c == 0)
        _exit(fn(arg));
    int st = -1;
    waitpid(c, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 100;
}

static int child_unlocks(int fd) {
    return flock(fd, LOCK_UN) == 0 ? 0 : 1;
}

static int child_conflicts(int fd) {
    int r = setlk(fd, F_SETLK, F_WRLCK, 0, 1);
    return r == -1 && errno == EAGAIN ? 0 : 1;
}

static void flocks(void) {
    int a = open(path, O_RDONLY), b = open(path, O_RDONLY);
    CHECK("flock", flock(a, LOCK_EX) == 0);
    CHECK_ERR("flock-other-description", flock(b, LOCK_SH | LOCK_NB), EWOULDBLOCK);
    int d = dup(a);
    CHECK("flock-duplicate", flock(d, LOCK_EX | LOCK_NB) == 0);
    /* A forked child shares the description: its unlock is the parent's. */
    CHECK("flock-shared-with-child", in_child(child_unlocks, a) == 0);
    CHECK("flock-unlocked-by-child", flock(b, LOCK_EX | LOCK_NB) == 0);
    /* A description's lock goes with its last descriptor. */
    CHECK_ERR("flock-held", flock(a, LOCK_SH | LOCK_NB), EWOULDBLOCK);
    close(b);
    CHECK("flock-released-by-close", flock(a, LOCK_SH | LOCK_NB) == 0);
    /* A conversion that would wait fails and loses the old lock. */
    b = open(path, O_RDONLY);
    CHECK("flock-shared-twice", flock(b, LOCK_SH | LOCK_NB) == 0);
    CHECK_ERR("flock-upgrade-conflict", flock(a, LOCK_EX | LOCK_NB), EWOULDBLOCK);
    CHECK("flock-upgrade-lost-lock", flock(b, LOCK_EX | LOCK_NB) == 0);
    close(a);
    close(b);
    close(d);
}

static void records(void) {
    int fd = open(path, O_RDWR);
    CHECK("setlk", setlk(fd, F_SETLK, F_WRLCK, 0, 100) == 0);
    struct flock fl = probe(F_RDLCK, 50, 1);
    CHECK("getlk-reports-owner", fl.l_type == F_WRLCK && fl.l_whence == SEEK_SET &&
                                     fl.l_start == 0 && fl.l_len == 100 && fl.l_pid == getpid());
    /* A partial unlock splits the lock. */
    CHECK("unlock-middle", setlk(fd, F_SETLK, F_UNLCK, 40, 20) == 0);
    CHECK("split-hole", probe(F_WRLCK, 45, 1).l_type == F_UNLCK);
    fl = probe(F_WRLCK, 30, 1);
    CHECK("split-low", fl.l_type == F_WRLCK && fl.l_start == 0 && fl.l_len == 40);
    fl = probe(F_WRLCK, 70, 1);
    CHECK("split-high", fl.l_type == F_WRLCK && fl.l_start == 60 && fl.l_len == 40);
    /* To the end of the file; read locks are shared. */
    CHECK("setlk-to-end", setlk(fd, F_SETLK, F_RDLCK, 200, 0) == 0);
    CHECK("read-locks-shared", probe(F_RDLCK, 500, 1).l_type == F_UNLCK);
    fl = probe(F_WRLCK, 1000000, 1);
    CHECK("lock-to-end", fl.l_type == F_RDLCK && fl.l_start == 200 && fl.l_len == 0);
    /* A child inherits no POSIX lock, and conflicts with its parent's. */
    CHECK("child-conflicts", in_child(child_conflicts, fd) == 0);
    close(fd);
    CHECK("last-close-releases", free_for_others(0, 0));
}

static void releases(void) {
    int fd = open(path, O_RDWR);
    setlk(fd, F_SETLK, F_WRLCK, 0, 0);
    close(dup(fd));
    CHECK("close-duplicate-releases", free_for_others(0, 0));
    setlk(fd, F_SETLK, F_WRLCK, 0, 0);
    close(open(path, O_RDONLY));
    CHECK("close-other-description-releases", free_for_others(0, 0));
    setlk(fd, F_SETLK, F_WRLCK, 0, 0);
    void *m = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
    munmap(m, 4096);
    m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    munmap(m, 4096);
    CHECK("munmap-keeps-locks", !free_for_others(0, 0));
    close(fd);
    CHECK("close-after-munmap-releases", free_for_others(0, 0));
}

/* Holds a lock of `kind` (0 flock, 1 POSIX) until killed, or for `ms`. */
static pid_t holder(int kind, int ms) {
    int p[2];
    pipe(p);
    pid_t c = fork();
    if (c == 0) {
        int fd = open(path, O_RDWR);
        if (kind == 0)
            flock(fd, LOCK_EX);
        else
            setlk(fd, F_SETLK, F_WRLCK, 0, 0);
        write(p[1], "r", 1);
        if (ms)
            usleep(ms * 1000);
        else
            pause();
        _exit(0);
    }
    char b;
    close(p[1]);
    read(p[0], &b, 1);
    close(p[0]);
    return c;
}

static void on_alarm(int sig) {
    (void)sig;
}

static void waits(void) {
    int fd = open(path, O_RDWR);
    pid_t c = holder(1, 50);
    CHECK_ERR("setlk-busy", setlk(fd, F_SETLK, F_RDLCK, 0, 1), EAGAIN);
    CHECK("setlkw-waits", setlk(fd, F_SETLKW, F_RDLCK, 0, 1) == 0);
    waitpid(c, 0, 0);
    setlk(fd, F_SETLK, F_UNLCK, 0, 0);
    c = holder(0, 50);
    CHECK_ERR("flock-busy", flock(fd, LOCK_SH | LOCK_NB), EWOULDBLOCK);
    CHECK("flock-waits", flock(fd, LOCK_SH) == 0);
    waitpid(c, 0, 0);
    flock(fd, LOCK_UN);
    /* A signal ends a wait: EINTR, as the handler has no SA_RESTART. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval t = {.it_value = {.tv_usec = 30000}};
    c = holder(1, 0);
    setitimer(ITIMER_REAL, &t, 0);
    CHECK_ERR("setlkw-interrupted", setlk(fd, F_SETLKW, F_WRLCK, 0, 1), EINTR);
    kill(c, SIGKILL);
    waitpid(c, 0, 0);
    c = holder(0, 0);
    setitimer(ITIMER_REAL, &t, 0);
    CHECK_ERR("flock-interrupted", flock(fd, LOCK_EX), EINTR);
    kill(c, SIGKILL);
    waitpid(c, 0, 0);
    close(fd);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    snprintf(path, sizeof path, "/tmp/rax-locks-%d", getpid());
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "0123456789abcdef", 16);
    close(fd);
    flocks();
    records();
    releases();
    waits();
    unlink(path);
    FINISH();
}
