/* POSIX message queues (ipc/mqueue.c): mq_open's checks in order and the
 * namespace's limits, attributes, and permissions (as nobody when run as
 * root); messages by priority; the queue file (its status line, position,
 * metadata, and flags); sizes, access, non-blocking calls, timeouts, and a
 * message taken although copying it faults; mq_unlink and a queue living on
 * while open; a receiver waiting in another process handed a message; a
 * sender waiting until another process frees a slot; notification across
 * processes (SI_MESGQ with the sender and value), EBUSY, removal by closing,
 * and none while a receiver waits; a signal ending a wait (EINTR) or
 * restarting it (SA_RESTART); mq_getsetattr. Queue names carry the process
 * ID, and nothing that depends on other queues of the user is printed. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <mqueue.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#define BAD ((void *)16)

static char base[64];

/* The raw calls, without libc's name handling. */
static long mq_open_(const char *name, int flags, int mode, struct mq_attr *a) {
    return syscall(SYS_mq_open, name, flags, mode, a);
}
static long send_(int fd, const void *m, size_t len, unsigned prio, const struct timespec *t) {
    return syscall(SYS_mq_timedsend, fd, m, len, prio, t);
}
static long recv_(int fd, void *m, size_t len, unsigned *prio, const struct timespec *t) {
    return syscall(SYS_mq_timedreceive, fd, m, len, prio, t);
}

static const char *qname(const char *suffix) {
    static char buf[4][96];
    static int next;
    char *b = buf[next++ % 4];
    snprintf(b, sizeof buf[0], "%s-%s", base, suffix);
    return b;
}

static void sleep_ms(int ms) {
    struct timespec t = {0, ms * 1000000L};
    nanosleep(&t, NULL);
}

static void on_usr2(int sig) {
    (void)sig;
}

static long attr_open(const char *name, long maxmsg, long msgsize) {
    struct mq_attr a = {0, maxmsg, msgsize, 0};
    return mq_open_(name, O_RDWR | O_CREAT | O_EXCL, 0600, &a);
}

static void limits(void) {
    const char *files[] = {"msg_max", "msgsize_max", "queues_max", "msg_default", "msgsize_default"};
    const char *want[] = {"10\n", "8192\n", "256\n", "10\n", "8192\n"};
    for (int i = 0; i < 5; i++) {
        char path[64], b[16] = {0};
        snprintf(path, sizeof path, "/proc/sys/fs/mqueue/%s", files[i]);
        int f = open(path, O_RDONLY);
        CHECK(files[i], f >= 0 && read(f, b, sizeof b) > 0 && !strcmp(b, want[i]));
        close(f);
    }
}

static void opening(void) {
    struct mq_attr a;
    CHECK_ERR("open-attr-fault", mq_open_(qname("x"), O_RDWR | O_CREAT, 0600, BAD), EFAULT);
    CHECK_ERR("open-attr-fault-first", mq_open_(BAD, O_RDWR, 0, BAD), EFAULT);
    CHECK_ERR("open-name-fault", mq_open_(BAD, O_RDWR, 0, NULL), EFAULT);
    CHECK_ERR("open-empty", mq_open_("", O_RDWR | O_CREAT, 0600, NULL), ENOENT);
    CHECK_ERR("open-slash", mq_open_("a/b", O_RDWR | O_CREAT, 0600, NULL), EACCES);
    CHECK_ERR("open-leading-slash", mq_open_("/lead", O_RDWR | O_CREAT, 0600, NULL), EACCES);
    CHECK_ERR("open-dot", mq_open_(".", O_RDWR | O_CREAT, 0600, NULL), EACCES);
    CHECK_ERR("open-dotdot", mq_open_("..", O_RDWR, 0, NULL), EACCES);
    char longname[300];
    memset(longname, 'n', 256);
    longname[256] = 0;
    CHECK_ERR("open-name-256", mq_open_(longname, O_RDWR | O_CREAT, 0600, NULL), ENAMETOOLONG);
    CHECK_ERR("open-missing", mq_open_(qname("missing"), O_RDWR, 0, NULL), ENOENT);
    CHECK_ERR("open-maxmsg-0", attr_open(qname("a"), 0, 8), EINVAL);
    CHECK_ERR("open-maxmsg-negative", attr_open(qname("a"), -1, 8), EINVAL);
    CHECK_ERR("open-maxmsg-11", attr_open(qname("a"), 11, 8), EINVAL);
    CHECK_ERR("open-msgsize-8193", attr_open(qname("a"), 10, 8193), EINVAL);
    CHECK_ERR("open-msgsize-0", attr_open(qname("a"), 10, 0), EINVAL);
    int q = attr_open(qname("a"), 3, 16);
    CHECK("open-create", q >= 0);
    CHECK("open-cloexec", fcntl(q, F_GETFD) == FD_CLOEXEC);
    CHECK("open-flags", fcntl(q, F_GETFL) == O_RDWR);
    struct stat st;
    CHECK("open-stat", fstat(q, &st) == 0 && st.st_mode == (S_IFREG | 0600) && st.st_size == 80 &&
                           st.st_nlink == 1 && st.st_uid == getuid() && st.st_blksize == 4096);
    CHECK("open-attr", syscall(SYS_mq_getsetattr, q, NULL, &a) == 0 && a.mq_flags == 0 && a.mq_maxmsg == 3 &&
                           a.mq_msgsize == 16 && a.mq_curmsgs == 0);
    CHECK_ERR("open-excl", mq_open_(qname("a"), O_RDWR | O_CREAT | O_EXCL, 0600, NULL), EEXIST);
    CHECK_ERR("open-accmode-3", mq_open_(qname("a"), O_RDWR | O_WRONLY, 0, NULL), EINVAL);
    struct mq_attr bad = {0, 0, 0, 0};
    int again = mq_open_(qname("a"), O_RDONLY | O_CREAT | O_NONBLOCK, 0, &bad);
    CHECK("open-existing-ignores-attr", again >= 0 && fcntl(again, F_GETFL) == (O_RDONLY | O_NONBLOCK));
    close(again);
    int d = mq_open_(qname("default"), O_WRONLY | O_CREAT | O_EXCL, 0600, NULL);
    CHECK("open-default-attr", d >= 0 && syscall(SYS_mq_getsetattr, d, NULL, &a) == 0 && a.mq_maxmsg == 10 &&
                                   a.mq_msgsize == 8192);
    close(d);
    int neither = mq_open_(qname("neither"), O_RDWR | O_WRONLY | O_CREAT | O_EXCL, 0600, NULL);
    CHECK("open-neither", neither >= 0 && fcntl(neither, F_GETFL) == 3);
    CHECK_ERR("neither-send", send_(neither, "x", 1, 0, NULL), EBADF);
    CHECK_ERR("neither-receive", recv_(neither, &a, 8192, NULL, NULL), EBADF);
    close(neither);
    close(q);
}

static void messages(void) {
    int q = attr_open(qname("prio"), 4, 16);
    char b[64];
    unsigned prio = 99;
    CHECK("send-low", send_(q, "low", 3, 1, NULL) == 0);
    CHECK("send-high", send_(q, "high", 4, 9, NULL) == 0);
    CHECK("send-low2", send_(q, "low2", 4, 1, NULL) == 0);
    CHECK("send-high2", send_(q, "high2", 5, 9, NULL) == 0);
    int n = read(q, b, sizeof b);
    CHECK("status-line", n == 60 && !memcmp(b, "QSIZE:16         NOTIFY:0     SIGNO:0     NOTIFY_PID:0     \n", 60));
    CHECK("status-end", read(q, b, sizeof b) == 0);
    CHECK("status-seek", lseek(q, 6, SEEK_SET) == 6 && read(q, b, 2) == 2 && !memcmp(b, "16", 2));
    CHECK("status-seek-end", lseek(q, -5, SEEK_END) == 75);
    CHECK("status-pread", pread(q, b, 5, 0) == 5 && !memcmp(b, "QSIZE", 5));
    CHECK_ERR("write", write(q, "x", 1), EINVAL);
    CHECK("receive-high", recv_(q, b, 16, &prio, NULL) == 4 && prio == 9 && !memcmp(b, "high", 4));
    CHECK("receive-high2", recv_(q, b, 16, &prio, NULL) == 5 && prio == 9 && !memcmp(b, "high2", 5));
    CHECK("receive-low", recv_(q, b, 16, &prio, NULL) == 3 && prio == 1 && !memcmp(b, "low", 3));
    CHECK("receive-low2", recv_(q, b, 16, NULL, NULL) == 4 && !memcmp(b, "low2", 4));
    CHECK_ERR("send-too-big", send_(q, b, 17, 0, NULL), EMSGSIZE);
    CHECK_ERR("send-prio", send_(q, b, 1, 32768, NULL), EINVAL);
    CHECK_ERR("send-fault", send_(q, BAD, 1, 32767, NULL), EFAULT);
    CHECK_ERR("receive-small", recv_(q, b, 15, NULL, NULL), EMSGSIZE);
    CHECK_ERR("send-bad-fd", send_(99, b, 1, 0, NULL), EBADF);
    CHECK_ERR("send-not-queue", send_(1, b, 1, 0, NULL), EBADF);
    int ro = mq_open_(qname("prio"), O_RDONLY | O_NONBLOCK, 0, NULL);
    CHECK_ERR("send-read-only", send_(ro, "x", 1, 0, NULL), EBADF);
    CHECK_ERR("receive-empty", recv_(ro, b, 16, NULL, NULL), EAGAIN);
    int wo = mq_open_(qname("prio"), O_WRONLY | O_NONBLOCK, 0, NULL);
    CHECK_ERR("receive-write-only", recv_(wo, b, 16, NULL, NULL), EBADF);
    CHECK_ERR("read-write-only", read(wo, b, 8), EBADF);
    for (int i = 0; i < 4; i++) send_(wo, "x", 1, 0, NULL);
    CHECK_ERR("send-full", send_(wo, "x", 1, 0, NULL), EAGAIN);
    CHECK_ERR("receive-fault", recv_(q, BAD, 16, NULL, NULL), EFAULT);
    struct mq_attr a;
    CHECK("receive-fault-took-it", syscall(SYS_mq_getsetattr, q, NULL, &a) == 0 && a.mq_curmsgs == 3);
    struct timespec past = {1, 0}, invalid = {1, 1000000000};
    CHECK_ERR("timeout-fault", recv_(99, b, 16, NULL, BAD), EFAULT);
    CHECK_ERR("timeout-invalid", send_(99, b, 1, 0, &invalid), EINVAL);
    send_(q, "x", 1, 0, NULL);
    CHECK_ERR("send-timeout", send_(q, "x", 1, 0, &past), ETIMEDOUT);
    for (int i = 0; i < 4; i++) recv_(q, b, 16, NULL, NULL);
    CHECK_ERR("receive-timeout", recv_(q, b, 16, NULL, &past), ETIMEDOUT);
    struct pollfd p = {q, POLLIN | POLLOUT, 0};
    CHECK("poll-empty", poll(&p, 1, 0) == 1 && p.revents == POLLOUT);
    close(ro);
    close(wo);
    close(q);
}

static void unlinking(void) {
    CHECK_ERR("unlink-missing", syscall(SYS_mq_unlink, qname("gone")), ENOENT);
    CHECK_ERR("unlink-fault", syscall(SYS_mq_unlink, BAD), EFAULT);
    CHECK_ERR("unlink-slash", syscall(SYS_mq_unlink, "/x"), EACCES);
    int q = mq_open_(qname("gone"), O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
    send_(q, "kept", 4, 0, NULL);
    CHECK("unlink", syscall(SYS_mq_unlink, qname("gone")) == 0);
    CHECK_ERR("unlink-again", syscall(SYS_mq_unlink, qname("gone")), ENOENT);
    char b[8192];
    CHECK("unlinked-receive", recv_(q, b, sizeof b, NULL, NULL) == 4 && !memcmp(b, "kept", 4));
    struct stat st;
    CHECK("unlinked-nlink", fstat(q, &st) == 0 && st.st_nlink == 0);
    char path[64], link[256] = {0}, want[128];
    snprintf(path, sizeof path, "/proc/self/fd/%d", q);
    snprintf(want, sizeof want, "/%s (deleted)", qname("gone"));
    CHECK("unlinked-link", readlink(path, link, sizeof link - 1) > 0 && !strcmp(link, want));
    int other = mq_open_(qname("gone"), O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
    send_(other, "new", 3, 0, NULL);
    struct mq_attr a;
    CHECK("another-queue", syscall(SYS_mq_getsetattr, q, NULL, &a) == 0 && a.mq_curmsgs == 0);
    syscall(SYS_mq_unlink, qname("gone"));
    close(other);
    close(q);
}

static void waiting(void) {
    struct mq_attr a;
    char b[16];
    int q = attr_open(qname("wait"), 1, 16);
    /* A receiver in another process is handed the message. */
    pid_t c = fork();
    if (c == 0) {
        char r[16];
        long n = recv_(q, r, sizeof r, NULL, NULL);
        _exit(n == 6 && !memcmp(r, "handed", 6) ? 0 : 1);
    }
    sleep_ms(200);
    CHECK("handed-send", send_(q, "handed", 6, 3, NULL) == 0);
    int status;
    waitpid(c, &status, 0);
    CHECK("handed-received", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("handed-empty", syscall(SYS_mq_getsetattr, q, NULL, &a) == 0 && a.mq_curmsgs == 0);
    /* A sender waits until another process frees the slot. */
    send_(q, "first", 5, 0, NULL);
    c = fork();
    if (c == 0) {
        sleep_ms(100);
        char r[16];
        _exit(recv_(q, r, sizeof r, NULL, NULL) == 5 ? 0 : 1);
    }
    CHECK("full-send-waits", send_(q, "second", 6, 0, NULL) == 0);
    waitpid(c, &status, 0);
    CHECK("full-send-slot", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("full-send-queued", recv_(q, b, 16, NULL, NULL) == 6 && !memcmp(b, "second", 6));
    /* A handled signal ends a wait: EINTR, or the call restarts. */
    struct sigaction sa = {0};
    sa.sa_handler = on_usr2;
    sigaction(SIGUSR2, &sa, NULL);
    pid_t me = getpid();
    c = fork();
    if (c == 0) {
        sleep_ms(100);
        kill(me, SIGUSR2);
        _exit(0);
    }
    CHECK_ERR("wait-interrupted", recv_(q, b, 16, NULL, NULL), EINTR);
    waitpid(c, &status, 0);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);
    c = fork();
    if (c == 0) {
        sleep_ms(100);
        kill(me, SIGUSR2);
        sleep_ms(100);
        send_(q, "later", 5, 0, NULL);
        _exit(0);
    }
    CHECK("wait-restarted", recv_(q, b, 16, NULL, NULL) == 5 && !memcmp(b, "later", 5));
    waitpid(c, &status, 0);
    close(q);
}

static void notifying(void) {
    int q = attr_open(qname("note"), 4, 16);
    char b[16];
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    struct sigevent ev = {0};
    ev.sigev_notify = 3;
    CHECK_ERR("notify-kind", syscall(SYS_mq_notify, 99, &ev), EINVAL);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = 65;
    CHECK_ERR("notify-signal", syscall(SYS_mq_notify, 99, &ev), EINVAL);
    ev.sigev_signo = SIGUSR1;
    ev.sigev_value.sival_ptr = (void *)(uintptr_t)0x1234;
    CHECK_ERR("notify-bad-fd", syscall(SYS_mq_notify, 99, &ev), EBADF);
    CHECK_ERR("notify-fault", syscall(SYS_mq_notify, q, BAD), EFAULT);
    struct sigevent th = {0};
    th.sigev_notify = SIGEV_THREAD;
    th.sigev_value.sival_ptr = BAD;
    CHECK_ERR("notify-thread-cookie", syscall(SYS_mq_notify, q, &th), EFAULT);
    char cookie[32] = {0};
    th.sigev_value.sival_ptr = cookie;
    th.sigev_signo = q;
    CHECK_ERR("notify-thread-not-socket", syscall(SYS_mq_notify, q, &th), ENOTSOCK);
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    th.sigev_signo = s;
    CHECK_ERR("notify-thread-not-netlink", syscall(SYS_mq_notify, q, &th), EINVAL);
    close(s);
    CHECK("notify", syscall(SYS_mq_notify, q, &ev) == 0);
    CHECK_ERR("notify-busy", syscall(SYS_mq_notify, q, &ev), EBUSY);
    char line[64] = {0};
    char want[64];
    snprintf(want, sizeof want, "QSIZE:0          NOTIFY:0     SIGNO:%-5d NOTIFY_PID:%-6d\n", SIGUSR1, getpid());
    CHECK("notify-status", pread(q, line, sizeof line - 1, 0) > 0 && !strcmp(line, want));
    /* Another process's send into the empty queue signals it. */
    pid_t c = fork();
    if (c == 0) {
        int ok = syscall(SYS_mq_notify, q, &ev) == -1 && errno == EBUSY;
        ok = ok && syscall(SYS_mq_notify, q, NULL) == 0;
        ok = ok && send_(q, "one", 3, 0, NULL) == 0;
        _exit(ok ? 0 : 1);
    }
    int status;
    waitpid(c, &status, 0);
    CHECK("notify-child", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    siginfo_t si;
    struct timespec zero = {0, 0};
    int got = sigtimedwait(&set, &si, &zero);
    CHECK("notify-signal-info", got == SIGUSR1 && si.si_code == SI_MESGQ && si.si_pid == c &&
                                    si.si_uid == getuid() && si.si_value.sival_ptr == (void *)(uintptr_t)0x1234);
    /* Once: consumed, and no signal into a queue that is not empty. */
    CHECK("notify-again", syscall(SYS_mq_notify, q, &ev) == 0);
    send_(q, "two", 3, 0, NULL);
    CHECK_ERR("notify-not-empty", sigtimedwait(&set, &si, &zero), EAGAIN);
    /* Closing a descriptor of the queue removes it. */
    int dup = mq_open_(qname("note"), O_RDONLY, 0, NULL);
    close(dup);
    c = fork();
    if (c == 0) {
        int ok = syscall(SYS_mq_notify, q, &ev) == 0;
        _exit(ok ? 0 : 1);
    }
    waitpid(c, &status, 0);
    CHECK("notify-removed-by-close", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* The child's exit removed its registration too. */
    char r[16];
    recv_(q, r, 16, NULL, NULL);
    recv_(q, r, 16, NULL, NULL);
    CHECK("notify-owner-gone", syscall(SYS_mq_notify, q, &ev) == 0);
    /* None while a receiver waits: the message is handed over. */
    c = fork();
    if (c == 0) {
        _exit(recv_(q, r, 16, NULL, NULL) == 4 ? 0 : 1);
    }
    sleep_ms(200);
    send_(q, "wait", 4, 0, NULL);
    waitpid(c, &status, 0);
    CHECK("notify-receiver-waited", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK_ERR("notify-none-sent", sigtimedwait(&set, &si, &zero), EAGAIN);
    CHECK("notify-still-registered", syscall(SYS_mq_notify, q, NULL) == 0);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    (void)b;
    close(q);
}

static void attributes(void) {
    int q = attr_open(qname("attr"), 2, 8);
    struct mq_attr n = {O_NONBLOCK | O_RDWR, 0, 0, 0}, o;
    CHECK_ERR("setattr-flags", syscall(SYS_mq_getsetattr, 99, &n, NULL), EINVAL);
    n.mq_flags = O_NONBLOCK;
    CHECK_ERR("setattr-bad-fd", syscall(SYS_mq_getsetattr, 99, &n, NULL), EBADF);
    CHECK_ERR("setattr-fault", syscall(SYS_mq_getsetattr, q, BAD, NULL), EFAULT);
    memset(&o, 0xff, sizeof o);
    CHECK("setattr", syscall(SYS_mq_getsetattr, q, &n, &o) == 0 && o.mq_flags == 0 && o.mq_maxmsg == 2 &&
                         o.mq_msgsize == 8 && o.__unused[0] == 0 && o.__unused[3] == 0);
    CHECK("setattr-flag-set", fcntl(q, F_GETFL) == (O_RDWR | O_NONBLOCK));
    char b[8];
    CHECK_ERR("setattr-nonblocking", recv_(q, b, 8, NULL, NULL), EAGAIN);
    CHECK_ERR("setattr-copy-fault", syscall(SYS_mq_getsetattr, q, &n, BAD), EFAULT);
    close(q);
}

static void cleanup(void) {
    const char *names[] = {"a", "default", "neither", "prio", "wait", "note", "attr"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) syscall(SYS_mq_unlink, qname(names[i]));
}

int main(void) {
    snprintf(base, sizeof base, "rax-fixture-%d", getpid());
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) {
            printf("FAIL drop-privileges\n");
            exit(1);
        }
        limits();
        opening();
        messages();
        unlinking();
        waiting();
        notifying();
        attributes();
        cleanup();
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(c, &status, 0);
    failures = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    FINISH();
}
