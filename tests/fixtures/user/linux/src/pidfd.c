/* pidfds: pidfd_open's checks and the file it makes (flags, mode, owner,
 * name, inode, file system); the operations a pidfd refuses; the
 * PIDFD_GET_INFO and FS_IOC_GETVERSION ioctls; a thread's pidfd from start
 * to its exit (a sleeping poll woken by it); a child's through exit,
 * zombie, and reaping, with waitid(P_PIDFD) blocking and non-blocking;
 * pidfd_send_signal's checks, scopes, siginfo, and the PIDFD_SELF_* and
 * /proc/<pid> forms; pidfd_getfd; CLONE_PIDFD from clone3 and clone; an
 * epoll on a pidfd; and a pidfd a forked child inherits. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

/* linux/pidfd.h and linux/fcntl.h (Linux 6.19), which conflict with the C
 * library's fcntl.h. */
#define PIDFD_NONBLOCK O_NONBLOCK
#define PIDFD_THREAD O_EXCL
#define PIDFD_SIGNAL_THREAD 1u
#define PIDFD_SIGNAL_THREAD_GROUP 2u
#define PIDFD_SIGNAL_PROCESS_GROUP 4u
#define PIDFD_SELF_THREAD -10000
#define PIDFD_SELF_THREAD_GROUP -10001
#define PIDFD_INFO_PID (1ull << 0)
#define PIDFD_INFO_CREDS (1ull << 1)
#define PIDFD_INFO_CGROUPID (1ull << 2)
#define PIDFD_INFO_EXIT (1ull << 3)
#define PIDFD_INFO_COREDUMP (1ull << 4)
#define PIDFD_INFO_SUPPORTED_MASK (1ull << 5)
#define PIDFD_COREDUMP_USER (1u << 2)
struct pidfd_info {
    uint64_t mask, cgroupid;
    uint32_t pid, tgid, ppid, ruid, rgid, euid, egid, suid, sgid, fsuid, fsgid;
    int32_t exit_code;
    uint32_t coredump_mask, coredump_signal;
    uint64_t supported_mask;
};
#define PIDFD_GET_INFO _IOWR(0xFF, 11, struct pidfd_info)
#define FS_IOC_GETVERSION_ _IOR('v', 1, long)
#define PID_FS_MAGIC 0x50494446
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif

struct clone_args_ {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid,
        set_tid_size, cgroup;
};

static int popen_(pid_t pid, unsigned flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}
static int psend(int fd, int sig, siginfo_t *info, unsigned flags) {
    return syscall(SYS_pidfd_send_signal, fd, sig, info, flags);
}
static int pgetfd(int fd, int target, unsigned flags) {
    return syscall(SYS_pidfd_getfd, fd, target, flags);
}
/* The events a pidfd reports now (or after `ms`), of IN, RDNORM, HUP. */
static int revents(int fd, int ms) {
    struct pollfd p = {fd, POLLIN | POLLRDNORM, 0};
    return poll(&p, 1, ms) < 0 ? -1 : p.revents;
}
static int get_info(int fd, uint64_t mask, struct pidfd_info *info) {
    memset(info, 0, sizeof *info);
    info->mask = mask;
    return ioctl(fd, PIDFD_GET_INFO, info);
}

static void opening(void) {
    CHECK_ERR("open-flag", popen_(getpid(), 1), EINVAL);
    CHECK_ERR("open-cloexec-flag", popen_(getpid(), O_CLOEXEC), EINVAL);
    CHECK_ERR("open-zero", popen_(0, 0), EINVAL);
    CHECK_ERR("open-negative", popen_(-1, 0), EINVAL);
    CHECK_ERR("open-missing", popen_(4000000, 0), ESRCH);
    int fd = popen_(getpid(), 0);
    struct stat st, st2;
    CHECK("file", fd >= 0 && fcntl(fd, F_GETFL) == O_RDWR && (fcntl(fd, F_GETFD) & FD_CLOEXEC) &&
                      fstat(fd, &st) == 0 && st.st_mode == 0700 && st.st_uid == 0 &&
                      st.st_gid == 0 && st.st_nlink == 1 && st.st_size == 0 &&
                      st.st_blksize == 4096 && major(st.st_dev) == 0);
    char link[64] = {0}, path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    readlink(path, link, sizeof link - 1);
    CHECK("name", !strcmp(link, "anon_inode:[pidfd]"));
    int nb = popen_(getpid(), PIDFD_NONBLOCK | PIDFD_THREAD);
    CHECK("flags", fcntl(nb, F_GETFL) == (O_RDWR | O_NONBLOCK | O_EXCL));
    CHECK("same-inode", fstat(nb, &st2) == 0 && st.st_ino == st2.st_ino && st.st_dev == st2.st_dev);
    /* F_SETFL changes O_NONBLOCK, never O_EXCL. */
    CHECK("setfl", fcntl(nb, F_SETFL, 0) == 0 && fcntl(nb, F_GETFL) == (O_RDWR | O_EXCL));
    struct statfs sf;
    CHECK("statfs", fstatfs(fd, &sf) == 0 && sf.f_type == PID_FS_MAGIC);
    CHECK("alive", revents(fd, 0) == 0);
    close(nb);
    close(fd);
}

static void refusals(void) {
    int fd = popen_(getpid(), 0);
    char b[8];
    CHECK_ERR("read", read(fd, b, 8), EINVAL);
    CHECK_ERR("read-empty", read(fd, b, 0), EINVAL);
    CHECK_ERR("write", write(fd, b, 8), EINVAL);
    CHECK_ERR("pread", pread(fd, b, 8, 0), EINVAL);
    CHECK_ERR("pwrite", pwrite(fd, b, 8, 0), EINVAL);
    CHECK_ERR("lseek", lseek(fd, 0, SEEK_SET), ESPIPE);
    CHECK_ERR("fchmod", fchmod(fd, 0600), EOPNOTSUPP);
    CHECK_ERR("fchown", fchown(fd, -1, -1), EOPNOTSUPP);
    CHECK_ERR("ftruncate", ftruncate(fd, 0), EOPNOTSUPP);
    CHECK_ERR("fallocate", fallocate(fd, 0, 0, 1), EOPNOTSUPP);
    CHECK_ERR("fsync", fsync(fd), EINVAL);
    CHECK_ERR("mmap", (long)mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0), ENODEV);
    int n;
    CHECK_ERR("fionread", ioctl(fd, FIONREAD, &n), ENOTTY);
    CHECK_ERR("unknown-ioctl", ioctl(fd, _IO(0xFF, 12), 0), ENOTTY);
    /* An eventfd refuses attribute changes the same way. */
    int ev = eventfd(0, 0);
    CHECK_ERR("eventfd-fchmod", fchmod(ev, 0600), EOPNOTSUPP);
    close(ev);
    close(fd);
}

static void ioctls(void) {
    int fd = popen_(getpid(), 0);
    unsigned version = 99;
    CHECK("getversion", ioctl(fd, FS_IOC_GETVERSION_, &version) == 0 && version == 0);
    CHECK_ERR("getversion-null", ioctl(fd, FS_IOC_GETVERSION_, 0), EINVAL);
    struct pidfd_info info;
    CHECK("info", get_info(fd, PIDFD_INFO_PID | PIDFD_INFO_SUPPORTED_MASK, &info) == 0 &&
                      (info.mask & ~PIDFD_INFO_CGROUPID) ==
                          (PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_SUPPORTED_MASK) &&
                      info.pid == (uint32_t)getpid() && info.tgid == (uint32_t)getpid() &&
                      info.ppid == (uint32_t)getppid() && info.ruid == getuid() &&
                      info.euid == geteuid() && info.suid == geteuid() &&
                      info.fsuid == geteuid() && info.rgid == getgid() &&
                      info.egid == getegid() && info.supported_mask == 0x7f);
    CHECK("info-no-exit", get_info(fd, PIDFD_INFO_EXIT, &info) == 0 &&
                              !(info.mask & PIDFD_INFO_EXIT) && info.exit_code == 0);
    CHECK("info-coredump", get_info(fd, PIDFD_INFO_COREDUMP, &info) == 0 &&
                               (info.mask & PIDFD_INFO_COREDUMP) &&
                               info.coredump_mask == PIDFD_COREDUMP_USER &&
                               info.coredump_signal == 0);
    unsigned char big[128];
    memset(big, 0xaa, sizeof big);
    *(uint64_t *)big = PIDFD_INFO_PID;
    CHECK("info-short", ioctl(fd, _IOWR(0xFF, 11, char[64]), big) == 0 && big[64] == 0xaa &&
                            *(uint32_t *)(big + 16) == (uint32_t)getpid());
    memset(big, 0xaa, sizeof big);
    *(uint64_t *)big = PIDFD_INFO_PID;
    CHECK("info-long", ioctl(fd, _IOWR(0xFF, 11, char[100]), big) == 0 && big[80] == 0 &&
                           big[99] == 0 && big[100] == 0xaa);
    CHECK_ERR("info-too-short", ioctl(fd, _IOWR(0xFF, 11, char[56]), big), ENOTTY);
    CHECK_ERR("info-direction", ioctl(fd, _IOR(0xFF, 11, struct pidfd_info), big), ENOTTY);
    CHECK_ERR("info-null", ioctl(fd, PIDFD_GET_INFO, 0), EINVAL);
    CHECK_ERR("info-fault", ioctl(fd, PIDFD_GET_INFO, 8), EFAULT);
    int plain = open("/dev/null", O_RDONLY);
    CHECK_ERR("info-not-pidfd", ioctl(plain, PIDFD_GET_INFO, &info), ENOTTY);
    close(plain);
    close(fd);
}

static volatile int thread_tid;
static int thread_go[2];

static void *thread_main(void *arg) {
    (void)arg;
    thread_tid = gettid();
    char c;
    read(thread_go[0], &c, 1);
    usleep(50000);
    return 0;
}

static void threads(void) {
    pipe(thread_go);
    pthread_t t;
    pthread_create(&t, 0, thread_main, 0);
    while (!thread_tid)
        usleep(1000);
    CHECK_ERR("thread-needs-flag", popen_(thread_tid, 0), ENOENT);
    int fd = popen_(thread_tid, PIDFD_THREAD);
    CHECK("thread", fd >= 0 && fcntl(fd, F_GETFL) == (O_RDWR | O_EXCL) && revents(fd, 0) == 0 &&
                        psend(fd, 0, 0, 0) == 0);
    CHECK_ERR("thread-not-child", waitid(P_PIDFD, fd, 0, WEXITED | WNOHANG), ECHILD);
    /* The task is found by its own ID; the scope only directs delivery. */
    CHECK("thread-group-scope", psend(fd, 0, 0, PIDFD_SIGNAL_THREAD_GROUP) == 0);
    struct pidfd_info info;
    CHECK("thread-info", get_info(fd, 0, &info) == 0 && info.pid == (uint32_t)thread_tid &&
                             info.tgid == (uint32_t)getpid());
    /* A sleeping poll wakes when the thread exits. */
    write(thread_go[1], "x", 1);
    CHECK("thread-exit", revents(fd, 5000) == (POLLIN | POLLRDNORM | POLLHUP));
    pthread_join(t, 0);
    CHECK_ERR("thread-gone-signal", psend(fd, 0, 0, 0), ESRCH);
    CHECK_ERR("thread-gone-info", get_info(fd, PIDFD_INFO_PID, &info), ESRCH);
    CHECK("thread-exit-info", get_info(fd, PIDFD_INFO_EXIT, &info) == 0 &&
                                  (info.mask & PIDFD_INFO_EXIT) && info.exit_code == 0);
    CHECK_ERR("thread-gone-getfd", pgetfd(fd, 1, 0), ESRCH);
    close(fd);
}

/* A child that exits with `code` once a byte arrives on `go`. */
static pid_t waiting_child(int go[2], int code) {
    pipe(go);
    pid_t pid = fork();
    if (pid == 0) {
        char c;
        read(go[0], &c, 1);
        _exit(code);
    }
    return pid;
}

static void children(void) {
    int go[2];
    pid_t pid = waiting_child(go, 7);
    int fd = popen_(pid, PIDFD_NONBLOCK);
    CHECK("child", fd >= 0 && revents(fd, 0) == 0);
    siginfo_t si;
    memset(&si, 0x55, sizeof si);
    CHECK_ERR("child-nonblock-wait", waitid(P_PIDFD, fd, &si, WEXITED), EAGAIN);
    CHECK("child-nonblock-zeroed", si.si_signo == 0 && si.si_pid == 0);
    CHECK("child-nohang", waitid(P_PIDFD, fd, &si, WEXITED | WNOHANG) == 0 && si.si_pid == 0);
    /* A sleeping poll wakes when the child exits; it is then a zombie. */
    write(go[1], "x", 1);
    CHECK("child-exit", revents(fd, 5000) == (POLLIN | POLLRDNORM));
    CHECK("zombie-signal", psend(fd, SIGKILL, 0, 0) == 0);
    CHECK_ERR("zombie-getfd", pgetfd(fd, 1, 0), ESRCH);
    struct pidfd_info info;
    CHECK("zombie-info", get_info(fd, PIDFD_INFO_EXIT, &info) == 0 &&
                             info.pid == (uint32_t)pid && info.ppid == (uint32_t)getpid() &&
                             !(info.mask & PIDFD_INFO_EXIT));
    memset(&si, 0, sizeof si);
    CHECK("zombie-wait", waitid(P_PIDFD, fd, &si, WEXITED | WNOWAIT) == 0 &&
                             si.si_signo == SIGCHLD && si.si_code == CLD_EXITED &&
                             si.si_pid == pid && si.si_status == 7);
    CHECK("reap", waitid(P_PIDFD, fd, &si, WEXITED) == 0 && si.si_pid == pid);
    CHECK("reaped", revents(fd, 0) == (POLLIN | POLLRDNORM | POLLHUP));
    CHECK_ERR("reaped-signal", psend(fd, 0, 0, 0), ESRCH);
    CHECK_ERR("reaped-open", popen_(pid, 0), ESRCH);
    CHECK_ERR("reaped-info", get_info(fd, PIDFD_INFO_PID, &info), ESRCH);
    CHECK("reaped-exit-info", get_info(fd, PIDFD_INFO_EXIT, &info) == 0 &&
                                  (info.mask & ~PIDFD_INFO_CGROUPID) == PIDFD_INFO_EXIT &&
                                  info.exit_code == 0x700);
    CHECK_ERR("reaped-wait", waitid(P_PIDFD, fd, &si, WEXITED), ECHILD);
    close(fd);
    close(go[0]);
    close(go[1]);
    /* A blocking waitid through a pidfd sleeps until the child exits. */
    pid = waiting_child(go, 3);
    fd = popen_(pid, 0);
    write(go[1], "x", 1);
    memset(&si, 0, sizeof si);
    CHECK("wait-blocks", waitid(P_PIDFD, fd, &si, WEXITED) == 0 && si.si_pid == pid &&
                             si.si_status == 3);
    close(fd);
    close(go[0]);
    close(go[1]);
}

static void signals(void) {
    int go[2];
    pid_t pid = waiting_child(go, 0);
    int fd = popen_(pid, 0);
    CHECK_ERR("send-flags", psend(fd, 0, 0, 8), EINVAL);
    CHECK_ERR("send-two-scopes", psend(fd, 0, 0, 3), EINVAL);
    CHECK("send-thread-scope", psend(fd, 0, 0, PIDFD_SIGNAL_THREAD) == 0);
    CHECK_ERR("send-group-scope", psend(fd, 0, 0, PIDFD_SIGNAL_PROCESS_GROUP), ESRCH);
    CHECK_ERR("send-bad-signal", psend(fd, 65, 0, 0), EINVAL);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR1;
    si.si_code = SI_USER;
    CHECK_ERR("send-forged", psend(fd, SIGUSR1, &si, 0), EPERM);
    si.si_code = SI_QUEUE;
    CHECK_ERR("send-mismatch", psend(fd, SIGUSR2, &si, 0), EINVAL);
    CHECK_ERR("send-not-pidfd", psend(0, 0, 0, 0), EBADF);
    CHECK_ERR("send-closed", psend(99, 0, 0, 0), EBADF);
    CHECK("send-kill", psend(fd, SIGKILL, 0, 0) == 0);
    int st;
    CHECK("send-killed", waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
    close(fd);
    close(go[0]);
    close(go[1]);
    /* The caller: the kinds of record each form sends. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, 0);
    struct timespec now = {0, 0};
    int self = popen_(getpid(), 0);
    CHECK("self-group", psend(self, SIGUSR2, 0, 0) == 0 &&
                            sigtimedwait(&set, &si, &now) == SIGUSR2 && si.si_code == SI_USER &&
                            si.si_pid == getpid() && si.si_uid == getuid());
    CHECK("self-thread", psend(self, SIGUSR2, 0, PIDFD_SIGNAL_THREAD) == 0 &&
                             sigtimedwait(&set, &si, &now) == SIGUSR2 && si.si_code == SI_TKILL);
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR2;
    si.si_code = SI_QUEUE;
    si.si_value.sival_int = 42;
    CHECK("self-record", psend(PIDFD_SELF_THREAD, SIGUSR2, &si, 0) == 0 &&
                             sigtimedwait(&set, &si, &now) == SIGUSR2 && si.si_code == SI_QUEUE &&
                             si.si_value.sival_int == 42);
    si.si_code = SI_USER;
    CHECK("self-forged-allowed", psend(PIDFD_SELF_THREAD, SIGUSR2, &si, 0) == 0 &&
                                     sigtimedwait(&set, &si, &now) == SIGUSR2);
    CHECK("self-process", psend(PIDFD_SELF_THREAD_GROUP, 0, 0, 0) == 0);
    int proc = open("/proc/self", O_RDONLY | O_DIRECTORY);
    CHECK("proc-dir", psend(proc, 0, 0, 0) == 0);
    close(proc);
    sigprocmask(SIG_UNBLOCK, &set, 0);
    /* A signal from the caller reaches the child with the caller's ID. */
    pipe(go);
    int ready[2];
    pipe(ready);
    pid = fork();
    if (pid == 0) {
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, SIGUSR1);
        sigprocmask(SIG_BLOCK, &s, 0);
        write(ready[1], "r", 1);
        siginfo_t got;
        int sig = sigwaitinfo(&s, &got);
        _exit(sig == SIGUSR1 && got.si_code == SI_USER && got.si_pid == getppid() ? 0 : 1);
    }
    char c;
    read(ready[0], &c, 1);
    fd = popen_(pid, 0);
    CHECK("send-child", psend(fd, SIGUSR1, 0, 0) == 0 && waitpid(pid, &st, 0) == pid &&
                            WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(fd);
    close(self);
    close(go[0]);
    close(go[1]);
    close(ready[0]);
    close(ready[1]);
}

static void getfd(void) {
    int self = popen_(getpid(), 0);
    int fd = pgetfd(self, 1, 0);
    CHECK("getfd", fd > 2 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    close(fd);
    CHECK_ERR("getfd-flags", pgetfd(self, 1, 1), EINVAL);
    CHECK_ERR("getfd-closed", pgetfd(self, 99, 0), EBADF);
    CHECK_ERR("getfd-not-pidfd", pgetfd(0, 0, 0), EBADF);
    CHECK_ERR("getfd-self-form", pgetfd(PIDFD_SELF_THREAD, 1, 0), EBADF);
    CHECK_ERR("wait-self-form", waitid(P_PIDFD, PIDFD_SELF_THREAD, 0, WEXITED), EINVAL);
    CHECK_ERR("wait-not-pidfd", waitid(P_PIDFD, 0, 0, WEXITED | WNOHANG), EBADF);
    CHECK_ERR("wait-self", waitid(P_PIDFD, self, 0, WEXITED | WNOHANG), ECHILD);
    close(self);
}

static void clones(void) {
    int pidfd = -1;
    struct clone_args_ ca = {0};
    ca.flags = CLONE_PIDFD;
    ca.pidfd = (uintptr_t)&pidfd;
    ca.exit_signal = SIGCHLD;
    long pid = syscall(SYS_clone3, &ca, sizeof ca);
    if (pid == 0)
        _exit(pidfd == -1 ? 5 : 6);
    siginfo_t si;
    CHECK("clone3", pid > 0 && pidfd > 2 && (fcntl(pidfd, F_GETFD) & FD_CLOEXEC) &&
                        fcntl(pidfd, F_GETFL) == O_RDWR);
    CHECK("clone3-wait", waitid(P_PIDFD, pidfd, &si, WEXITED) == 0 && si.si_pid == pid &&
                             si.si_status == 5);
    close(pidfd);
    ca.pidfd = 16;
    CHECK_ERR("clone3-fault", syscall(SYS_clone3, &ca, sizeof ca), EFAULT);
    CHECK_ERR("clone3-no-child", waitpid(-1, 0, WNOHANG), ECHILD);
    pidfd = -1;
    pid = syscall(SYS_clone, CLONE_PIDFD | SIGCHLD, 0, &pidfd, 0, 0);
    if (pid == 0)
        _exit(4);
    CHECK("clone", pid > 0 && pidfd > 2 && waitid(P_PIDFD, pidfd, &si, WEXITED) == 0 &&
                       si.si_status == 4);
    close(pidfd);
    CHECK_ERR("clone-settid", syscall(SYS_clone, CLONE_PIDFD | CLONE_PARENT_SETTID | SIGCHLD, 0,
                                      &pidfd, 0, 0),
              EINVAL);
    CHECK_ERR("clone-detached", syscall(SYS_clone, CLONE_PIDFD | CLONE_DETACHED | SIGCHLD, 0,
                                        &pidfd, 0, 0),
              EINVAL);
}

static void polling(void) {
    /* An epoll on a child's pidfd sleeps until the child exits. */
    int go[2];
    pid_t pid = waiting_child(go, 0);
    int fd = popen_(pid, 0);
    int ep = epoll_create1(0);
    struct epoll_event e = {EPOLLIN, {.u64 = 7}};
    CHECK("epoll-add", epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e) == 0 && epoll_wait(ep, &e, 1, 0) == 0);
    write(go[1], "x", 1);
    CHECK("epoll-exit", epoll_wait(ep, &e, 1, 5000) == 1 && e.data.u64 == 7 &&
                            (e.events & EPOLLIN));
    waitpid(pid, 0, 0);
    close(ep);
    close(fd);
    close(go[0]);
    close(go[1]);
    /* A forked child polls its inherited pidfd of a sibling. */
    pid_t a = waiting_child(go, 0);
    int afd = popen_(a, 0);
    int ready[2];
    pipe(ready);
    pid_t b = fork();
    if (b == 0) {
        int parent = popen_(getppid(), 0);
        int alive = revents(afd, 0) == 0 && revents(parent, 0) == 0;
        write(ready[1], "r", 1);
        _exit(alive && (revents(afd, 5000) & POLLIN) ? 0 : 1);
    }
    char c;
    read(ready[0], &c, 1);
    write(go[1], "x", 1);
    int st;
    CHECK("inherited", waitpid(b, &st, 0) == b && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    waitpid(a, 0, 0);
    close(afd);
    close(go[0]);
    close(go[1]);
    close(ready[0]);
    close(ready[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    opening();
    refusals();
    ioctls();
    threads();
    children();
    signals();
    getfd();
    clones();
    polling();
    FINISH();
}
