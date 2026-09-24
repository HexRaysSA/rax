/* /proc/self/fdinfo: the fields every descriptor shows (position, status
 * flags with O_CLOEXEC, mount ID, inode number) for a file, a directory,
 * pipes, and a socket; and what pidfds, eventfds, timerfds, signalfds, and
 * epoll instances add. System-specific values (mount IDs, eventfd IDs) are
 * only checked for their form; inode numbers against fstat. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static char info[4096];

/* Reads the fdinfo of `fd` into `info`; its length, or -1. */
static int load(int fd) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    int f = open(path, O_RDONLY);
    if (f < 0)
        return -1;
    int n = read(f, info, sizeof info - 1);
    close(f);
    if (n < 0)
        return -1;
    info[n] = 0;
    return n;
}

/* The value after "key" at the start of a line, or NULL. */
static const char *field(const char *key) {
    size_t k = strlen(key);
    for (const char *p = info; *p;) {
        if (!strncmp(p, key, k))
            return p + k;
        p = strchr(p, '\n');
        if (!p)
            break;
        p++;
    }
    return 0;
}

static long long num(const char *key, int base) {
    const char *v = field(key);
    return v ? strtoll(v, 0, base) : -12345;
}

/* The generic lines: position, flags (F_GETFL plus O_CLOEXEC), a mount ID,
 * and the inode number fstat reports. */
static int generic(int fd, long long pos) {
    struct stat st;
    fstat(fd, &st);
    int flags = fcntl(fd, F_GETFL) | ((fcntl(fd, F_GETFD) & FD_CLOEXEC) ? O_CLOEXEC : 0);
    const char *m;
    return load(fd) > 0 && !strncmp(info, "pos:\t", 5) && num("pos:\t", 10) == pos &&
           field("flags:\t0") && num("flags:\t", 8) == flags && (m = field("mnt_id:\t")) &&
           *m >= '0' && *m <= '9' && (unsigned long long)num("ino:\t", 10) == st.st_ino;
}

static void files(void) {
    int f = open("/proc/self/exe", O_RDONLY);
    lseek(f, 5, SEEK_SET);
    CHECK("file", generic(f, 5));
    int c = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    CHECK("file-cloexec", generic(c, 0) && (num("flags:\t", 8) & O_CLOEXEC));
    int d = open("/", O_RDONLY | O_DIRECTORY);
    CHECK("directory", generic(d, 0));
    int p[2];
    pipe2(p, O_NONBLOCK);
    CHECK("pipe-read", generic(p[0], 0) && (num("flags:\t", 8) & O_NONBLOCK));
    CHECK("pipe-write", generic(p[1], 0) && (num("flags:\t", 8) & O_ACCMODE) == O_WRONLY);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("socket", generic(s, 0));
    /* The directory lists the open descriptors; a closed one has none. */
    DIR *dir = opendir("/proc/self/fdinfo");
    int seen = 0;
    struct dirent *e;
    while (dir && (e = readdir(dir)))
        seen += atoi(e->d_name) == s && e->d_type == DT_REG;
    if (dir)
        closedir(dir);
    CHECK("listed", seen == 1);
    close(s);
    CHECK_ERR("closed", load(s), ENOENT);
    close(f);
    close(c);
    close(d);
    close(p[0]);
    close(p[1]);
}

static void pidfds(void) {
    int self = syscall(SYS_pidfd_open, getpid(), 0);
    char want[32];
    snprintf(want, sizeof want, "%d\n", getpid());
    CHECK("pidfd", generic(self, 0) && field("Pid:\t") && !strncmp(field("Pid:\t"), want, strlen(want)) &&
                       !strncmp(field("NSpid:\t"), want, strlen(want)));
    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    int child = syscall(SYS_pidfd_open, pid, 0);
    CHECK("pidfd-child", load(child) > 0 && num("Pid:\t", 10) == pid);
    waitpid(pid, 0, 0);
    CHECK("pidfd-reaped", load(child) > 0 && num("Pid:\t", 10) == -1 && num("NSpid:\t", 10) == -1);
    close(child);
    close(self);
}

static void events(void) {
    int ev = eventfd(5, EFD_SEMAPHORE | EFD_NONBLOCK);
    const char *count = 0;
    CHECK("eventfd", generic(ev, 0) && (count = field("eventfd-count: ")) &&
                         !strncmp(count, "               5\n", 17) &&
                         num("eventfd-semaphore: ", 10) == 1 && num("eventfd-id: ", 10) >= 0);
    uint64_t v = 0x1234;
    write(ev, &v, 8);
    CHECK("eventfd-count", load(ev) > 0 && num("eventfd-count: ", 16) == 0x1239);
    close(ev);
    int t = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    CHECK("timerfd-idle", generic(t, 0) && num("clockid: ", 10) == CLOCK_MONOTONIC &&
                              num("ticks: ", 10) == 0 && field("settime flags: 00\n") &&
                              field("it_value: (0, 0)\n") && field("it_interval: (0, 0)\n"));
    struct itimerspec its = {{3, 500}, {100, 0}};
    timerfd_settime(t, 0, &its, 0);
    const char *val = 0;
    long long sec = -1;
    CHECK("timerfd-armed", load(t) > 0 && field("settime flags: 00\n") &&
                               (val = field("it_value: (")) && (sec = strtoll(val, 0, 10)) >= 98 &&
                               sec <= 100 && field("it_interval: (3, 500)\n"));
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    its.it_value = now;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    timerfd_settime(t, TFD_TIMER_ABSTIME, &its, 0);
    CHECK("timerfd-fired", load(t) > 0 && num("ticks: ", 10) == 1 &&
                               field("settime flags: 01\n") && field("it_value: (0, 0)\n"));
    close(t);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGKILL);
    int sf = signalfd(-1, &set, 0);
    CHECK("signalfd", generic(sf, 0) && field("sigmask:\t0000000000000a00\n"));
    close(sf);
}

static void epolls(void) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK("epoll-empty", generic(ep, 0) && !field("tfd:"));
    int p[2];
    pipe(p);
    struct epoll_event e = {EPOLLIN | EPOLLET, {.u64 = 0x1234}};
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &e);
    struct stat st;
    fstat(p[0], &st);
    char want[128];
    snprintf(want, sizeof want, "tfd: %8d events: %8x data: %16llx  pos:0 ino:%lx sdev:%x\n", p[0],
             EPOLLIN | EPOLLET | EPOLLERR | EPOLLHUP, 0x1234ULL, (unsigned long)st.st_ino,
             (major(st.st_dev) << 20) | minor(st.st_dev));
    CHECK("epoll-item", load(ep) > 0 && field(want));
    close(p[0]);
    close(p[1]);
    CHECK("epoll-closed", load(ep) > 0 && !field("tfd:"));
    close(ep);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    files();
    pidfds();
    events();
    epolls();
    FINISH();
}
