/* kcmp (kernel/kcmp.c) and the objects tasks share by their clone flags:
 * the checks in order (tasks, then the right to inspect them, then the
 * type), open file descriptions (duplicates, O_PATH, the index as an
 * unsigned int, a total order), what threads share (address space,
 * tables, signal handlers) and what they share only by CLONE_IO or
 * CLONE_SYSVSEM (an I/O context, a semaphore undo list, both absent until
 * made), epoll items by descriptor and offset, a leader that exited while
 * its threads run, and init, which another user may not inspect. The
 * threads are made by a bare clone (rawthread.h). Root drops to nobody
 * first. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/futex.h>
#include "check.h"
#include "rawthread.h"

#define KCMP_FILE 0
#define KCMP_VM 1
#define KCMP_FILES 2
#define KCMP_FS 3
#define KCMP_SIGHAND 4
#define KCMP_IO 5
#define KCMP_SYSVSEM 6
#define KCMP_EPOLL_TFD 7
#define BAD ((void *)16)
#define THREAD (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD)
#define IOPRIO_BE (2 << 13)

static long kcmp(pid_t a, pid_t b, int type, unsigned long i1, unsigned long i2) {
    return syscall(SYS_kcmp, a, b, type, i1, i2);
}

/* Distinct objects: 1 or 2, the other way round with the arguments. */
static int ordered(pid_t a, pid_t b, int type, unsigned long i1, unsigned long i2) {
    long x = kcmp(a, b, type, i1, i2), y = kcmp(b, a, type, i2, i1);
    return (x == 1 && y == 2) || (x == 2 && y == 1);
}

static void order_and_files(void) {
    pid_t me = getpid();
    CHECK_ERR("no-task-first", kcmp(99999, me, 99, 0, 0), ESRCH);
    CHECK_ERR("no-task-second", kcmp(me, 0, 99, 0, 0), ESRCH);
    CHECK_ERR("unknown-type", kcmp(me, me, 8, 0, 0), EINVAL);
    CHECK_ERR("negative-type", kcmp(me, me, -1, 0, 0), EINVAL);
    int a = open("/", O_RDONLY), b = open("/", O_RDONLY), d = dup(a);
    int p = open("/", O_PATH);
    CHECK("file-dup", kcmp(me, me, KCMP_FILE, a, d) == 0);
    CHECK("file-distinct", ordered(me, me, KCMP_FILE, a, b));
    CHECK("file-o-path", ordered(me, me, KCMP_FILE, a, p));
    CHECK("file-index-unsigned-int", kcmp(me, me, KCMP_FILE, a, (1UL << 32) | d) == 0);
    CHECK_ERR("file-none", kcmp(me, me, KCMP_FILE, a, 999), EBADF);
    CHECK_ERR("file-negative", kcmp(me, me, KCMP_FILE, -1UL, a), EBADF);
    /* Three descriptions in a total order. */
    int c = open("/", O_RDONLY);
    int v[3] = {a, b, c};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j + 1 < 3 - i; j++)
            if (kcmp(me, me, KCMP_FILE, v[j], v[j + 1]) == 2) {
                int t = v[j];
                v[j] = v[j + 1];
                v[j + 1] = t;
            }
    CHECK("file-total-order", kcmp(me, me, KCMP_FILE, v[0], v[1]) == 1 &&
                                  kcmp(me, me, KCMP_FILE, v[1], v[2]) == 1 &&
                                  kcmp(me, me, KCMP_FILE, v[0], v[2]) == 1);
    close(a);
    close(b);
    close(c);
    close(d);
    close(p);
}

/* Bare threads that wait until told to stop. */
static int stop;
static char stacks[4][1 << 14] __attribute__((aligned(16)));
static int ctids[4];

static int waiter(void *arg) {
    (void)arg;
    while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE))
        syscall(SYS_futex, &stop, FUTEX_WAIT, 0, NULL);
    return 0;
}

static pid_t spawn(int i, unsigned long flags) {
    ctids[i] = 1;
    return raw_thread(flags | CLONE_CHILD_CLEARTID, stacks[i] + sizeof stacks[i], waiter, NULL,
                      &ctids[i]);
}

static void stop_all(void) {
    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    syscall(SYS_futex, &stop, FUTEX_WAKE, 4, NULL);
    for (int i = 0; i < 4; i++)
        while (__atomic_load_n(&ctids[i], __ATOMIC_ACQUIRE))
            syscall(SYS_futex, &ctids[i], FUTEX_WAIT, ctids[i], NULL);
}

static void threads(void) {
    pid_t me = getpid();
    pid_t t = spawn(0, THREAD);
    CHECK("thread", t > 0);
    CHECK("thread-vm", kcmp(me, t, KCMP_VM, 0, 0) == 0);
    CHECK("thread-files", kcmp(me, t, KCMP_FILES, 0, 0) == 0);
    CHECK("thread-fs", kcmp(me, t, KCMP_FS, 0, 0) == 0);
    CHECK("thread-sighand", kcmp(me, t, KCMP_SIGHAND, 0, 0) == 0);
    CHECK("thread-no-io-contexts", kcmp(me, t, KCMP_IO, 0, 0) == 0);
    CHECK("thread-no-undo-lists", kcmp(me, t, KCMP_SYSVSEM, 0, 0) == 0);
    CHECK("ioprio-set", syscall(SYS_ioprio_set, 1, 0, IOPRIO_BE | 4) == 0);
    CHECK("io-context-own", ordered(me, t, KCMP_IO, 0, 0));
    pid_t io = spawn(1, THREAD | CLONE_IO);
    CHECK("io-context-shared", kcmp(me, io, KCMP_IO, 0, 0) == 0);
    pid_t copy = spawn(2, THREAD);
    CHECK("io-context-copied", ordered(me, copy, KCMP_IO, 0, 0));
    CHECK("io-context-copied-priority", syscall(SYS_ioprio_get, 1, copy) == (IOPRIO_BE | 4));
    pid_t sem = spawn(3, THREAD | CLONE_SYSVSEM);
    CHECK("undo-list-shared", kcmp(me, sem, KCMP_SYSVSEM, 0, 0) == 0);
    CHECK("undo-list-made-for-creator", ordered(me, t, KCMP_SYSVSEM, 0, 0));
    CHECK("undo-lists-absent-equal", kcmp(t, copy, KCMP_SYSVSEM, 0, 0) == 0);
    stop_all();
}

static void epoll_items(void) {
    pid_t me = getpid();
    int ep = epoll_create1(0), fds[2];
    CHECK("pipe", pipe(fds) == 0);
    int r = fds[0], w = fds[1];
    struct epoll_event ev = {.events = EPOLLIN};
    CHECK("epoll-add", epoll_ctl(ep, EPOLL_CTL_ADD, r, &ev) == 0);
    struct { uint32_t efd, tfd, toff; } slot = {ep, r, 0};
    CHECK("epoll-item", kcmp(me, me, KCMP_EPOLL_TFD, r, (unsigned long)&slot) == 0);
    long other = kcmp(me, me, KCMP_EPOLL_TFD, w, (unsigned long)&slot);
    CHECK("epoll-item-other", other == 1 || other == 2);
    CHECK_ERR("epoll-slot-first", kcmp(me, me, KCMP_EPOLL_TFD, 999, (unsigned long)BAD), EFAULT);
    CHECK_ERR("epoll-descriptor", kcmp(me, me, KCMP_EPOLL_TFD, 999, (unsigned long)&slot), EBADF);
    slot.efd = 999;
    CHECK_ERR("epoll-instance-none", kcmp(me, me, KCMP_EPOLL_TFD, r, (unsigned long)&slot), EBADF);
    slot.efd = r;
    CHECK_ERR("epoll-not-instance", kcmp(me, me, KCMP_EPOLL_TFD, r, (unsigned long)&slot), EINVAL);
    slot.efd = ep;
    slot.toff = 1;
    CHECK_ERR("epoll-offset", kcmp(me, me, KCMP_EPOLL_TFD, r, (unsigned long)&slot), ENOENT);
    slot.toff = 0;
    slot.tfd = w;
    CHECK_ERR("epoll-not-added", kcmp(me, me, KCMP_EPOLL_TFD, r, (unsigned long)&slot), ENOENT);
    /* Two descriptions under one number: the read end stays in the set
     * through a duplicate once its number is reused. */
    int keep = dup(r);
    close(r);
    CHECK("reuse", dup(w) == r);
    CHECK("epoll-add-again", epoll_ctl(ep, EPOLL_CTL_ADD, r, &ev) == 0);
    long k[3], v[3];
    slot.tfd = r;
    for (int i = 0; i < 3; i++) {
        slot.toff = i;
        errno = 0;
        k[i] = kcmp(me, me, KCMP_EPOLL_TFD, keep, (unsigned long)&slot);
        v[i] = kcmp(me, me, KCMP_EPOLL_TFD, w, (unsigned long)&slot);
    }
    CHECK("epoll-two-items", (k[0] == 0) != (k[1] == 0) && (v[0] == 0) != (v[1] == 0) &&
                                 (k[0] == 0) != (v[0] == 0));
    CHECK("epoll-third-none", k[2] == -1 && v[2] == -1 && errno == ENOENT);
    close(keep);
    close(r);
    close(w);
    close(ep);
}

/* A leader that exited while a thread runs keeps only its signal
 * handlers. */
static int leader_word;

static void *after_leader(void *arg) {
    (void)arg;
    while (__atomic_load_n(&leader_word, __ATOMIC_ACQUIRE) != 0)
        syscall(SYS_futex, &leader_word, FUTEX_WAIT, leader_word, NULL);
    usleep(100000);
    pid_t me = getpid(), self = gettid();
    CHECK("exited-leader-vm", ordered(me, self, KCMP_VM, 0, 0));
    CHECK("exited-leader-files", ordered(me, self, KCMP_FILES, 0, 0));
    CHECK("exited-leader-fs", ordered(me, self, KCMP_FS, 0, 0));
    CHECK("exited-leader-sighand", kcmp(me, self, KCMP_SIGHAND, 0, 0) == 0);
    /* The thread has a copy of the context threads() gave a priority,
     * which fork and pthread_create passed on (copy_io). */
    CHECK("exited-leader-io", ordered(me, self, KCMP_IO, 0, 0));
    CHECK("exited-leader-undo-list", ordered(me, self, KCMP_SYSVSEM, 0, 0));
    CHECK_ERR("exited-leader-file", kcmp(me, self, KCMP_FILE, 1, 1), EBADF);
    fflush(stdout);
    exit(failures ? 1 : 0);
}

static void exited_leader(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        leader_word = 1;
        syscall(SYS_set_tid_address, &leader_word);
        pthread_t t;
        pthread_create(&t, NULL, after_leader, NULL);
        syscall(SYS_exit, 0);
    }
    int status = 0;
    waitpid(c, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) failures++;
}

/* Another user's process: init. */
static void others(void) {
    pid_t me = getpid();
    CHECK_ERR("init", kcmp(me, 1, KCMP_VM, 0, 0), EPERM);
    CHECK_ERR("init-before-type", kcmp(1, me, 99, 0, 0), EPERM);
}

int main(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) {
            printf("FAIL drop-privileges\n");
            exit(1);
        }
        order_and_files();
        threads();
        epoll_items();
        others();
        exited_leader();
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(c, &status, 0);
    failures = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    FINISH();
}
