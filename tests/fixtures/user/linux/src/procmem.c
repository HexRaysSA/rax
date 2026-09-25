/* A process's memory through a task's ID (mm/process_vm_access.c,
 * mm/gup.c, lib/iov_iter.c, mm/madvise.c): process_vm_readv and
 * process_vm_writev (the checks in order, vector import with access_ok
 * and MAX_RW_COUNT, transfers by page needing VM_READ or VM_WRITE,
 * partial transfers at a remote or local fault, a thread's ID), what
 * /proc/self/maps and MADV_POPULATE_READ make of a mapping without
 * PROT_READ, process_madvise (the checks, advice by vector, empty and
 * misaligned vectors, pidfds), a leader that exited while its threads run,
 * and init's memory, which another user may not reach. Root drops to
 * nobody first. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/futex.h>
#include "check.h"

#define P 4096UL
#define BAD ((void *)16)
#define KERNEL ((void *)0xffff800000000000UL)
#define PIDFD_SELF_THREAD -10000
#define PIDFD_SELF_THREAD_GROUP -10001
#define PIDFD_THREAD O_EXCL
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#define MADV_POPULATE_READ_ 22
#define MADV_POPULATE_WRITE_ 23

static long pvr(pid_t pid, const struct iovec *l, unsigned long ln, const struct iovec *r,
                unsigned long rn) {
    return syscall(SYS_process_vm_readv, pid, l, ln, r, rn, 0UL);
}

static long pvw(pid_t pid, const struct iovec *l, unsigned long ln, const struct iovec *r,
                unsigned long rn) {
    return syscall(SYS_process_vm_writev, pid, l, ln, r, rn, 0UL);
}

static long pmadv(int pidfd, const struct iovec *v, size_t n, int advice) {
    return syscall(SYS_process_madvise, pidfd, v, n, advice, 0U);
}

static char *map(size_t len, int prot) {
    return mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static unsigned char pattern(size_t i) {
    return (unsigned char)(i * 7 + 3);
}

/* The permission column of the /proc/self/maps line covering `a`. */
static void maps_perms(void *a, char out[5]) {
    static char b[1 << 16];
    strcpy(out, "none");
    int fd = open("/proc/self/maps", O_RDONLY);
    size_t n = 0;
    long k;
    while (fd >= 0 && n < sizeof b - 1 && (k = read(fd, b + n, sizeof b - 1 - n)) > 0) n += k;
    if (fd >= 0) close(fd);
    b[n] = 0;
    for (char *l = b; *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : l + strlen(l)) {
        unsigned long lo, hi;
        char perms[5];
        if (sscanf(l, "%lx-%lx %4s", &lo, &hi, perms) == 3 && lo <= (unsigned long)a &&
            (unsigned long)a < hi) {
            memcpy(out, perms, 5);
            return;
        }
    }
}

static void vm_read_flag(void) {
    char perms[5];
    char *w = map(3 * P, PROT_WRITE);
    maps_perms(w, perms);
    CHECK("maps-write-only", strcmp(perms, "-w-p") == 0);
    CHECK_ERR("populate-read-write-only", madvise(w, P, MADV_POPULATE_READ_), EINVAL);
    CHECK("populate-write-write-only", madvise(w, P, MADV_POPULATE_WRITE_) == 0);
    CHECK("mprotect-exec-only", mprotect(w + P, P, PROT_EXEC) == 0);
    maps_perms(w + P, perms);
    CHECK("maps-exec-only", strcmp(perms, "--xp") == 0);
    maps_perms(w + 2 * P, perms);
    CHECK("maps-split-rest", strcmp(perms, "-w-p") == 0);
    CHECK_ERR("populate-read-exec-only", madvise(w + P, P, MADV_POPULATE_READ_), EINVAL);
    CHECK("mprotect-rw", mprotect(w, 3 * P, PROT_READ | PROT_WRITE) == 0);
    maps_perms(w + P, perms);
    CHECK("maps-rw", strcmp(perms, "rw-p") == 0);
    CHECK("populate-read-rw", madvise(w, 3 * P, MADV_POPULATE_READ_) == 0);
    CHECK("mprotect-none", mprotect(w, P, PROT_NONE) == 0);
    maps_perms(w, perms);
    CHECK("maps-none", strcmp(perms, "---p") == 0);
    munmap(w, 3 * P);
}

static void order(void) {
    pid_t me = getpid();
    char *m = map(4 * P, PROT_READ | PROT_WRITE);
    char *buf = m + P;
    struct iovec l = {buf, 16}, r = {m + 2 * P, 16};
    CHECK_ERR("flags", syscall(SYS_process_vm_readv, me, &l, 1UL, &r, 1UL, 1UL), EINVAL);
    CHECK_ERR("local-count", pvr(me, &l, 1025, &r, 1), EINVAL);
    CHECK_ERR("local-array", pvr(me, BAD, 1, &r, 1), EFAULT);
    struct iovec neg = {buf, (size_t)-1};
    CHECK_ERR("local-negative", pvr(me, &neg, 1, &r, 1), EINVAL);
    CHECK_ERR("remote-negative", pvr(me, &l, 1, &neg, 1), EINVAL);
    struct iovec kern[2] = {{buf, 10}, {KERNEL, 10}};
    CHECK_ERR("local-kernel", pvr(me, kern, 2, &r, 1), EFAULT);
    CHECK_ERR("remote-kernel", pvr(me, &l, 1, &kern[1], 1), EFAULT);
    /* One vector is capped at MAX_RW_COUNT before access_ok; several are
     * checked at their full lengths. */
    char *low = mmap((void *)0x10000000, P, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK("low-page", low == (void *)0x10000000);
    struct iovec one = {low, 1UL << 62};
    CHECK("single-capped", pvr(me, &one, 1, &r, 1) == 16);
    struct iovec two[2] = {{low, 1UL << 62}, {buf, 1}};
    CHECK_ERR("several-full-length", pvr(me, two, 2, &r, 1), EFAULT);
    CHECK("count-unsigned-int", pvr(me, &l, (1UL << 32) | 1, &r, 1) == 16);
    /* Empty transfers end before the task is looked up. */
    struct iovec empty = {buf, 0};
    CHECK("empty-local", pvr(99999, &empty, 1, &r, 1) == 0);
    CHECK("no-local", pvr(99999, &l, 0, &r, 1) == 0);
    CHECK_ERR("remote-array", pvr(99999, &l, 1, BAD, 1), EFAULT);
    CHECK_ERR("remote-count", pvr(99999, &l, 1, &r, 1025), EINVAL);
    struct iovec rempty[2] = {{BAD, 0}, {BAD, 0}};
    CHECK("empty-remote", pvr(99999, &l, 1, rempty, 2) == 0);
    CHECK("no-remote", pvr(99999, &l, 1, &r, 0) == 0);
    CHECK_ERR("no-task", pvr(99999, &l, 1, &r, 1), ESRCH);
    CHECK_ERR("pid-0", pvr(0, &l, 1, &r, 1), ESRCH);
    CHECK_ERR("write-no-task", pvw(-1, &l, 1, &r, 1), ESRCH);
    munmap(low, P);
    munmap(m, 4 * P);
}

static volatile pid_t helper_tid;

static void *helper(void *arg) {
    (void)arg;
    helper_tid = gettid();
    for (;;) pause();
    return NULL;
}

static void transfers(void) {
    pid_t me = getpid();
    char *m = map(8 * P, PROT_READ | PROT_WRITE);
    char *dst = m + P;
    char *src = map(2 * P, PROT_READ | PROT_WRITE);
    for (size_t i = 0; i < 2 * P; i++) src[i] = pattern(i);
    struct iovec l3[3] = {{dst, 3}, {dst + 100, 0}, {dst + 200, 5}};
    struct iovec r2[2] = {{src + 10, 2}, {src + 20, 10}};
    CHECK("vectors", pvr(me, l3, 3, r2, 2) == 8);
    CHECK("vectors-data", (unsigned char)dst[0] == pattern(10) &&
                              (unsigned char)dst[2] == pattern(20) &&
                              (unsigned char)dst[200] == pattern(21) &&
                              (unsigned char)dst[204] == pattern(25));
    pthread_t t;
    pthread_create(&t, NULL, helper, NULL);
    while (!helper_tid) sched_yield();
    struct iovec l = {dst, 8}, r = {src, 8}, far = {src + P, 8};
    CHECK("thread-read", pvr(helper_tid, &l, 1, &r, 1) == 8);
    CHECK("thread-write", pvw(helper_tid, &l, 1, &far, 1) == 8);
    CHECK("thread-write-data", memcmp(src + P, src, 8) == 0);

    /* A remote fault ends the transfer at the pages reached. */
    munmap(src + P, P);
    struct iovec big = {dst, 4 * P}, straddle = {src + 100, 2 * P};
    CHECK("remote-partial", pvr(me, &big, 1, &straddle, 1) == (long)(P - 100));
    CHECK("remote-partial-data", (unsigned char)dst[0] == pattern(100) &&
                                     (unsigned char)dst[P - 101] == pattern(P - 1));
    struct iovec hole = {src + P, 10};
    CHECK_ERR("remote-hole", pvr(me, &big, 1, &hole, 1), EFAULT);
    struct iovec then_hole[2] = {{src, 10}, {src + P, 10}};
    CHECK("remote-then-hole", pvr(me, &big, 1, then_hole, 2) == 10);

    /* Reading needs VM_READ, which write-only and execute-only mappings
     * lack; writing needs VM_WRITE. */
    struct iovec r16 = {src, 16}, l16 = {dst, 16};
    mprotect(src, P, PROT_WRITE);
    CHECK_ERR("read-write-only", pvr(me, &l16, 1, &r16, 1), EFAULT);
    mprotect(src, P, PROT_EXEC);
    CHECK_ERR("read-exec-only", pvr(me, &l16, 1, &r16, 1), EFAULT);
    mprotect(src, P, PROT_NONE);
    CHECK_ERR("read-none", pvr(me, &l16, 1, &r16, 1), EFAULT);
    mprotect(src, P, PROT_READ);
    CHECK("read-read-only", pvr(me, &l16, 1, &r16, 1) == 16);
    CHECK_ERR("write-read-only", pvw(me, &l16, 1, &r16, 1), EFAULT);
    mprotect(src, P, PROT_WRITE);
    memset(dst, 0xab, 16);
    CHECK("write-write-only", pvw(me, &l16, 1, &r16, 1) == 16);
    mprotect(src, P, PROT_READ | PROT_WRITE);
    CHECK("write-write-only-data", (unsigned char)src[0] == 0xab && (unsigned char)src[15] == 0xab);

    /* A local fault ends it exactly where the local side stops. */
    char *ro = m + 4 * P;
    mprotect(ro, P, PROT_READ);
    struct iovec lro = {ro - 100, 1000}, r1000 = {src, 1000};
    CHECK("local-partial", pvr(me, &lro, 1, &r1000, 1) == 100);
    lro.iov_base = ro;
    CHECK_ERR("local-fault", pvr(me, &lro, 1, &r1000, 1), EFAULT);
    char *none = m + 6 * P;
    memset(none - 30, 0x5a, 30);
    mprotect(none, P, PROT_NONE);
    struct iovec lnone = {none - 30, 100};
    CHECK("local-read-partial", pvw(me, &lnone, 1, &r1000, 1) == 30);
    CHECK("local-read-partial-data", (unsigned char)src[29] == 0x5a &&
                                         (unsigned char)src[30] == pattern(30));
    munmap(m, 8 * P);
    munmap(src, P);
}

static void advice(void) {
    pid_t me = getpid();
    char *m = map(2 * P, PROT_READ | PROT_WRITE);
    int pfd = syscall(SYS_pidfd_open, me, 0);
    CHECK("pidfd", pfd >= 0);
    memset(m, 5, 2 * P);
    struct iovec both[2] = {{m, P}, {m + P, P}};
    CHECK("dontneed", pmadv(pfd, both, 2, MADV_DONTNEED) == (long)(2 * P));
    CHECK("dontneed-data", m[0] == 0 && m[P] == 0);
    CHECK_ERR("advice-flags", syscall(SYS_process_madvise, pfd, both, 2UL, MADV_WILLNEED, 1U), EINVAL);
    CHECK_ERR("vectors-first", pmadv(-1, BAD, 2, MADV_WILLNEED), EFAULT);
    CHECK_ERR("advice-count", pmadv(pfd, both, 1025, MADV_WILLNEED), EINVAL);
    CHECK_ERR("no-descriptor", pmadv(-1, both, 2, MADV_WILLNEED), EBADF);
    CHECK_ERR("not-a-pidfd", pmadv(1, both, 2, MADV_WILLNEED), EBADF);
    CHECK("self-thread", pmadv(PIDFD_SELF_THREAD, both, 1, MADV_WILLNEED) == (long)P);
    CHECK("self-group", pmadv(PIDFD_SELF_THREAD_GROUP, both, 1, MADV_WILLNEED) == (long)P);
    struct iovec first_empty[2] = {{m + 1, 0}, {m, P}};
    CHECK_ERR("first-empty-misaligned", pmadv(pfd, first_empty, 2, MADV_DONTNEED), EINVAL);
    struct iovec mid_empty[3] = {{m, P}, {m + 1, 0}, {m + P, P}};
    CHECK("later-empty-passed", pmadv(pfd, mid_empty, 3, MADV_DONTNEED) == (long)(2 * P));
    struct iovec second_bad[2] = {{m, P}, {m + 1, P}};
    CHECK("second-misaligned", pmadv(pfd, second_bad, 2, MADV_DONTNEED) == (long)P);
    struct iovec lone_empty = {m + 1, 0};
    CHECK("single-empty", pmadv(pfd, &lone_empty, 1, MADV_DONTNEED) == 0);
    struct iovec kern = {KERNEL, P};
    CHECK_ERR("kernel-address", pmadv(pfd, &kern, 1, MADV_DONTNEED), EFAULT);
    /* The vector cap: one is capped to MAX_RW_COUNT bytes, which reach
     * past the page into nothing mapped; of several, each is checked at
     * its full length. */
    char *low = mmap((void *)0x10000000, P, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    struct iovec capped = {low, 1UL << 40};
    CHECK_ERR("advice-single-capped", pmadv(pfd, &capped, 1, MADV_WILLNEED), ENOMEM);
    struct iovec full[2] = {{low, 1UL << 62}, {m, P}};
    CHECK_ERR("advice-several-full-length", pmadv(pfd, full, 2, MADV_WILLNEED), EFAULT);
    munmap(low, P);
    CHECK_ERR("bad-advice", pmadv(pfd, both, 1, 999), EINVAL);
    int tfd = syscall(SYS_pidfd_open, helper_tid, PIDFD_THREAD);
    CHECK("thread-pidfd", tfd >= 0);
    CHECK_ERR("thread-pidfd-not-leader", pmadv(tfd, both, 1, MADV_WILLNEED), ESRCH);
    close(tfd);
    close(pfd);
    munmap(m, 2 * P);
}

/* Another user's process: init. */
static void others(void) {
    char b[16];
    char *m = map(P, PROT_READ | PROT_WRITE);
    struct iovec l = {b, sizeof b}, r = {m, 16};
    CHECK_ERR("init-read", pvr(1, &l, 1, &r, 1), EPERM);
    CHECK_ERR("init-write", pvw(1, &l, 1, &r, 1), EPERM);
    int init = syscall(SYS_pidfd_open, 1, 0);
    CHECK("init-pidfd", init >= 0);
    struct iovec v = {m, P};
    CHECK_ERR("init-advice", pmadv(init, &v, 1, MADV_COLD), EACCES);
    close(init);
    munmap(m, P);
}

/* A leader that exited while a thread runs has no memory. */
static int leader_word;
static char *leader_page;

static void *after_leader(void *arg) {
    (void)arg;
    while (__atomic_load_n(&leader_word, __ATOMIC_ACQUIRE) != 0)
        syscall(SYS_futex, &leader_word, FUTEX_WAIT, leader_word, NULL);
    usleep(100000);
    pid_t me = getpid();
    struct iovec l = {leader_page + 64, 8}, r = {leader_page, 8};
    CHECK_ERR("exited-leader-read", pvr(me, &l, 1, &r, 1), ESRCH);
    CHECK("exited-leader-own-tid", pvr(gettid(), &l, 1, &r, 1) == 8);
    struct iovec v = {leader_page, P};
    CHECK_ERR("exited-leader-advice", pmadv(PIDFD_SELF_THREAD_GROUP, &v, 1, MADV_WILLNEED),
              ESRCH);
    CHECK("exited-leader-self-thread", pmadv(PIDFD_SELF_THREAD, &v, 1, MADV_WILLNEED) == (long)P);
    fflush(stdout);
    exit(failures ? 1 : 0);
}

static void exited_leader(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        leader_page = map(P, PROT_READ | PROT_WRITE);
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

int main(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) {
            printf("FAIL drop-privileges\n");
            exit(1);
        }
        vm_read_flag();
        order();
        transfers();
        advice();
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
