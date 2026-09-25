/* Memory locking (mm/mlock.c, mm/gup.c, mm/mmap.c, mm/mremap.c,
 * mm/madvise.c): mlock, mlock2, and munlock (the right, RLIMIT_MEMLOCK
 * less what a range already holds locked, holes, PROT_NONE, whole pages,
 * the kernel's length arithmetic), populating or not (MLOCK_ONFAULT),
 * madvise's refusals, mlockall with MCL_FUTURE for mmap, brk, and mremap,
 * MAP_LOCKED, VmLck in /proc/self/status, and a child process, which
 * inherits no lock. Root drops to nobody first; only the soft limit is
 * changed. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define P 4096UL
#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT 4
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef MADV_DONTNEED_LOCKED
#define MADV_DONTNEED_LOCKED 24
#endif

/* VmLck in kB, -1 if missing. */
static long vmlck(void) {
    static char b[8192];
    int fd = open("/proc/self/status", O_RDONLY);
    long n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    char *l = strstr(b, "\nVmLck:");
    return l ? atol(l + 7) : -1;
}

static int resident(void *a) {
    unsigned char v = 0;
    return mincore(a, P, &v) == 0 && (v & 1);
}

static int memlock(unsigned long pages) {
    struct rlimit r;
    getrlimit(RLIMIT_MEMLOCK, &r);
    r.rlim_cur = pages * P;
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

static char *map(size_t len, int prot) {
    return mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void locking(void) {
    char *m = map(32 * P, PROT_READ | PROT_WRITE);
    CHECK_ERR("mlock2-flags", syscall(SYS_mlock2, m, P, 2), EINVAL);
    CHECK("limit-0", memlock(0) == 0);
    CHECK_ERR("mlock-no-right", mlock(m, P), EPERM);
    CHECK_ERR("mlockall-no-right", mlockall(MCL_CURRENT), EPERM);
    /* musl's mmap turns this EPERM into ENOMEM; the call itself: */
    CHECK_ERR("map-locked-no-right",
              syscall(SYS_mmap, NULL, P, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0),
              EPERM);
    CHECK("munlock-no-right-needed", munlock(m, P) == 0);
    CHECK("limit-16", memlock(16) == 0);
    CHECK("vmlck-none", vmlck() == 0);
    CHECK("mlock-8", mlock(m, 8 * P) == 0 && vmlck() == 32);
    CHECK_ERR("mlock-over-limit", mlock(m + 8 * P, 16 * P), ENOMEM);
    CHECK("mlock-again", mlock(m, 8 * P) == 0 && vmlck() == 32);
    CHECK("mlock-overlap-counted-once", mlock(m + 4 * P, 12 * P) == 0 && vmlck() == 64);
    CHECK("munlock-whole-pages", munlock(m + 2 * P + 1, P) == 0 && vmlck() == 56);
    CHECK("mlock-size-max", mlock(m + 20 * P, (size_t)-1) == 0 && vmlck() == 56);
    CHECK("munlock-all-of-it", munlock(m, 32 * P) == 0 && vmlck() == 0);
    /* Holes, PROT_NONE. */
    munmap(m + 25 * P, P);
    CHECK_ERR("mlock-hole-first", mlock(m + 25 * P, 2 * P), ENOMEM);
    CHECK("mlock-hole-first-nothing", vmlck() == 0);
    CHECK_ERR("mlock-hole-later", mlock(m + 24 * P, 3 * P), ENOMEM);
    CHECK("mlock-hole-later-before", vmlck() == 4);
    mprotect(m + 28 * P, P, PROT_NONE);
    CHECK_ERR("mlock-prot-none", mlock(m + 28 * P, P), ENOMEM);
    CHECK("mlock-prot-none-locked", vmlck() == 8);
    CHECK("munlock-holes", munlock(m + 24 * P, P) == 0 && munlock(m + 28 * P, P) == 0 &&
                               vmlck() == 0);
    /* Bringing pages in. */
    char *f = map(4 * P, PROT_READ | PROT_WRITE);
    CHECK("onfault", syscall(SYS_mlock2, f, 2 * P, MLOCK_ONFAULT) == 0 && !resident(f) &&
                         vmlck() == 8);
    CHECK("populated", mlock(f + 2 * P, 2 * P) == 0 && resident(f + 3 * P));
    char *w = map(P, PROT_WRITE), *x = map(P, PROT_EXEC);
    CHECK("write-only-populated", mlock(w, P) == 0 && resident(w));
    CHECK("exec-only-populated", mlock(x, P) == 0 && resident(x));
    /* Locked pages are not discarded. */
    memset(m, 7, 2 * P);
    CHECK("lock-for-advice", mlock(m, P) == 0);
    CHECK_ERR("dontneed-locked", madvise(m, 2 * P, MADV_DONTNEED), EINVAL);
    CHECK_ERR("free-locked", madvise(m, 2 * P, MADV_FREE), EINVAL);
    CHECK_ERR("cold-locked", madvise(m, 2 * P, MADV_COLD), EINVAL);
    CHECK("kept", m[0] == 7);
    CHECK("dontneed-locked-ok", madvise(m, P, MADV_DONTNEED_LOCKED) == 0 && m[0] == 0);
    CHECK("munlock-then-dontneed", munlock(m, P) == 0 && madvise(m + P, P, MADV_DONTNEED) == 0 &&
                                       m[P] == 0);
    munlockall();
    CHECK("munlockall", vmlck() == 0);
    munmap(m, 32 * P);
    munmap(f, 4 * P);
}

static void future(void) {
    CHECK_ERR("mlockall-none", mlockall(0), EINVAL);
    CHECK_ERR("mlockall-unknown", mlockall(8), EINVAL);
    CHECK_ERR("mlockall-onfault-alone", mlockall(MCL_ONFAULT), EINVAL);
    CHECK_ERR("mlockall-current-too-big", mlockall(MCL_CURRENT), ENOMEM);
    CHECK("mlockall-future", mlockall(MCL_FUTURE) == 0 && vmlck() == 0);
    char *m = map(4 * P, PROT_READ | PROT_WRITE);
    CHECK("future-mapping-locked", m != MAP_FAILED && vmlck() == 16 && resident(m + 3 * P));
    CHECK("future-over-limit", map(16 * P, PROT_READ) == MAP_FAILED && errno == EAGAIN);
    char *brk = (char *)syscall(SYS_brk, 0);
    char *top = (char *)(((unsigned long)brk + P - 1) & ~(P - 1));
    CHECK("brk-locked", (char *)syscall(SYS_brk, top + 2 * P) == top + 2 * P && vmlck() == 24);
    CHECK("brk-over-limit", (char *)syscall(SYS_brk, top + 64 * P) == top + 2 * P);
    char *g = mremap(m, 4 * P, 6 * P, MREMAP_MAYMOVE);
    CHECK("mremap-grow-locked", g != MAP_FAILED && vmlck() == 32 && resident(g + 5 * P));
    CHECK("mremap-over-limit", mremap(g, 6 * P, 16 * P, MREMAP_MAYMOVE) == MAP_FAILED &&
                                   errno == EAGAIN);
    /* MREMAP_DONTUNMAP unlocks the old range but leaves it counted:
     * move_vma counts the new VMA and never unmaps the old one. */
    char *d = mremap(g, 6 * P, 6 * P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
    CHECK("dontunmap-counted-twice", d != MAP_FAILED && vmlck() == 56 && !resident(g));
    /* A child starts unlocked, MCL_FUTURE and all. */
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        char *n = map(P, PROT_READ | PROT_WRITE);
        _exit(vmlck() == 0 && n != MAP_FAILED && vmlck() == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    CHECK("child-unlocked", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK("munlockall-keeps-the-count", munlockall() == 0 && vmlck() == 24);
    char *n = map(P, PROT_READ | PROT_WRITE);
    CHECK("no-future-lock", n != MAP_FAILED && vmlck() == 24);
    CHECK("map-locked", mmap(NULL, 2 * P, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1,
                             0) != MAP_FAILED &&
                            vmlck() == 32);
}

int main(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) {
            printf("FAIL drop-privileges\n");
            exit(1);
        }
        locking();
        future();
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(c, &status, 0);
    failures = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    FINISH();
}
