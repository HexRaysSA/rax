/* Memory sealing (mm/mseal.c and the checks of mm/vma.c, mm/mprotect.c,
 * mm/mremap.c, mm/madvise.c, mm/mmap.c, ipc/shm.c): mseal's checks in
 * order (flags, alignment, the rounded length, holes), and what a seal
 * refuses: munmap and the unmapping behind mmap(MAP_FIXED),
 * shmat(SHM_REMAP), and mremap(MREMAP_FIXED) (EPERM, nothing changed),
 * mremap of the sealed VMA, mprotect VMA by VMA, and discarding advice on
 * private anonymous memory that cannot be written; a shrinking brk keeps
 * the break and shmdt leaves a sealed attach mapped; mlock, readable
 * advice, and a child's copy are unaffected. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define P 4096UL
#ifndef SYS_mseal
#define SYS_mseal 462
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef MADV_DONTNEED_LOCKED
#define MADV_DONTNEED_LOCKED 24
#endif

static long seal(void *a, size_t len, unsigned long flags) {
    return syscall(SYS_mseal, a, len, flags);
}

static char *map(size_t len, int prot) {
    return mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

/* Whether the /proc/self/maps line covering `a` has permissions `want`. */
static int maps_perms_are(void *a, const char *want) {
    static char b[1 << 16];
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
            (unsigned long)a < hi)
            return strcmp(perms, want) == 0;
    }
    return 0;
}

static int mapped(void *a) {
    unsigned char v;
    return mincore(a, P, &v) == 0;
}

static void checks(void) {
    char *m = map(8 * P, PROT_READ | PROT_WRITE);
    CHECK_ERR("flags", seal(m, P, 1), EINVAL);
    CHECK_ERR("unaligned", seal(m + 1, P, 0), EINVAL);
    CHECK_ERR("length-wraps", seal(m, (size_t)-1, 0), EINVAL);
    CHECK_ERR("end-wraps", seal((void *)-P, 2 * P, 0), EINVAL);
    CHECK("empty", seal(m, 0, 0) == 0);
    CHECK("empty-unmapped", seal((void *)P, 0, 0) == 0);
    munmap(m + 4 * P, P);
    CHECK_ERR("hole-middle", seal(m + 3 * P, 3 * P, 0), ENOMEM);
    CHECK_ERR("hole-start", seal(m + 4 * P, 2 * P, 0), ENOMEM);
    CHECK_ERR("hole-end", seal(m + 3 * P, 2 * P, 0), ENOMEM);
    /* Nothing was sealed by the failures. */
    CHECK("nothing-sealed", munmap(m + 3 * P, P) == 0);
    CHECK("seal", seal(m, 2 * P, 0) == 0);
    CHECK("seal-again", seal(m, P + 1, 0) == 0);
    munmap(m + 5 * P, 3 * P);
    munmap(m + 2 * P, P);
}

static void refused(void) {
    char *m = map(4 * P, PROT_READ | PROT_WRITE);
    memset(m, 1, 4 * P);
    CHECK("seal-middle", seal(m + P, 2 * P, 0) == 0);
    CHECK_ERR("munmap", munmap(m, 4 * P), EPERM);
    CHECK("munmap-nothing-changed", mapped(m) && mapped(m + 3 * P));
    CHECK_ERR("munmap-partial", munmap(m + 2 * P, P), EPERM);
    CHECK("munmap-unsealed", munmap(m + 3 * P, P) == 0);
    CHECK_ERR("map-fixed", mmap(m, 2 * P, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
                               == MAP_FAILED ? -1 : 0,
              EPERM);
    CHECK("map-fixed-kept", m[P] == 1);
    CHECK_ERR("mremap-grow", mremap(m + P, 2 * P, 3 * P, MREMAP_MAYMOVE) == MAP_FAILED ? -1 : 0,
              EPERM);
    CHECK_ERR("mremap-move", mremap(m + P, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, m + 8 * P)
                                 == MAP_FAILED ? -1 : 0,
              EPERM);
    char *other = map(P, PROT_READ | PROT_WRITE);
    CHECK_ERR("mremap-onto-sealed", mremap(other, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, m + P)
                                        == MAP_FAILED ? -1 : 0,
              EPERM);
    CHECK("mremap-onto-sealed-source-kept", mapped(other));
    /* mprotect: the VMAs before the sealed one change. */
    CHECK_ERR("mprotect", mprotect(m, 3 * P, PROT_READ), EPERM);
    CHECK("mprotect-before-changed", maps_perms_are(m, "r--p") && maps_perms_are(m + P, "rw-p"));
    CHECK("mprotect-unsealed", mprotect(m, P, PROT_READ | PROT_WRITE) == 0);
    CHECK_ERR("mprotect-same", mprotect(m + P, P, PROT_READ | PROT_WRITE), EPERM);
    /* Advice: writable anonymous memory may still be discarded. */
    CHECK("dontneed-writable", madvise(m + P, P, MADV_DONTNEED) == 0 && m[P] == 0);
    char *r = map(2 * P, PROT_READ | PROT_WRITE);
    memset(r, 2, 2 * P);
    mprotect(r, 2 * P, PROT_READ);
    CHECK("seal-read-only", seal(r, 2 * P, 0) == 0);
    CHECK_ERR("dontneed-read-only", madvise(r, P, MADV_DONTNEED), EPERM);
    CHECK_ERR("free-read-only", madvise(r, P, MADV_FREE), EPERM);
    CHECK_ERR("dontneed-locked-read-only", madvise(r, P, MADV_DONTNEED_LOCKED), EPERM);
    CHECK_ERR("dontfork-read-only", madvise(r, P, MADV_DONTFORK), EPERM);
    CHECK("cold-read-only", madvise(r, P, MADV_COLD) == 0);
    CHECK("willneed-read-only", madvise(r, P, MADV_WILLNEED) == 0);
    CHECK("kept-read-only", r[0] == 2);
    CHECK("mlock-sealed", mlock(r, P) == 0 && munlock(r, P) == 0);
    /* A private file mapping may be discarded however it is sealed. */
    int fd = open("/proc/self/exe", O_RDONLY);
    char *f = mmap(NULL, P, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK("seal-file", f != MAP_FAILED && seal(f, P, 0) == 0);
    CHECK("dontneed-file", madvise(f, P, MADV_DONTNEED) == 0);
    close(fd);
    /* A child's copy is sealed too. */
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) _exit(munmap(r, P) == -1 && errno == EPERM ? 0 : 1);
    int st = 0;
    waitpid(c, &st, 0);
    CHECK("child-sealed", WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void brk_and_shm(void) {
    char *b = (char *)syscall(SYS_brk, 0);
    char *top = (char *)(((unsigned long)b + P - 1) & ~(P - 1));
    CHECK("brk-grow", (char *)syscall(SYS_brk, top + 2 * P) == top + 2 * P);
    CHECK("seal-heap", seal(top, 2 * P, 0) == 0);
    CHECK("brk-shrink-kept", (char *)syscall(SYS_brk, top) == top + 2 * P);
    CHECK("brk-still-grows", (char *)syscall(SYS_brk, top + 3 * P) == top + 3 * P);
    int id = shmget(IPC_PRIVATE, P, 0600);
    char *s = shmat(id, NULL, 0);
    CHECK("shmat", s != (void *)-1 && seal(s, P, 0) == 0);
    CHECK("shmdt-sealed", shmdt(s) == 0 && mapped(s));
    CHECK_ERR("shmat-remap-sealed", shmat(id, s, SHM_REMAP) == (void *)-1 ? -1 : 0, EPERM);
    shmctl(id, IPC_RMID, NULL);
}

int main(void) {
    checks();
    refused();
    brk_and_shm();
    FINISH();
}
