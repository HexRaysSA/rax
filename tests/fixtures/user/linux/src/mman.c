/* Per-VMA semantics of mprotect and madvise, and personality(2). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "check.h"

#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#define MADV_POPULATE_WRITE 23
#endif

static long page;
static int zero_fd;

static unsigned char *anon(long len, int prot, int kind) {
    return mmap(NULL, len, prot, kind | MAP_ANONYMOUS, -1, 0);
}

/* Whether the kernel can store into p: read(2) into a page the process may
 * not write fails with EFAULT. */
static int writable(void *p) {
    errno = 0;
    return read(zero_fd, p, 1) == 1;
}

/* mprotect without musl's address rounding. */
static long sys_mprotect(void *addr, long len, long prot) {
    return syscall(SYS_mprotect, addr, len, prot);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    page = sysconf(_SC_PAGESIZE);
    zero_fd = open("/dev/zero", O_RDONLY);
    CHECK("open-dev-zero", zero_fd >= 0);
    const int rw = PROT_READ | PROT_WRITE;

    /* MADV_DONTNEED: private anonymous pages refault as zero; shared pages
     * keep their contents. */
    unsigned char *pa = anon(2 * page, rw, MAP_PRIVATE);
    unsigned char *sa = anon(2 * page, rw, MAP_SHARED);
    memset(pa, 0x11, 2 * page);
    memset(sa, 0x22, 2 * page);
    CHECK("dontneed-private", madvise(pa, 2 * page, MADV_DONTNEED) == 0 &&
                                  pa[0] == 0 && pa[2 * page - 1] == 0);
    CHECK("dontneed-shared", madvise(sa, 2 * page, MADV_DONTNEED) == 0 &&
                                 sa[0] == 0x22 && sa[2 * page - 1] == 0x22);

    /* MADV_FREE: private anonymous memory only. */
    CHECK("free-private", madvise(pa, page, MADV_FREE) == 0);
    CHECK_ERR("free-shared", madvise(sa, page, MADV_FREE), EINVAL);

    /* MADV_REMOVE: a shared mapping that may be written. */
    CHECK_ERR("remove-private-anon", madvise(pa, page, MADV_REMOVE), EINVAL);
    CHECK("remove-shared-anon", madvise(sa, page, MADV_REMOVE) == 0 &&
                                    sa[0] == 0 && sa[page] == 0x22);

    char path[] = "/tmp/rax-mman-XXXXXX";
    int fd = mkstemp(path);
    CHECK("mkstemp", fd >= 0);
    char data[100];
    memset(data, 'f', sizeof data);
    CHECK("file-write", write(fd, data, sizeof data) == (ssize_t)sizeof data);
    int ro = open(path, O_RDONLY);
    CHECK("open-ro", ro >= 0);
    unsigned char *pf = mmap(NULL, page, PROT_READ, MAP_PRIVATE, ro, 0);
    CHECK("map-private-file", pf != MAP_FAILED);
    CHECK_ERR("remove-private-file", madvise(pf, page, MADV_REMOVE), EACCES);

    /* A shared mapping of a read-only file can never become writable; a
     * private one can (copy-on-write). */
    CHECK_ERR("map-shared-ro-write",
              (long)mmap(NULL, page, rw, MAP_SHARED, ro, 0), EACCES);
    unsigned char *sf = mmap(NULL, page, PROT_READ, MAP_SHARED, ro, 0);
    CHECK("map-shared-ro", sf != MAP_FAILED && sf[0] == 'f');
    CHECK_ERR("mprotect-shared-ro-write", mprotect(sf, page, rw), EACCES);
    CHECK_ERR("remove-shared-ro", madvise(sf, page, MADV_REMOVE), EACCES);
    CHECK("mprotect-private-ro-write", mprotect(pf, page, rw) == 0);
    pf[0] = 'z';
    char first = 0;
    CHECK("private-write-stays-private", pread(fd, &first, 1, 0) == 1 && first == 'f');

    /* MADV_POPULATE_*: permission mismatch is EINVAL; a page past the end
     * of the file would raise SIGBUS, which is EFAULT. */
    unsigned char *r = anon(page, PROT_READ, MAP_PRIVATE);
    CHECK("populate-read", madvise(r, page, MADV_POPULATE_READ) == 0);
    CHECK_ERR("populate-write-readonly", madvise(r, page, MADV_POPULATE_WRITE), EINVAL);
    unsigned char *w = anon(2 * page, rw, MAP_PRIVATE);
    unsigned char vec[2] = {0, 0};
    CHECK("populate-write", madvise(w, 2 * page, MADV_POPULATE_WRITE) == 0 &&
                                mincore(w, 2 * page, vec) == 0 &&
                                (vec[0] & 1) && (vec[1] & 1) && w[0] == 0);
    unsigned char *pe = mmap(NULL, 2 * page, PROT_READ, MAP_PRIVATE, ro, 0);
    CHECK_ERR("populate-beyond-eof", madvise(pe, 2 * page, MADV_POPULATE_READ), EFAULT);

    /* madvise skips holes, applies the advice elsewhere, then fails. */
    unsigned char *q = anon(3 * page, rw, MAP_PRIVATE);
    memset(q, 0x44, 3 * page);
    CHECK("unmap-middle", munmap(q + page, page) == 0);
    CHECK_ERR("madvise-hole", madvise(q, 3 * page, MADV_DONTNEED), ENOMEM);
    CHECK("madvise-hole-applied", q[0] == 0 && q[2 * page] == 0);
    CHECK_ERR("populate-hole", madvise(q, 3 * page, MADV_POPULATE_WRITE), ENOMEM);

    /* A VMA refusing the advice ends the walk with its error. */
    unsigned char *mid = mmap(q + page, page, rw, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK("map-fixed-shared", mid == q + page);
    q[2 * page] = 0x66;
    CHECK_ERR("madvise-refused", madvise(q, 3 * page, MADV_FREE), EINVAL);
    CHECK("madvise-refused-stops", q[2 * page] == 0x66);

    /* mprotect validates in kernel order and stops at the first hole,
     * keeping the change it already made. */
    CHECK_ERR("mprotect-grows-both",
              sys_mprotect(q, 0, PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP), EINVAL);
    CHECK("mprotect-len0-bad-prot", sys_mprotect(q, 0, 0x1000) == 0);
    CHECK_ERR("mprotect-unaligned", sys_mprotect(q + 1, page, PROT_READ), EINVAL);
    CHECK_ERR("mprotect-bad-prot", sys_mprotect(q, page, 0x1000), EINVAL);
    CHECK_ERR("mprotect-growsup", sys_mprotect(q, page, PROT_READ | PROT_GROWSUP), EINVAL);
    CHECK_ERR("mprotect-growsdown-anon",
              sys_mprotect(q, page, PROT_READ | PROT_GROWSDOWN), EINVAL);
    unsigned char *h = anon(3 * page, rw, MAP_PRIVATE);
    CHECK("unmap-h", munmap(h + page, page) == 0);
    CHECK("writable-before", writable(h) && writable(h + 2 * page));
    CHECK_ERR("mprotect-hole", sys_mprotect(h, 3 * page, PROT_READ), ENOMEM);
    CHECK("mprotect-hole-applied", !writable(h) && errno == EFAULT);
    CHECK("mprotect-hole-stopped", writable(h + 2 * page));

    /* PROT_GROWSDOWN on the main stack extends to the start of the VMA. */
    volatile char local = 1;
    uintptr_t sp_page = (uintptr_t)&local & ~(uintptr_t)(page - 1);
    CHECK("mprotect-growsdown-stack",
          sys_mprotect((void *)sp_page, page, rw | PROT_GROWSDOWN) == 0 && local == 1);

    /* personality(2) returns the previous value. */
    int old = personality(0xffffffff);
    CHECK("personality-set", personality(old | READ_IMPLIES_EXEC) == old);
    CHECK("personality-query", personality(0xffffffff) == (old | READ_IMPLIES_EXEC));
    CHECK("personality-restore", personality(old) == (old | READ_IMPLIES_EXEC) &&
                                     personality(0xffffffff) == old);

    close(ro);
    close(fd);
    unlink(path);
    FINISH();
}
