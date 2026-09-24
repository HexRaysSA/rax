/* Heap, anonymous and file mappings, protection, and remapping. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "check.h"

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    long page = sysconf(_SC_PAGESIZE);
    CHECK("pagesize", page == 4096);

    /* malloc across the mmap threshold. */
    int ok = 1;
    for (size_t sz = 1; sz <= (4u << 20); sz *= 3) {
        unsigned char *p = malloc(sz);
        if (!p) { ok = 0; break; }
        memset(p, (int)(sz & 0xff), sz);
        if (p[0] != (unsigned char)(sz & 0xff) || p[sz - 1] != (unsigned char)(sz & 0xff))
            ok = 0;
        free(p);
    }
    CHECK("malloc-sizes", ok);

    /* brk grows exactly and the new memory is zero. musl's sbrk() refuses
     * nonzero increments, so use the system call directly. */
    char *b0 = (char *)syscall(SYS_brk, 0);
    char *b1 = (char *)syscall(SYS_brk, b0 + 3 * page);
    CHECK("brk-grow", b1 == b0 + 3 * page);
    if (b1 == b0 + 3 * page) {
        CHECK("brk-zero", b0[0] == 0 && b0[3 * page - 1] == 0);
        b0[0] = 1;
        b0[3 * page - 1] = 2;
    }
    CHECK("brk-below-start-ignored", (char *)syscall(SYS_brk, (char *)4096) == b1);
    CHECK("brk-shrink", (char *)syscall(SYS_brk, b0) == b0);
    CHECK("brk-query", (char *)syscall(SYS_brk, 0) == b0);

    unsigned char *m = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK("mmap-anon", m != MAP_FAILED);
    CHECK("mmap-aligned", ((uintptr_t)m & (page - 1)) == 0);
    CHECK("mmap-zero", m[0] == 0 && m[4 * page - 1] == 0);
    memset(m, 0x5a, 4 * page);
    CHECK("mprotect-ro", mprotect(m + page, page, PROT_READ) == 0);
    CHECK("mprotect-rw", mprotect(m + page, page, PROT_READ | PROT_WRITE) == 0);
    CHECK("madvise-dontneed", madvise(m + 2 * page, page, MADV_DONTNEED) == 0);
    CHECK("dontneed-zeroes", m[2 * page] == 0 && m[3 * page - 1] == 0);
    CHECK("dontneed-keeps-others", m[page] == 0x5a && m[3 * page] == 0x5a);

    unsigned char vec[4];
    CHECK("munmap-middle", munmap(m + page, page) == 0);
    CHECK_ERR("mincore-hole", mincore(m, 4 * page, vec), ENOMEM);
    CHECK_ERR("mprotect-hole", mprotect(m, 4 * page, PROT_READ), ENOMEM);
    CHECK_ERR("noreplace", (long)mmap(m, page, PROT_READ,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0), EEXIST);
    unsigned char *f = mmap(m + page, page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK("map-fixed-hole", f == m + page && f[0] == 0);

    /* mremap: grow in place is impossible (next page mapped), so it moves. */
    unsigned char *g = mremap(m, page, 8 * page, MREMAP_MAYMOVE);
    CHECK("mremap-grow", g != MAP_FAILED);
    CHECK("mremap-contents", g[0] == 0x5a && g[page - 1] == 0x5a && g[8 * page - 1] == 0);
    CHECK_ERR("mremap-bad-flags", (long)mremap(g, page, page, 0x80), EINVAL);
    CHECK("munmap-g", munmap(g, 8 * page) == 0);
    CHECK("munmap-rest", munmap(m + page, 3 * page) == 0);

    CHECK_ERR("mmap-zero-len", (long)mmap(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), EINVAL);
    CHECK_ERR("mmap-no-type", (long)mmap(NULL, page, PROT_READ, MAP_ANONYMOUS, -1, 0), EINVAL);
    CHECK_ERR("mmap-bad-fd", (long)mmap(NULL, page, PROT_READ, MAP_PRIVATE, 1000, 0), EBADF);
    CHECK_ERR("munmap-unaligned", munmap((void *)1, page), EINVAL);

    /* Private file mapping: contents visible, writes stay private. */
    char path[] = "/tmp/rax-mmap-XXXXXX";
    int fd = mkstemp(path);
    CHECK("mkstemp", fd >= 0);
    char data[6000];
    for (int i = 0; i < (int)sizeof data; i++)
        data[i] = (char)('a' + i % 26);
    CHECK("file-write", write(fd, data, sizeof data) == (ssize_t)sizeof data);
    char *fm = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK("mmap-file", fm != MAP_FAILED);
    CHECK("mmap-file-contents", memcmp(fm, data, sizeof data) == 0);
    CHECK("mmap-file-tail-zero", fm[sizeof data] == 0 && fm[2 * page - 1] == 0);
    fm[0] = 'Z';
    char first;
    CHECK("private-write-not-in-file", pread(fd, &first, 1, 0) == 1 && first == 'a');
    char *fo = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, page);
    CHECK("mmap-file-offset", fo != MAP_FAILED && fo[0] == data[page]);
    CHECK_ERR("mmap-unaligned-offset", (long)mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 100), EINVAL);
    munmap(fm, 2 * page);
    munmap(fo, page);
    close(fd);
    unlink(path);
    FINISH();
}
