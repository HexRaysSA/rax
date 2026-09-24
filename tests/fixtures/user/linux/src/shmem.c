/* Shared memory: anonymous and /dev/zero shared mappings shared with a
 * forked child (a private one not); a shared file mapping's stores in the
 * file and the file's changes in the mapping, before and after munmap,
 * from another process, and with msync; mremap duplicating a shared
 * mapping (and refusing a private one) and growing one past its object
 * (SIGBUS); MADV_REMOVE and MADV_DONTNEED on shared pages; the
 * /proc/self/maps line of shared anonymous memory; and a page past a
 * truncated end (SIGBUS). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define PG 4096

static sigjmp_buf jb;
static volatile sig_atomic_t buses;
static void on_bus(int sig) {
    (void)sig;
    buses++;
    siglongjmp(jb, 1);
}

/* Whether reading *p raises SIGBUS. */
static int bus_on_read(volatile char *p) {
    if (sigsetjmp(jb, 1))
        return 1;
    (void)*p;
    return 0;
}

/* The child writes `v` at p[off] and exits; the parent waits. */
static void child_writes(volatile char *p, int off, char v) {
    pid_t pid = fork();
    if (pid == 0) {
        p[off] = v;
        _exit(0);
    }
    waitpid(pid, 0, 0);
}

static void forking(void) {
    char *s = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK("anon-zero", s != MAP_FAILED && s[100] == 0);
    child_writes(s, 100, 42);
    CHECK("anon-shared", s[100] == 42);
    int z = open("/dev/zero", O_RDWR);
    char *d = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED, z, 0);
    close(z);
    child_writes(d, 7, 9);
    CHECK("devzero-shared", d != MAP_FAILED && d[7] == 9);
    char *pv = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pv[5] = 1;
    child_writes(pv, 5, 2);
    CHECK("private-copied", pv[5] == 1);
    /* Parent's stores reach the child too. */
    s[200] = 77;
    pid_t pid = fork();
    if (pid == 0)
        _exit(s[200] == 77 ? 0 : 1);
    int st;
    CHECK("anon-to-child", waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    munmap(s, PG);
    munmap(d, PG);
    munmap(pv, PG);
}

static char path[64];

static void file_mapping(void) {
    snprintf(path, sizeof path, "/tmp/rax-shmem-%d", getpid());
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    char page[2 * PG];
    memset(page, 'a', sizeof page);
    write(fd, page, sizeof page);
    char *m = mmap(0, 2 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK("file-map", m != MAP_FAILED && m[PG] == 'a');
    /* Stores in the file; the file's changes in the mapping. */
    m[3] = 'X';
    char c = 0;
    CHECK("store-to-file", pread(fd, &c, 1, 3) == 1 && c == 'X');
    pwrite(fd, "Y", 1, PG + 1);
    CHECK("file-to-mapping", m[PG + 1] == 'Y');
    CHECK("msync", msync(m, 2 * PG, MS_SYNC) == 0 && msync(m, PG, MS_ASYNC) == 0);
    /* Another process's stores through its own mapping. */
    pid_t pid = fork();
    if (pid == 0) {
        char *n = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PG);
        n[10] = 'Z';
        _exit(0);
    }
    waitpid(pid, 0, 0);
    CHECK("other-process", m[PG + 10] == 'Z');
    /* A second mapping of the same pages in this process. */
    char *again = mmap(0, PG, PROT_READ, MAP_SHARED, fd, PG);
    CHECK("second-mapping", again != MAP_FAILED && again[1] == 'Y' && again[10] == 'Z');
    m[PG + 20] = 'W';
    CHECK("second-sees", again[20] == 'W');
    munmap(again, PG);
    /* The stores stay after unmapping and closing. */
    m[4] = 'V';
    munmap(m, 2 * PG);
    close(fd);
    fd = open(path, O_RDONLY);
    char back[8] = {0};
    CHECK("after-munmap", pread(fd, back, 5, 0) == 5 && !memcmp(back, "aaaXV", 5));
    /* A read-only file maps shared only for reading. */
    CHECK_ERR("ro-shared-write",
              (long)mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0), EACCES);
    char *r = mmap(0, PG, PROT_READ, MAP_SHARED, fd, 0);
    CHECK("ro-shared-read", r != MAP_FAILED && r[3] == 'X');
    CHECK_ERR("ro-mprotect", mprotect(r, PG, PROT_READ | PROT_WRITE), EACCES);
    munmap(r, PG);
    close(fd);
}

static void remapping(void) {
    char *s = mmap(0, 2 * PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    /* old_len 0: a second mapping of the same pages. */
    char *dup = mremap(s, 0, PG, MREMAP_MAYMOVE);
    CHECK("dup", dup != MAP_FAILED && dup != s);
    dup[1] = 5;
    CHECK("dup-shares", s[1] == 5);
    CHECK_ERR("dup-no-move", (long)mremap(s, 0, PG, 0), ENOMEM);
    char *p = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK_ERR("dup-private", (long)mremap(p, 0, PG, MREMAP_MAYMOVE), EINVAL);
    /* Grown past its object: the new pages are a bus error. */
    char *g = mremap(s, 2 * PG, 4 * PG, MREMAP_MAYMOVE);
    CHECK("grow", g != MAP_FAILED && g[1] == 5 && !bus_on_read(g + PG));
    CHECK("grow-sigbus", bus_on_read(g + 3 * PG) && buses == 1);
    /* MADV_DONTNEED keeps shared contents; MADV_REMOVE zeroes them. */
    g[PG] = 8;
    CHECK("dontneed", madvise(g, 2 * PG, MADV_DONTNEED) == 0 && g[1] == 5 && g[PG] == 8);
    CHECK("remove", madvise(g, PG, MADV_REMOVE) == 0 && g[1] == 0 && dup[1] == 0 &&
                        g[PG] == 8);
    CHECK_ERR("remove-private", madvise(p, PG, MADV_REMOVE), EINVAL);
    munmap(dup, PG);
    munmap(g, 4 * PG);
    munmap(p, PG);
}

static void maps_line(void) {
    char *s = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    char want[32];
    snprintf(want, sizeof want, "%lx-", (unsigned long)s);
    FILE *f = fopen("/proc/self/maps", "r");
    char line[256];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, want, strlen(want)))
            found = strstr(line, " rw-s 00000000 00:01 ") && strstr(line, " /dev/zero (deleted)");
    }
    fclose(f);
    CHECK("maps-shmem", found);
    munmap(s, PG);
}

static void truncation(void) {
    int fd = open(path, O_RDWR | O_TRUNC);
    char page[2 * PG];
    memset(page, 'b', sizeof page);
    write(fd, page, sizeof page);
    char *m = mmap(0, 2 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK("trunc-before", m[PG] == 'b');
    /* Truncated to one page and a bit: the second page's first bytes are
     * zero beyond the end, the rest still mapped; truncated to one page,
     * the second is a bus error. */
    ftruncate(fd, PG + 10);
    CHECK("trunc-partial", m[PG + 9] == 'b' && m[PG + 10] == 0 && !bus_on_read(m + PG + 100));
    ftruncate(fd, PG);
    CHECK("trunc-sigbus", bus_on_read(m + PG) && buses == 2 && m[0] == 'b');
    munmap(m, 2 * PG);
    close(fd);
    unlink(path);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction sa = {.sa_handler = on_bus, .sa_flags = SA_NODEFER};
    sigaction(SIGBUS, &sa, 0);
    forking();
    file_mapping();
    remapping();
    maps_line();
    truncation();
    FINISH();
}
