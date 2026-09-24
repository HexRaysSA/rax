/* memfd_create and file seals: the flag and name checks; the file's
 * status flags, mode, links, size, and /proc names; the initial seals of
 * each creation mode; each seal where it applies (ftruncate, write,
 * fallocate, mmap, mprotect, fchmod, MADV_REMOVE); F_SEAL_WRITE refused
 * while a shared mapping may write, F_SEAL_FUTURE_WRITE not; F_SEAL_EXEC
 * implying the write seals on an executable file; and the object and its
 * seals shared with a forked child. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

/* linux/memfd.h and linux/fcntl.h (Linux 6.3); older libc headers lack
 * them. */
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif

#define PG 4096

static int seals(int fd) {
    return fcntl(fd, F_GET_SEALS);
}

static void creation(void) {
    CHECK_ERR("bad-flags", memfd_create("x", 0x100), EINVAL);
    CHECK_ERR("exec-and-noexec", memfd_create("x", MFD_EXEC | MFD_NOEXEC_SEAL), EINVAL);
    char name[251];
    memset(name, 'n', 250);
    name[250] = 0;
    CHECK_ERR("name-too-long", memfd_create(name, 0), EINVAL);
    name[249] = 0;
    int ok = memfd_create(name, 0);
    CHECK("name-longest", ok >= 0);
    close(ok);
    CHECK_ERR("name-fault", memfd_create((char *)16, 0), EFAULT);
    int fd = memfd_create("test", MFD_CLOEXEC);
    struct stat st;
    CHECK("props", fd >= 0 && fcntl(fd, F_GETFL) == (O_RDWR | O_LARGEFILE) &&
                       (fcntl(fd, F_GETFD) & FD_CLOEXEC) && fstat(fd, &st) == 0 &&
                       S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0777 &&
                       st.st_nlink == 0 && st.st_size == 0);
    char link[64] = {0}, path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    readlink(path, link, sizeof link - 1);
    CHECK("proc-name", !strcmp(link, "/memfd:test (deleted)"));
    CHECK("default-seals", seals(fd) == F_SEAL_SEAL);
    CHECK_ERR("sealed-seals", fcntl(fd, F_ADD_SEALS, F_SEAL_GROW), EPERM);
    /* Data through write, lseek, and a shared mapping. */
    CHECK("data", write(fd, "hello", 5) == 5 && lseek(fd, 0, SEEK_SET) == 0);
    ftruncate(fd, PG);
    char *m = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK("mapped", m != MAP_FAILED && !memcmp(m, "hello", 5));
    m[0] = 'J';
    char c = 0;
    CHECK("mapped-store", pread(fd, &c, 1, 0) == 1 && c == 'J');
    FILE *f = fopen("/proc/self/maps", "r");
    char line[256];
    int found = 0;
    while (fgets(line, sizeof line, f))
        found |= strstr(line, " /memfd:test (deleted)") != 0;
    fclose(f);
    CHECK("maps-name", found);
    munmap(m, PG);
    close(fd);
    /* The seal commands on another file. */
    int plain = open("/dev/null", O_RDWR);
    CHECK_ERR("get-seals-plain", fcntl(plain, F_GET_SEALS), EINVAL);
    CHECK_ERR("add-seals-plain", fcntl(plain, F_ADD_SEALS, F_SEAL_GROW), EINVAL);
    close(plain);
    int ne = memfd_create("noexec", MFD_NOEXEC_SEAL);
    CHECK("noexec", fstat(ne, &st) == 0 && (st.st_mode & 0777) == 0666 &&
                        seals(ne) == F_SEAL_EXEC);
    CHECK_ERR("noexec-chmod", fchmod(ne, 0777), EPERM);
    CHECK("noexec-more-seals", fcntl(ne, F_ADD_SEALS, F_SEAL_GROW) == 0 &&
                                   seals(ne) == (F_SEAL_EXEC | F_SEAL_GROW));
    close(ne);
}

static void size_seals(void) {
    int fd = memfd_create("size", MFD_ALLOW_SEALING);
    char buf[2 * PG];
    memset(buf, 'd', sizeof buf);
    CHECK("sealable", seals(fd) == 0 && write(fd, buf, sizeof buf) == sizeof buf);
    CHECK_ERR("bad-seal", fcntl(fd, F_ADD_SEALS, 0x40), EINVAL);
    CHECK("shrink-seal", fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) == 0);
    CHECK_ERR("shrink", ftruncate(fd, PG), EPERM);
    CHECK("shrink-grow-ok", ftruncate(fd, 2 * PG) == 0 && ftruncate(fd, 2 * PG + 1) == 0);
    CHECK("grow-seal", fcntl(fd, F_ADD_SEALS, F_SEAL_GROW) == 0);
    CHECK_ERR("grow", ftruncate(fd, 3 * PG), EPERM);
    /* A write within the size goes; one past it stops at the first
     * page-sized chunk that would grow the file. */
    CHECK("grow-write-inside", pwrite(fd, buf, 1, 2 * PG) == 1);
    CHECK("grow-write-partial", pwrite(fd, buf, 20, 2 * PG - 10) == 10);
    CHECK_ERR("grow-write", pwrite(fd, buf, 1, 2 * PG + 1), EPERM);
    CHECK_ERR("grow-fallocate", fallocate(fd, 0, PG, 2 * PG), EPERM);
    CHECK_ERR("grow-fallocate-keep", fallocate(fd, FALLOC_FL_KEEP_SIZE, PG, 2 * PG), EPERM);
    CHECK("inside-fallocate", fallocate(fd, 0, 0, PG) == 0);
    close(fd);
}

static void write_seals(void) {
    int fd = memfd_create("write", MFD_ALLOW_SEALING);
    ftruncate(fd, PG);
    /* A shared mapping that may write keeps F_SEAL_WRITE off. */
    char *m = mmap(0, PG, PROT_READ, MAP_SHARED, fd, 0);
    CHECK_ERR("write-seal-busy", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE), EBUSY);
    munmap(m, PG);
    char *p = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK("write-seal", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    CHECK_ERR("sealed-write", write(fd, "x", 1), EPERM);
    CHECK_ERR("sealed-map-write", (long)mmap(0, PG, PROT_WRITE, MAP_SHARED, fd, 0), EPERM);
    char *r = mmap(0, PG, PROT_READ, MAP_SHARED, fd, 0);
    CHECK("sealed-map-read", r != MAP_FAILED);
    CHECK_ERR("sealed-mprotect", mprotect(r, PG, PROT_READ | PROT_WRITE), EACCES);
    CHECK("private-still", p != MAP_FAILED && (p[0] = 1) == 1);
    CHECK_ERR("sealed-remove-ro", madvise(r, PG, MADV_REMOVE), EACCES);
    munmap(r, PG);
    munmap(p, PG);
    close(fd);
    /* F_SEAL_FUTURE_WRITE: existing writable mappings stay. */
    fd = memfd_create("future", MFD_ALLOW_SEALING);
    ftruncate(fd, PG);
    char *w = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK("future-seal", fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0);
    w[0] = 'w';
    char c = 0;
    CHECK("future-mapping-writes", pread(fd, &c, 1, 0) == 1 && c == 'w');
    CHECK_ERR("future-write", pwrite(fd, "x", 1, 0), EPERM);
    CHECK_ERR("future-map", (long)mmap(0, PG, PROT_WRITE, MAP_SHARED, fd, 0), EPERM);
    CHECK_ERR("future-remove", madvise(w, PG, MADV_REMOVE), EPERM);
    munmap(w, PG);
    close(fd);
}

static void exec_seal(void) {
    int fd = memfd_create("exec", MFD_ALLOW_SEALING);
    CHECK("exec-seal", fcntl(fd, F_ADD_SEALS, F_SEAL_EXEC) == 0 &&
                           seals(fd) == (F_SEAL_EXEC | F_SEAL_SHRINK | F_SEAL_GROW |
                                         F_SEAL_WRITE | F_SEAL_FUTURE_WRITE));
    CHECK_ERR("exec-chmod", fchmod(fd, 0666), EPERM);
    CHECK("exec-chmod-other-bits", fchmod(fd, 0755) == 0);
    close(fd);
}

static void across_fork(void) {
    int fd = memfd_create("fork", MFD_ALLOW_SEALING);
    ftruncate(fd, PG);
    char *m = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    pid_t pid = fork();
    if (pid == 0) {
        m[7] = 'c';
        munmap(m, PG);
        _exit(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) == 0 ? 0 : 1);
    }
    int st;
    waitpid(pid, &st, 0);
    CHECK("fork-data", WIFEXITED(st) && WEXITSTATUS(st) == 0 && m[7] == 'c');
    CHECK("fork-seals", seals(fd) == F_SEAL_SHRINK);
    munmap(m, PG);
    close(fd);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    creation();
    size_seals();
    write_seals();
    exec_seal();
    across_fork();
    FINISH();
}
