// POSIX shared memory: creating, opening, sizing once, mapping (shared
// only, within the object, writable only through a writable
// descriptor), sharing between mappings and with a forked child, the
// name and flag checks, permissions, close-on-exec, and unlinking.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void show(const char *what, long r) { printf("%s: %ld errno=%d\n", what, r, r < 0 ? errno : 0); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char name[32], other[32];
    snprintf(name, sizeof name, "/rax-shm-%d", getpid());
    snprintf(other, sizeof other, "/rax-shm-o-%d", getpid());
    shm_unlink(name);
    errno = 0;
    show("open missing", shm_open(name, O_RDWR, 0));
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    printf("create: %d cloexec=%d getfl=%#x\n", fd >= 0, fcntl(fd, F_GETFD), fcntl(fd, F_GETFL));
    errno = 0;
    show("create again exclusive", shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600));
    struct stat st;
    fstat(fd, &st);
    printf("fstat: type=%o perm=%o size=%lld\n", st.st_mode & S_IFMT, st.st_mode & 07777, (long long)st.st_size);
    errno = 0;
    show("map unsized", (long)(mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED ? -1 : 0));
    show("ftruncate", ftruncate(fd, 5000));
    fstat(fd, &st);
    printf("sized: %d\n", st.st_size >= 5000);
    errno = 0;
    show("ftruncate again", ftruncate(fd, 100000));
    errno = 0;
    show("truncate on open", shm_open(name, O_RDWR | O_TRUNC, 0));

    char *p = mmap(NULL, 5000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("map: %d\n", p != MAP_FAILED);
    strcpy(p, "shared hello");
    errno = 0;
    show("map private", (long)(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED ? -1 : 0));
    errno = 0;
    show("map too large", (long)(mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED ? -1 : 0));
    errno = 0;
    show("map past end", (long)(mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 1 << 20) == MAP_FAILED ? -1 : 0));
    errno = 0;
    show("map exec", (long)(mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0) == MAP_FAILED ? -1 : 0));
    char buf[8];
    errno = 0;
    show("read", read(fd, buf, sizeof buf));

    int ro = shm_open(name, O_RDONLY, 0);
    char *q = mmap(NULL, 5000, PROT_READ, MAP_SHARED, ro, 0);
    printf("second mapping sees: %s\n", q);
    errno = 0;
    show("write map through read-only", (long)(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0) == MAP_FAILED ? -1 : 0));
    pid_t c = fork();
    if (c == 0) {
        strcpy(p, "from the child");
        int again = shm_open(name, O_RDWR, 0);
        char *r = mmap(NULL, 5000, PROT_READ | PROT_WRITE, MAP_SHARED, again, 0);
        r[100] = 'x';
        _exit(0);
    }
    waitpid(c, NULL, 0);
    printf("after child: %s [%c]\n", q, q[100]);

    // Two objects are two objects.
    int fo = shm_open(other, O_RDWR | O_CREAT, 0600);
    ftruncate(fo, 4096);
    char *o = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fo, 0);
    strcpy(o, "other");
    printf("objects apart: %s / %s\n", q, o);

    char locked[32];
    snprintf(locked, sizeof locked, "/rax-shm-r-%d", getpid());
    close(shm_open(locked, O_RDONLY | O_CREAT, 0400));
    char long_name[64];
    memset(long_name, 'n', sizeof long_name - 1);
    long_name[0] = '/';
    long_name[sizeof long_name - 1] = 0;
    errno = 0;
    show("name too long", shm_open(long_name, O_RDWR | O_CREAT, 0600));
    errno = 0;
    show("empty name", shm_open("", O_RDWR | O_CREAT, 0600));
    errno = 0;
    show("bad name pointer", shm_open((const char *)8, O_RDWR, 0));
    errno = 0;
    show("undocumented flag", shm_open(name, O_RDWR | O_APPEND, 0));
    errno = 0;
    show("write-only", shm_open(name, O_WRONLY, 0) >= 0 ? 0 : -1);
    errno = 0;
    show("read-only object opened for writing", shm_open(locked, O_RDWR, 0) >= 0 ? 0 : -1);
    shm_unlink(locked);
    show("unlink", shm_unlink(name));
    errno = 0;
    show("unlink again", shm_unlink(name));
    printf("still mapped after unlink: %s\n", q);
    shm_unlink(other);
    return 0;
}
