// Access control lists through the *_extended calls: setting a list
// (chmod_extended, fchmod_extended, and at creation: open_extended,
// mkdir_extended, mkfifo_extended), removing it, reading it back with the
// status (stat64_extended, lstat64_extended, fstat64_extended; the size
// written back whether or not the buffer holds the list), umask_extended,
// and the checks, the list copied in before the path is looked up.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYS_open_extended 277
#define SYS_umask_extended 278
#define SYS_chmod_extended 282
#define SYS_fchmod_extended 283
#define SYS_mkfifo_extended 291
#define SYS_mkdir_extended 292
#define SYS_stat64_extended 341
#define SYS_lstat64_extended 342
#define SYS_fstat64_extended 343
#define ID_NONE (~0u - 100)

struct ace {
    uint8_t who[16];
    uint32_t flags, rights;
};
struct filesec {
    uint32_t magic;
    uint8_t owner[16], group[16];
    uint32_t count, flags;
    struct ace ace[4];
};

static struct filesec make(uint32_t count, uint32_t rights) {
    struct filesec f;
    memset(&f, 0, sizeof f);
    f.magic = 0x012cc16d;
    f.count = count;
    for (uint32_t i = 0; i < count && i < 4; i++) {
        // The uid's well-known GUID: FFFFEEEE-DDDD-CCCC-BBBB-AAAA<uid>.
        uint8_t g[16] = {0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa};
        uint32_t uid = getuid() + i;
        g[12] = uid >> 24;
        g[13] = uid >> 16;
        g[14] = uid >> 8;
        g[15] = uid;
        memcpy(f.ace[i].who, g, 16);
        f.ace[i].flags = 1; // KAUTH_ACE_PERMIT
        f.ace[i].rights = rights;
    }
    return f;
}

static void show(const char *what, long r) { printf("%s: %ld errno=%d\n", what, r, r < 0 ? errno : 0); }

static void read_back(const char *what, int sys, long target) {
    struct stat st;
    struct filesec f;
    memset(&f, 0x55, sizeof f);
    size_t size = 0;
    errno = 0;
    long r = syscall(sys, target, &st, &f, &size);
    printf("%s: %ld errno=%d size query=%zu", what, r, r < 0 ? errno : 0, size);
    size = sizeof f;
    r = syscall(sys, target, &st, &f, &size);
    printf(" size=%zu", size);
    if (size > 0) {
        printf(" magic=%#x count=%u", f.magic, f.count);
        for (uint32_t i = 0; f.count != 0xffffffff && i < f.count && i < 4; i++) {
            printf(" [%02x..%02x%02x flags=%u rights=%#x]", f.ace[i].who[0], f.ace[i].who[14], f.ace[i].who[15],
                   f.ace[i].flags, f.ace[i].rights);
        }
    }
    printf(" mode=%o\n", st.st_mode & 07777);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char dir[] = "/tmp/rax-acl-XXXXXX";
    mkdtemp(dir);
    char file[256], link[256], sub[256], fifo[256], made[256];
    snprintf(file, sizeof file, "%s/f", dir);
    snprintf(link, sizeof link, "%s/l", dir);
    snprintf(sub, sizeof sub, "%s/d", dir);
    snprintf(fifo, sizeof fifo, "%s/p", dir);
    snprintf(made, sizeof made, "%s/o", dir);
    close(open(file, O_CREAT | O_WRONLY, 0644));
    symlink(file, link);

    read_back("no list", SYS_stat64_extended, (long)file);
    struct filesec one = make(1, 1 << 1);
    show("chmod_extended", syscall(SYS_chmod_extended, file, ID_NONE, ID_NONE, -1, &one));
    read_back("one entry", SYS_stat64_extended, (long)file);
    show("chmod_extended mode only", syscall(SYS_chmod_extended, file, ID_NONE, ID_NONE, 0600, NULL));
    read_back("mode changed, list kept", SYS_stat64_extended, (long)file);
    read_back("through the link", SYS_stat64_extended, (long)link);
    read_back("the link itself", SYS_lstat64_extended, (long)link);
    int fd = open(file, O_RDONLY);
    struct filesec two = make(2, (1 << 1) | (1 << 2));
    show("fchmod_extended", syscall(SYS_fchmod_extended, fd, ID_NONE, ID_NONE, -1, &two));
    read_back("descriptor", SYS_fstat64_extended, fd);
    show("remove list", syscall(SYS_chmod_extended, file, ID_NONE, ID_NONE, -1, (void *)1));
    read_back("removed", SYS_stat64_extended, (long)file);

    long nfd = syscall(SYS_open_extended, made, O_CREAT | O_WRONLY | O_EXCL, ID_NONE, ID_NONE, 0640, &one);
    printf("open_extended: %d\n", nfd >= 0);
    read_back("created with a list", SYS_fstat64_extended, nfd);
    show("mkdir_extended", syscall(SYS_mkdir_extended, sub, ID_NONE, ID_NONE, 0750, &two));
    read_back("directory", SYS_stat64_extended, (long)sub);
    show("mkfifo_extended", syscall(SYS_mkfifo_extended, fifo, ID_NONE, ID_NONE, 0600, NULL));
    read_back("fifo", SYS_lstat64_extended, (long)fifo);
    long old = syscall(SYS_umask_extended, 027, NULL);
    printf("umask_extended: old=%lo now=%o\n", old, umask(022));

    struct filesec bad = make(1, 2);
    bad.magic = 1;
    errno = 0;
    show("bad magic", syscall(SYS_chmod_extended, file, ID_NONE, ID_NONE, -1, &bad));
    struct filesec many = make(1, 2);
    many.count = 129;
    errno = 0;
    show("too many entries", syscall(SYS_chmod_extended, file, ID_NONE, ID_NONE, -1, &many));
    errno = 0;
    show("bad list pointer", syscall(SYS_chmod_extended, file, ID_NONE, ID_NONE, -1, (void *)8));
    errno = 0;
    show("bad list pointer, missing path",
         syscall(SYS_chmod_extended, "/nonexistent/x", ID_NONE, ID_NONE, -1, (void *)8));
    errno = 0;
    show("missing path", syscall(SYS_chmod_extended, "/nonexistent/x", ID_NONE, ID_NONE, -1, &one));
    struct stat st;
    struct filesec f;
    errno = 0;
    show("bad size pointer", syscall(SYS_stat64_extended, file, &st, &f, (void *)8));
    errno = 0;
    show("bad stat buffer", syscall(SYS_stat64_extended, file, (void *)8, NULL, NULL));

    unlink(link);
    unlink(file);
    unlink(made);
    unlink(fifo);
    rmdir(sub);
    rmdir(dir);
    return 0;
}
