/* Machine administration without privilege (Linux 6.19): each call's
 * checks in the kernel's order up to its capability check, which fails
 * with EPERM. Swap (mm/swapfile.c), reboot, accounting, the host and
 * domain names, vhangup, modules (kernel/module/main.c), kexec (absent,
 * as in the reference kernel), the kernel log with dmesg_restrict
 * (kernel/printk/printk.c), chroot (fs/open.c), setting and adjusting the
 * clocks (kernel/time/time.c, posix-timers.c, timekeeping.c), mounts
 * (fs/namespace.c, fs/fsopen.c), and open_tree without a clone, which needs
 * no privilege. Root drops to nobody first; the NTP state is printed only
 * where it does not depend on the machine.
 *
 * The cases are those on which Linux 6.19, the kernel modelled, and later
 * kernels agree. Linux 7.0 checks settimeofday's microseconds against a
 * whole second before reading the zone (commit ce4abda5e126), looks up
 * pivot_root's paths before may_mount, and adds OPEN_TREE_NAMESPACE
 * (open_tree flag 2). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

/* Numbers musl's headers may lack: the same in every table since the
 * tables were unified. */
#define NR_open_tree 428
#define NR_move_mount 429
#define NR_fsopen 430
#define NR_fsconfig 431
#define NR_fsmount 432
#define NR_fspick 433
#define NR_mount_setattr 442
#define NR_open_tree_attr 467

#define BAD ((void *)16)
#define MISSING "/nonexistent-rax-user-admin"
#define OPEN_TREE_CLONE 1
#define AT_RECURSIVE 0x8000
#define MS_NOUSER_FLAG (1UL << 31)
#define UMOUNT_NOFOLLOW_FLAG 8
#define FSCONFIG_SET_FLAG 0
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_SET_BINARY 2
#define FSCONFIG_CMD_CREATE 6
/* linux/time64.h: TIME_SETTOD_SEC_MAX. */
#define SETTOD_SEC_MAX (9223372036LL - 946080000LL)
/* linux/timex.h: the adjtime bits as the kernel splits them. */
#define K_ADJ_ADJTIME 0x8000
#define K_ADJ_SETOFFSET 0x0100
/* MAKE_PROCESS_CPUCLOCK and MAKE_THREAD_CPUCLOCK with CPUCLOCK_SCHED. */
#define PROCESS_CLOCK(pid) ((clockid_t)((~(unsigned)(pid)) << 3) | 2)
#define THREAD_CLOCK(tid) ((clockid_t)((~(unsigned)(tid)) << 3) | 6)
/* A process ID no process has (PID_MAX_LIMIT less 1). */
#define NO_PID 4194303
/* FD_TO_CLOCKID. */
#define FD_CLOCK(fd) ((clockid_t)((~(unsigned)(fd)) << 3) | 3)

static char dir[64];
static char file[80];
static char dangling[80];

static long sys(long nr, long a, long b, long c, long d, long e) {
    return syscall(nr, a, b, c, d, e);
}

static long swapon_call(const char *path, int flags) {
    return syscall(SYS_swapon, path, flags);
}

static void machine(void) {
    CHECK_ERR("swapon-flags-first", swapon_call("/", 0x80000), EINVAL);
    CHECK_ERR("swapon", swapon_call("/", 0x7ffff), EPERM);
    CHECK_ERR("swapoff-before-name", syscall(SYS_swapoff, BAD), EPERM);
    CHECK_ERR("reboot-before-magic", syscall(SYS_reboot, 0, 0, 0, BAD), EPERM);
    CHECK_ERR("acct-off", syscall(SYS_acct, NULL), EPERM);
    CHECK_ERR("acct-before-name", syscall(SYS_acct, BAD), EPERM);
    CHECK_ERR("sethostname-before-length", syscall(SYS_sethostname, BAD, -1), EPERM);
    CHECK_ERR("setdomainname-before-length", syscall(SYS_setdomainname, BAD, 65), EPERM);
    CHECK_ERR("vhangup", syscall(SYS_vhangup), EPERM);
    CHECK_ERR("init-module-before-image", syscall(SYS_init_module, BAD, 0, BAD), EPERM);
    CHECK_ERR("finit-module-before-flags", syscall(SYS_finit_module, -1, BAD, -1), EPERM);
    CHECK_ERR("delete-module-before-name", syscall(SYS_delete_module, BAD, 0), EPERM);
    CHECK_ERR("kexec-load-absent", syscall(SYS_kexec_load, 0, 0, NULL, 0), ENOSYS);
    int restrict_fd = open("/proc/sys/kernel/dmesg_restrict", O_RDONLY);
    char b[8] = {0};
    CHECK("dmesg-restrict", restrict_fd >= 0 && read(restrict_fd, b, sizeof b) == 2 && !strcmp(b, "1\n"));
    close(restrict_fd);
    CHECK_ERR("syslog-close", syscall(SYS_syslog, 0, BAD, 0), EPERM);
    CHECK_ERR("syslog-read-all", syscall(SYS_syslog, 3, BAD, 0), EPERM);
    CHECK_ERR("syslog-size", syscall(SYS_syslog, 10, NULL, 0), EPERM);
    CHECK_ERR("syslog-unknown", syscall(SYS_syslog, 99, NULL, 0), EPERM);
    CHECK_ERR("chroot-fault", syscall(SYS_chroot, BAD), EFAULT);
    CHECK_ERR("chroot-missing", syscall(SYS_chroot, MISSING), ENOENT);
    CHECK_ERR("chroot-not-directory", syscall(SYS_chroot, file), ENOTDIR);
    CHECK_ERR("chroot-proc-file", syscall(SYS_chroot, "/proc/self/stat"), ENOTDIR);
    CHECK_ERR("chroot", syscall(SYS_chroot, "/"), EPERM);
    CHECK_ERR("chroot-proc-link", syscall(SYS_chroot, "/proc/self"), EPERM);
}

static void clocks(void *ro) {
    struct timeval tv;
    struct timezone tz = {15 * 60 + 1, 0};
    CHECK_ERR("settimeofday-nothing", syscall(SYS_settimeofday, NULL, NULL), EPERM);
    CHECK_ERR("settimeofday-fault", syscall(SYS_settimeofday, BAD, NULL), EFAULT);
    tv = (struct timeval){1, -1};
    CHECK_ERR("settimeofday-negative-usec", syscall(SYS_settimeofday, &tv, BAD), EINVAL);
    tv = (struct timeval){1, 1000001};
    CHECK_ERR("settimeofday-usec-over", syscall(SYS_settimeofday, &tv, BAD), EINVAL);
    tv = (struct timeval){1, 999999};
    CHECK_ERR("settimeofday-zone-fault", syscall(SYS_settimeofday, &tv, BAD), EFAULT);
    tv = (struct timeval){1, 1000000};
    CHECK_ERR("settimeofday-whole-second", syscall(SYS_settimeofday, &tv, NULL), EINVAL);
    tv = (struct timeval){-1, 0};
    CHECK_ERR("settimeofday-negative", syscall(SYS_settimeofday, &tv, NULL), EINVAL);
    tv = (struct timeval){SETTOD_SEC_MAX, 0};
    CHECK_ERR("settimeofday-too-late", syscall(SYS_settimeofday, &tv, NULL), EINVAL);
    tv = (struct timeval){SETTOD_SEC_MAX - 1, 0};
    CHECK_ERR("settimeofday-latest", syscall(SYS_settimeofday, &tv, NULL), EPERM);
    CHECK_ERR("settimeofday-zone-after-capability", syscall(SYS_settimeofday, NULL, &tz), EPERM);

    struct timespec ts = {1700000000, 0};
    struct timespec bad_ts = {1, 1000000000};
    CHECK_ERR("settime-monotonic", syscall(SYS_clock_settime, CLOCK_MONOTONIC, BAD), EINVAL);
    CHECK_ERR("settime-process-cputime", syscall(SYS_clock_settime, CLOCK_PROCESS_CPUTIME_ID, &ts), EINVAL);
    CHECK_ERR("settime-tai", syscall(SYS_clock_settime, CLOCK_TAI, &ts), EINVAL);
    CHECK_ERR("settime-unknown", syscall(SYS_clock_settime, 10, &ts), EINVAL);
    CHECK_ERR("settime-fault", syscall(SYS_clock_settime, CLOCK_REALTIME, BAD), EFAULT);
    CHECK_ERR("settime-invalid", syscall(SYS_clock_settime, CLOCK_REALTIME, &bad_ts), EINVAL);
    CHECK_ERR("settime-realtime", syscall(SYS_clock_settime, CLOCK_REALTIME, &ts), EPERM);
    CHECK_ERR("settime-cpu-self-fault", syscall(SYS_clock_settime, PROCESS_CLOCK(0), BAD), EFAULT);
    CHECK_ERR("settime-cpu-self", syscall(SYS_clock_settime, PROCESS_CLOCK(0), &ts), EPERM);
    CHECK_ERR("settime-cpu-pid", syscall(SYS_clock_settime, PROCESS_CLOCK(getpid()), &ts), EPERM);
    CHECK_ERR("settime-cpu-thread", syscall(SYS_clock_settime, THREAD_CLOCK(gettid()), &ts), EPERM);
    CHECK_ERR("settime-cpu-none", syscall(SYS_clock_settime, PROCESS_CLOCK(NO_PID), &ts), EINVAL);
    CHECK_ERR("settime-clock-device", syscall(SYS_clock_settime, FD_CLOCK(0), &ts), EINVAL);

    struct timex tx;
    memset(&tx, 0, sizeof tx);
    int state = syscall(SYS_adjtimex, &tx);
    CHECK("adjtimex-read", state >= 0 && state <= 5 && tx.precision == 1 &&
                               tx.tolerance == 500L << 16 && tx.tick == 10000);
    memset(&tx, 0, sizeof tx);
    tx.modes = ADJ_OFFSET_SS_READ;
    state = syscall(SYS_adjtimex, &tx);
    CHECK("adjtimex-read-adjtime", state >= 0 && state <= 5 && tx.tick == 10000);
    CHECK_ERR("adjtimex-fault", syscall(SYS_adjtimex, BAD), EFAULT);
    tx.modes = K_ADJ_ADJTIME;
    CHECK_ERR("adjtimex-adjtime-alone", syscall(SYS_adjtimex, &tx), EINVAL);
    tx.modes = ADJ_OFFSET_SINGLESHOT;
    CHECK_ERR("adjtimex-adjtime", syscall(SYS_adjtimex, &tx), EPERM);
    tx.modes = ADJ_OFFSET;
    CHECK_ERR("adjtimex-offset", syscall(SYS_adjtimex, &tx), EPERM);
    tx.modes = ADJ_TICK;
    tx.tick = 5;
    CHECK_ERR("adjtimex-tick-after-capability", syscall(SYS_adjtimex, &tx), EPERM);
    tx.modes = ADJ_OFFSET_SS_READ | K_ADJ_SETOFFSET;
    CHECK_ERR("adjtimex-read-setoffset", syscall(SYS_adjtimex, &tx), EPERM);
    tx.modes = ADJ_OFFSET_SS_READ | ADJ_FREQUENCY;
    tx.freq = INT64_MAX / (1000L << 16) + 1;
    CHECK_ERR("adjtimex-read-frequency", syscall(SYS_adjtimex, &tx), EINVAL);
    /* The structure is written back whatever the result. */
    CHECK_ERR("adjtimex-refused-read-only", syscall(SYS_adjtimex, ro), EFAULT);
    memset(&tx, 0, sizeof tx);
    CHECK_ERR("adjtime-monotonic", syscall(SYS_clock_adjtime, CLOCK_MONOTONIC, &tx), EOPNOTSUPP);
    CHECK_ERR("adjtime-cpu", syscall(SYS_clock_adjtime, PROCESS_CLOCK(0), &tx), EOPNOTSUPP);
    CHECK_ERR("adjtime-unknown", syscall(SYS_clock_adjtime, 10, &tx), EINVAL);
    CHECK_ERR("adjtime-clock-device", syscall(SYS_clock_adjtime, FD_CLOCK(0), &tx), EINVAL);
    CHECK_ERR("adjtime-fault", syscall(SYS_clock_adjtime, CLOCK_MONOTONIC, BAD), EFAULT);
    /* Unlike adjtimex, an error is not written back. */
    CHECK_ERR("adjtime-refused-read-only", syscall(SYS_clock_adjtime, CLOCK_REALTIME, ro), EPERM);
    state = syscall(SYS_clock_adjtime, CLOCK_REALTIME, &tx);
    CHECK("adjtime-read", state >= 0 && state <= 5 && tx.tick == 10000);
}

static void mounts(void) {
    static char long_type[4097];
    memset(long_type, 't', 4096);
    CHECK_ERR("mount-type-fault", syscall(SYS_mount, NULL, "/", BAD, 0, NULL), EFAULT);
    CHECK_ERR("mount-type-too-long", syscall(SYS_mount, NULL, "/", long_type, 0, NULL), EINVAL);
    CHECK_ERR("mount-device-fault", syscall(SYS_mount, BAD, "/", NULL, 0, NULL), EFAULT);
    CHECK_ERR("mount-options-fault", syscall(SYS_mount, NULL, "/", NULL, 0, BAD), EFAULT);
    CHECK_ERR("mount-point-fault", syscall(SYS_mount, NULL, BAD, NULL, 0, NULL), EFAULT);
    CHECK_ERR("mount-point-missing", syscall(SYS_mount, NULL, MISSING, NULL, 0, NULL), ENOENT);
    CHECK_ERR("mount-nouser", syscall(SYS_mount, NULL, "/", NULL, MS_NOUSER_FLAG, NULL), EINVAL);
    CHECK_ERR("mount-magic", syscall(SYS_mount, NULL, "/", NULL, 0xc0ed0000UL, NULL), EPERM);
    CHECK_ERR("mount", syscall(SYS_mount, "none", "/", "tmpfs", 0, NULL), EPERM);
    CHECK_ERR("umount-flags", syscall(SYS_umount2, "/", 16), EINVAL);
    CHECK_ERR("umount-missing", syscall(SYS_umount2, MISSING, 0), ENOENT);
    CHECK_ERR("umount-dangling", syscall(SYS_umount2, dangling, 0), ENOENT);
    CHECK_ERR("umount-nofollow", syscall(SYS_umount2, dangling, UMOUNT_NOFOLLOW_FLAG), EPERM);
    CHECK_ERR("umount", syscall(SYS_umount2, "/", 0), EPERM);
    CHECK_ERR("pivot-root", syscall(SYS_pivot_root, "/", "/"), EPERM);
    CHECK_ERR("move-mount", sys(NR_move_mount, -1, (long)BAD, -1, (long)BAD, -1), EPERM);
    CHECK_ERR("fsopen", sys(NR_fsopen, (long)BAD, -1, 0, 0, 0), EPERM);
    CHECK_ERR("fspick", sys(NR_fspick, -1, (long)BAD, -1, 0, 0), EPERM);
    CHECK_ERR("fsmount", sys(NR_fsmount, -1, -1, -1, 0, 0), EPERM);

    int d = open("/", O_RDONLY | O_DIRECTORY);
    int p = open("/", O_PATH);
    CHECK_ERR("fsconfig-negative", sys(NR_fsconfig, -1, FSCONFIG_SET_FLAG, (long)"k", 0, 0), EINVAL);
    CHECK_ERR("fsconfig-command", sys(NR_fsconfig, 99, 9, 0, 0, 0), EOPNOTSUPP);
    CHECK_ERR("fsconfig-flag-key", sys(NR_fsconfig, 99, FSCONFIG_SET_FLAG, 0, 0, 0), EINVAL);
    CHECK_ERR("fsconfig-string-value", sys(NR_fsconfig, 99, FSCONFIG_SET_STRING, (long)"k", 0, 0), EINVAL);
    CHECK_ERR("fsconfig-binary-size", sys(NR_fsconfig, 99, FSCONFIG_SET_BINARY, (long)"k", (long)"v", 0), EINVAL);
    CHECK_ERR("fsconfig-create-key", sys(NR_fsconfig, 99, FSCONFIG_CMD_CREATE, (long)"k", 0, 0), EINVAL);
    CHECK_ERR("fsconfig-closed", sys(NR_fsconfig, 99, FSCONFIG_SET_FLAG, (long)"k", 0, 0), EBADF);
    CHECK_ERR("fsconfig-path-only", sys(NR_fsconfig, p, FSCONFIG_SET_FLAG, (long)"k", 0, 0), EBADF);
    CHECK_ERR("fsconfig-not-context", sys(NR_fsconfig, d, FSCONFIG_SET_FLAG, (long)"k", 0, 0), EINVAL);

    /* open_tree without a clone: an O_PATH open. */
    int t = sys(NR_open_tree, AT_FDCWD, (long)file, O_CLOEXEC, 0, 0);
    struct stat st;
    CHECK("open-tree", t >= 0 && fcntl(t, F_GETFL) == O_PATH && fcntl(t, F_GETFD) == FD_CLOEXEC &&
                           fstat(t, &st) == 0 && S_ISREG(st.st_mode));
    CHECK_ERR("open-tree-no-read", read(t, &st, 1), EBADF);
    close(t);
    CHECK_ERR("open-tree-dangling", sys(NR_open_tree, AT_FDCWD, (long)dangling, 0, 0, 0), ENOENT);
    t = sys(NR_open_tree, AT_FDCWD, (long)dangling, AT_SYMLINK_NOFOLLOW, 0, 0);
    CHECK("open-tree-link", t >= 0 && fcntl(t, F_GETFL) == O_PATH && fcntl(t, F_GETFD) == 0 &&
                                fstat(t, &st) == 0 && S_ISLNK(st.st_mode));
    close(t);
    int rw = open(file, O_RDONLY);
    t = sys(NR_open_tree, rw, (long)"", AT_EMPTY_PATH, 0, 0);
    CHECK("open-tree-empty-path", t >= 0 && fcntl(t, F_GETFL) == O_PATH && fcntl(rw, F_GETFL) != O_PATH);
    close(t);
    CHECK_ERR("open-tree-empty", sys(NR_open_tree, rw, (long)"", 0, 0, 0), ENOENT);
    CHECK_ERR("open-tree-flags", sys(NR_open_tree, AT_FDCWD, (long)file, 4, 0, 0), EINVAL);
    CHECK_ERR("open-tree-recursive", sys(NR_open_tree, AT_FDCWD, (long)file, AT_RECURSIVE, 0, 0), EINVAL);
    CHECK_ERR("open-tree-clone", sys(NR_open_tree, AT_FDCWD, (long)MISSING, OPEN_TREE_CLONE, 0, 0), EPERM);

    uint64_t attr[5] = {1, 0, 0, 0, 0};
    CHECK_ERR("open-tree-attr-size-alone", sys(NR_open_tree_attr, AT_FDCWD, (long)file, 0, 0, 8), EINVAL);
    t = sys(NR_open_tree_attr, AT_FDCWD, (long)file, 0, 0, 0);
    CHECK("open-tree-attr-none", t >= 0 && fcntl(t, F_GETFL) == O_PATH);
    CHECK_ERR("open-tree-attr-lookup-first", sys(NR_open_tree_attr, AT_FDCWD, (long)MISSING, 0, (long)BAD, 4097),
              ENOENT);
    CHECK_ERR("open-tree-attr-too-big", sys(NR_open_tree_attr, AT_FDCWD, (long)file, 0, (long)BAD, 4097), E2BIG);
    CHECK_ERR("open-tree-attr-too-small", sys(NR_open_tree_attr, AT_FDCWD, (long)file, 0, (long)BAD, 31), EINVAL);
    int next = dup(d);
    close(next);
    CHECK_ERR("open-tree-attr", sys(NR_open_tree_attr, AT_FDCWD, (long)file, 0, (long)attr, 32), EPERM);
    /* The refused descriptor was never published. */
    int again = dup(d);
    CHECK("open-tree-attr-unpublished", again == next);
    close(again);
    close(t);
    CHECK_ERR("mount-setattr-flags", sys(NR_mount_setattr, AT_FDCWD, (long)BAD, 1, (long)BAD, 0), EINVAL);
    CHECK_ERR("mount-setattr-too-big", sys(NR_mount_setattr, AT_FDCWD, (long)BAD, 0, (long)BAD, 4097), E2BIG);
    CHECK_ERR("mount-setattr-too-small", sys(NR_mount_setattr, AT_FDCWD, (long)BAD, 0, (long)BAD, 31), EINVAL);
    CHECK_ERR("mount-setattr", sys(NR_mount_setattr, AT_FDCWD, (long)BAD, 0, (long)BAD, 40), EPERM);

    /* A descriptor is taken before open_tree checks anything. */
    struct rlimit lim;
    getrlimit(RLIMIT_NOFILE, &lim);
    int low = dup(d);
    close(low);
    struct rlimit tight = {low, lim.rlim_max};
    setrlimit(RLIMIT_NOFILE, &tight);
    CHECK_ERR("open-tree-descriptor-first", sys(NR_open_tree, AT_FDCWD, (long)BAD, 2, 0, 0), EMFILE);
    setrlimit(RLIMIT_NOFILE, &lim);
    close(rw);
    close(p);
    close(d);
}

int main(void) {
    snprintf(dir, sizeof dir, "/tmp/rax-admin-%d", getpid());
    snprintf(file, sizeof file, "%s/file", dir);
    snprintf(dangling, sizeof dangling, "%s/dangling", dir);
    mkdir(dir, 0777);
    chmod(dir, 0777);
    close(open(file, O_CREAT | O_WRONLY, 0666));
    symlink("/nonexistent-rax-user-target", dangling);
    /* A read-only page holding a refused adjustment. */
    struct timex *ro = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ro->modes = ADJ_OFFSET;
    mprotect(ro, 4096, PROT_READ);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) {
            printf("FAIL drop-privileges\n");
            exit(1);
        }
        machine();
        clocks(ro);
        mounts();
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    unlink(dangling);
    unlink(file);
    rmdir(dir);
    failures = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    FINISH();
}
