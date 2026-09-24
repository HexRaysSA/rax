/* Process identity, auxiliary vector, time, limits, and /proc. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#if defined(__x86_64__)
#define MACHINE "x86_64"
#elif defined(__aarch64__)
#define MACHINE "aarch64"
#elif defined(__riscv) && __riscv_xlen == 64
#define MACHINE "riscv64"
#endif

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IOLBF, 0);
    CHECK("getpid", getpid() > 0);
    CHECK("gettid-is-pid", syscall(SYS_gettid) == getpid());
    CHECK("getppid", getppid() >= 0);

    struct utsname u;
    CHECK("uname", uname(&u) == 0);
    CHECK("uname-sysname", strcmp(u.sysname, "Linux") == 0);
    CHECK("uname-machine", strcmp(u.machine, MACHINE) == 0);

    CHECK("auxv-pagesz", getauxval(AT_PAGESZ) == 4096);
    CHECK("auxv-random", getauxval(AT_RANDOM) != 0);
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    CHECK("auxv-execfn", execfn && strcmp(execfn, argv[0]) == 0);
    CHECK("auxv-phdr", getauxval(AT_PHDR) != 0 && getauxval(AT_PHNUM) > 0);
    CHECK("auxv-entry", getauxval(AT_ENTRY) != 0);
    CHECK("auxv-secure", getauxval(AT_SECURE) == 0);

    struct timespec a, b, r;
    CHECK("clock-monotonic", clock_gettime(CLOCK_MONOTONIC, &a) == 0);
    struct timespec sl = {0, 20 * 1000 * 1000};
    CHECK("nanosleep", nanosleep(&sl, NULL) == 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long long ns = (b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec);
    CHECK("monotonic-advances", ns >= 20 * 1000 * 1000);
    CHECK("clock-realtime", clock_gettime(CLOCK_REALTIME, &a) == 0 && a.tv_sec > 1600000000);
    CHECK("clock-getres", clock_getres(CLOCK_MONOTONIC, &r) == 0 && r.tv_sec == 0 && r.tv_nsec > 0);
    CHECK_ERR("clock-invalid", clock_gettime(12345, &a), EINVAL);

    struct rlimit rl;
    CHECK("getrlimit-stack", getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur > 0);
    CHECK("getrlimit-nofile", getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur <= rl.rlim_max);
    rl.rlim_cur = rl.rlim_max + 1;
    CHECK_ERR("setrlimit-cur-above-max", setrlimit(RLIMIT_NOFILE, &rl), EINVAL);

    cpu_set_t set;
    CHECK("sched-getaffinity", sched_getaffinity(0, sizeof set, &set) == 0 && CPU_COUNT(&set) >= 1);
    CHECK("sched-yield", sched_yield() == 0);

    unsigned char rnd[32];
    CHECK("getrandom", getrandom(rnd, sizeof rnd, 0) == (ssize_t)sizeof rnd);
    CHECK_ERR("getrandom-bad-flags", getrandom(rnd, 1, 0x80), EINVAL);

    char name[16] = {0};
    CHECK("prctl-set-name", prctl(PR_SET_NAME, "rax-fixture") == 0);
    CHECK("prctl-get-name", prctl(PR_GET_NAME, name) == 0 && strcmp(name, "rax-fixture") == 0);
    CHECK("umask-roundtrip", umask(027) == 022 && umask(022) == 027);

    char link[4096];
    ssize_t n = readlink("/proc/self/exe", link, sizeof link - 1);
    if (n > 0)
        link[n] = 0;
    char arg0[4096];
    strncpy(arg0, argv[0], sizeof arg0 - 1);
    arg0[sizeof arg0 - 1] = 0;
    CHECK("proc-self-exe", n > 0 && link[0] == '/' && strcmp(basename(link), basename(arg0)) == 0);

    int fd = open("/proc/self/maps", O_RDONLY);
    CHECK("proc-self-maps-open", fd >= 0);
    static char maps[1 << 16];
    ssize_t len = fd >= 0 ? read(fd, maps, sizeof maps - 1) : -1;
    if (len > 0)
        maps[len] = 0;
    CHECK("proc-self-maps-stack", len > 0 && strstr(maps, "[stack]") != NULL);
    CHECK("proc-self-maps-exe", len > 0 && strstr(maps, basename(arg0)) != NULL);
    if (fd >= 0)
        close(fd);

    CHECK_ERR("enosys", syscall(1000), ENOSYS);
    CHECK_ERR("bad-fd", close(4000), EBADF);
    CHECK_ERR("efault", syscall(SYS_uname, (void *)8), EFAULT);
    FINISH();
}
