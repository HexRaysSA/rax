#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned long long cpu_us(const struct rusage *usage) {
    return 1000000ull * (usage->ru_utime.tv_sec + usage->ru_stime.tv_sec) +
           usage->ru_utime.tv_usec + usage->ru_stime.tv_usec;
}

static bool read_usage(int who, struct rusage *usage) {
    return getrusage(who, usage) == 0 &&
           usage->ru_utime.tv_sec >= 0 && usage->ru_stime.tv_sec >= 0 &&
           usage->ru_utime.tv_usec >= 0 && usage->ru_utime.tv_usec < 1000000 &&
           usage->ru_stime.tv_usec >= 0 && usage->ru_stime.tv_usec < 1000000 &&
           usage->ru_maxrss >= 0 && usage->ru_minflt >= 0;
}

static void work(void) {
    volatile unsigned long acc = 0;
    for (unsigned long i = 0; i < 100000; i++) {
        acc += i;
    }
}

static int fail(const char *stage) {
    fprintf(stderr, "resource usage failed at %s (errno=%d)\n", stage, errno);
    return 1;
}

int main(int argc, char **argv) {
    struct rusage current, children, child;
    if (!read_usage(RUSAGE_SELF, &current) || current.ru_maxrss == 0) {
        return fail("self");
    }
    if (!read_usage(RUSAGE_CHILDREN, &children)) {
        return fail("children");
    }
    if (argc == 3 && strcmp(argv[1], "--after-exec") == 0) {
        if (cpu_us(&current) < strtoull(argv[2], NULL, 10) || cpu_us(&children) != 0 ||
            children.ru_maxrss != 0) {
            return fail("exec preserved usage");
        }
        puts("resource usage tracks self, child reaping, and exec accounting");
        return 0;
    }

    errno = 0;
    if (getrusage(-2, &child) != -1 || errno != EINVAL) {
        return fail("invalid selector");
    }
    struct rusage *bad = (struct rusage *)1;
    errno = 0;
    if (getrusage(RUSAGE_SELF, bad) != -1 || errno != EFAULT) {
        return fail("invalid result pointer");
    }
    if (cpu_us(&children) != 0 || children.ru_maxrss != 0) {
        return fail("initial children");
    }

    const size_t length = 256 * 1024;
    volatile unsigned char *pages = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pages == MAP_FAILED) {
        return fail("private mapping");
    }
    for (size_t index = 0; index < length; index += 4096) {
        pages[index] = 1;
    }
    work();
    if (munmap((void *)pages, length) != 0 || !read_usage(RUSAGE_SELF, &child) ||
        child.ru_maxrss < current.ru_maxrss || child.ru_minflt <= current.ru_minflt ||
        cpu_us(&child) <= cpu_us(&current)) {
        return fail("self accounting");
    }

    pid_t first = fork();
    if (first == 0) {
        pid_t grandchild = fork();
        if (grandchild == 0) {
            work();
            _exit(0);
        }
        int status;
        if (grandchild < 0 || wait4(grandchild, &status, 0, &child) != grandchild ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0 || cpu_us(&child) == 0 ||
            !read_usage(RUSAGE_CHILDREN, &children) || cpu_us(&children) != cpu_us(&child)) {
            _exit(2);
        }
        _exit(0);
    }
    siginfo_t info = {0};
    if (first < 0 || waitid(P_PID, (id_t)first, &info, WNOWAIT | WEXITED) != 0 ||
        info.si_pid != first || info.si_status != 0 || !read_usage(RUSAGE_CHILDREN, &children) ||
        cpu_us(&children) != 0 || children.ru_maxrss != 0) {
        return fail("unreaped child");
    }
    errno = 0;
    if (wait4(first, NULL, 0, bad) != -1 || errno != EFAULT ||
        !read_usage(RUSAGE_CHILDREN, &children) || cpu_us(&children) != 0) {
        return fail("failed wait copyout");
    }
    int status;
    if (wait4(first, &status, 0, &child) != first || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        cpu_us(&child) == 0 || child.ru_maxrss == 0 || !read_usage(RUSAGE_CHILDREN, &children) ||
        cpu_us(&children) != cpu_us(&child) || children.ru_maxrss != child.ru_maxrss ||
        children.ru_minflt != child.ru_minflt) {
        return fail("reaped child");
    }

    struct sigaction action = {0};
    action.sa_handler = SIG_DFL;
    action.sa_flags = SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &action, NULL) != 0) {
        return fail("auto-reap setup");
    }
    pid_t auto_child = fork();
    if (auto_child == 0) {
        work();
        _exit(0);
    }
    errno = 0;
    if (auto_child < 0 || waitpid(auto_child, NULL, 0) != -1 || errno != ECHILD ||
        !read_usage(RUSAGE_CHILDREN, &children) || cpu_us(&children) != cpu_us(&child) ||
        children.ru_maxrss != child.ru_maxrss) {
        return fail("auto-reaped child");
    }

    if (!read_usage(RUSAGE_SELF, &current)) {
        return fail("before exec");
    }
    char cpu[32];
    snprintf(cpu, sizeof(cpu), "%llu", cpu_us(&current));
    char *next[] = {argv[0], "--after-exec", cpu, NULL};
    execv(next[0], next);
    return fail("exec");
}
