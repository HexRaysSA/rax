#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void failed(const char *operation, int cpu, int error)
{
    dprintf(STDOUT_FILENO, "RAX-USERSPACE-FAIL cpu=%d %s: %s\n",
            cpu, operation, strerror(error));
    _exit(1);
}

static int64_t nanoseconds(struct timespec value)
{
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

static void verify_cpu(int target_cpu)
{
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    CPU_SET(target_cpu, &allowed);
    if (sched_setaffinity(0, sizeof(allowed), &allowed) < 0)
        failed("sched_setaffinity", target_cpu, errno);
    if (sched_getcpu() != target_cpu)
        failed("initial sched_getcpu", target_cpu, EINVAL);

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        failed("clock_gettime before sleep", target_cpu, errno);
    const int64_t interval = 20000000;
    int64_t deadline_ns = nanoseconds(start) + interval;
    struct timespec deadline = {.tv_sec = deadline_ns / 1000000000,
                               .tv_nsec = deadline_ns % 1000000000};
    int result;
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    } while (result == EINTR);
    if (result != 0)
        failed("clock_nanosleep", target_cpu, result);
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
        failed("clock_gettime after sleep", target_cpu, errno);
    int observed_cpu = sched_getcpu();
    if (observed_cpu != target_cpu || nanoseconds(end) < deadline_ns)
        failed("timer wakeup or final CPU", target_cpu, EINVAL);

    dprintf(STDOUT_FILENO, "RAX-USERSPACE-CPU=%d DELTA_NS=%" PRId64 "\n",
            observed_cpu, nanoseconds(end) - nanoseconds(start));
    _exit(0);
}

int main(void)
{
    const int count = 4;
    pid_t workers[4];
    for (int cpu = 0; cpu < count; ++cpu) {
        workers[cpu] = fork();
        if (workers[cpu] == 0)
            verify_cpu(cpu);
        if (workers[cpu] < 0)
            failed("fork", cpu, errno);
    }
    for (int cpu = 0; cpu < count; ++cpu) {
        int status;
        if (waitpid(workers[cpu], &status, 0) != workers[cpu] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            failed("timer worker", cpu, ECHILD);
    }
    dprintf(STDOUT_FILENO, "RAX-USERSPACE-PASS CPUS=%d\n", count);
    for (;;)
        pause();
}
